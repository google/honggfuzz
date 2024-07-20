/*
 *
 * honggfuzz - fuzzing routines
 * -----------------------------------------
 *
 * Authors: Robert Swiecki <swiecki@google.com>
 *          Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#include "fuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "honggfuzz.h"
#include "input.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "report.h"
#include "sanitizers.h"
#include "socketfuzzer.h"
#include "subproc.h"

static time_t termTimeStamp = 0;

bool fuzz_isTerminating(void) {
    if (ATOMIC_GET(termTimeStamp) != 0) {
        return true;
    }
    return false;
}

void fuzz_setTerminating(void) {
    if (ATOMIC_GET(termTimeStamp) != 0) {
        return;
    }
    ATOMIC_SET(termTimeStamp, time(NULL));
}

bool fuzz_shouldTerminate() {
    if (ATOMIC_GET(termTimeStamp) == 0) {
        return false;
    }
    if ((time(NULL) - ATOMIC_GET(termTimeStamp)) > 5) {
        return true;
    }
    return false;
}

fuzzState_t fuzz_getState(honggfuzz_t* hfuzz) {
    return ATOMIC_GET(hfuzz->feedback.state);
}

static void fuzz_setDynamicMainState(run_t* run) {
    /* All threads need to indicate willingness to switch to the DYNAMIC_MAIN state. Count them! */
    static uint32_t cnt = 0;
    ATOMIC_PRE_INC(cnt);

    MX_SCOPED_LOCK(&run->global->mutex.state);

    if (fuzz_getState(run->global) != _HF_STATE_DYNAMIC_DRY_RUN) {
        /* Already switched out of the Dry Run */
        return;
    }

    LOG_I("Entering phase 2/3: Switching to the Feedback Driven Mode");
    ATOMIC_SET(run->global->cfg.switchingToFDM, true);

    for (;;) {
        /* Check if all threads have already reported in for changing state */
        if (ATOMIC_GET(cnt) == run->global->threads.threadsMax) {
            break;
        }
        if (fuzz_isTerminating()) {
            return;
        }
        util_sleepForMSec(10); /* Check every 10ms */
    }

    ATOMIC_SET(run->global->cfg.switchingToFDM, false);

    if (run->global->cfg.minimize) {
        LOG_I("Entering phase 3/3: Corpus Minimization");
        ATOMIC_SET(run->global->feedback.state, _HF_STATE_DYNAMIC_MINIMIZE);
        return;
    }

    /*
     * If the initial fuzzing yielded no useful coverage, just add a single empty file to the
     * dynamic corpus, so the dynamic phase doesn't fail because of lack of useful inputs
     */
    if (run->global->io.dynfileqCnt == 0) {
        dynfile_t dynfile = {
            .size          = 0,
            .cov           = {},
            .idx           = 0,
            .fd            = -1,
            .timeExecUSecs = 1,
            .path          = "[DYNAMIC-0-SIZE]",
            .timedout      = false,
            .data          = (uint8_t*)"",
        };
        dynfile_t* tmp_dynfile = run->dynfile;
        run->dynfile           = &dynfile;
        input_addDynamicInput(run);
        run->dynfile = tmp_dynfile;
    }
    snprintf(run->dynfile->path, sizeof(run->dynfile->path), "[DYNAMIC]");

    if (run->global->io.maxFileSz == 0 && run->global->mutate.maxInputSz > _HF_INPUT_DEFAULT_SIZE) {
        size_t newsz = (run->global->io.dynfileqMaxSz >= _HF_INPUT_DEFAULT_SIZE)
                           ? run->global->io.dynfileqMaxSz
                           : _HF_INPUT_DEFAULT_SIZE;
        newsz        = (newsz + newsz / 4); /* Add 25% overhead for growth */
        if (newsz > run->global->mutate.maxInputSz) {
            newsz = run->global->mutate.maxInputSz;
        }
        LOG_I("Setting maximum input size to %zu bytes (previously %zu bytes)", newsz,
            run->global->mutate.maxInputSz);
        run->global->mutate.maxInputSz = newsz;
    }

    LOG_I("Entering phase 3/3: Dynamic Main (Feedback Driven Mode)");
    ATOMIC_SET(run->global->feedback.state, _HF_STATE_DYNAMIC_MAIN);
}

static void fuzz_minimizeRemoveFiles(run_t* run) {
    if (run->global->io.outputDir) {
        LOG_I("Minimized files were copied to '%s'", run->global->io.outputDir);
        return;
    }
    if (!input_getDirStatsAndRewind(run->global)) {
        return;
    }
    for (;;) {
        char   fname[PATH_MAX];
        size_t len;
        if (!input_getNext(run, fname, &len, /* rewind= */ false)) {
            break;
        }
        if (!input_inDynamicCorpus(run, fname, len)) {
            if (input_removeStaticFile(run->global->io.inputDir, fname)) {
                LOG_I("Removed unnecessary '%s'", fname);
            }
        }
    }
    LOG_I("Corpus minimization done");
}

static void fuzz_perfFeedback(run_t* run) {
    if (run->global->feedback.skipFeedbackOnTimeout && run->tmOutSignaled) {
        return;
    }
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    MX_SCOPED_LOCK(&run->global->mutex.feedback);
    defer {
        wmb();
    };

    uint64_t softNewPC   = 0;
    uint64_t softCurPC   = 0;
    uint64_t softNewEdge = 0;
    uint64_t softCurEdge = 0;
    uint64_t softNewCmp  = 0;
    uint64_t softCurCmp  = 0;

    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_SOFT) {
        softNewPC = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidNewPC[run->fuzzNo]);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidNewPC[run->fuzzNo]);
        softCurPC = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidTotalPC[run->fuzzNo]);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidTotalPC[run->fuzzNo]);

        softNewEdge = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidNewEdge[run->fuzzNo]);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidNewEdge[run->fuzzNo]);
        softCurEdge = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidTotalEdge[run->fuzzNo]);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidTotalEdge[run->fuzzNo]);

        softNewCmp = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidNewCmp[run->fuzzNo]);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidNewCmp[run->fuzzNo]);
        softCurCmp = ATOMIC_GET(run->global->feedback.covFeedbackMap->pidTotalCmp[run->fuzzNo]);
        ATOMIC_CLEAR(run->global->feedback.covFeedbackMap->pidTotalCmp[run->fuzzNo]);
    }

    rmb();

    int64_t diff0 = (int64_t)run->global->feedback.hwCnts.cpuInstrCnt - run->hwCnts.cpuInstrCnt;
    int64_t diff1 = (int64_t)run->global->feedback.hwCnts.cpuBranchCnt - run->hwCnts.cpuBranchCnt;

    /* Any increase in coverage (edge, pc, cmp, hw) counters forces adding input to the corpus */
    if (run->hwCnts.newBBCnt > 0 || softNewPC > 0 || softNewEdge > 0 || softNewCmp > 0 ||
        diff0 < 0 || diff1 < 0) {
        if (diff0 < 0) {
            run->global->feedback.hwCnts.cpuInstrCnt = run->hwCnts.cpuInstrCnt;
        }
        if (diff1 < 0) {
            run->global->feedback.hwCnts.cpuBranchCnt = run->hwCnts.cpuBranchCnt;
        }
        run->global->feedback.hwCnts.bbCnt += run->hwCnts.newBBCnt;
        run->global->feedback.hwCnts.softCntPc += softNewPC;
        run->global->feedback.hwCnts.softCntEdge += softNewEdge;
        run->global->feedback.hwCnts.softCntCmp += softNewCmp;

        LOG_I("Sz:%zu Tm:%" _HF_NONMON_SEP PRIu64 "us (i/b/h/e/p/c) New:%" PRIu64 "/%" PRIu64
              "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 ", Cur:%" PRIu64 "/%" PRIu64
              "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64,
            run->dynfile->size, util_timeNowUSecs() - run->timeStartedUSecs,
            run->hwCnts.cpuInstrCnt, run->hwCnts.cpuBranchCnt, run->hwCnts.newBBCnt, softNewEdge,
            softNewPC, softNewCmp, run->hwCnts.cpuInstrCnt, run->hwCnts.cpuBranchCnt,
            run->global->feedback.hwCnts.bbCnt, run->global->feedback.hwCnts.softCntEdge,
            run->global->feedback.hwCnts.softCntPc, run->global->feedback.hwCnts.softCntCmp);

        if (run->global->io.statsFileName) {
            const time_t curr_sec      = time(NULL);
            const time_t elapsed_sec   = curr_sec - run->global->timing.timeStart;
            size_t       curr_exec_cnt = ATOMIC_GET(run->global->cnts.mutationsCnt);
            /*
             * We increase the mutation counter unconditionally in threads, but if it's
             * above hfuzz->mutationsMax we don't really execute the fuzzing loop.
             * Therefore at the end of fuzzing, the mutation counter might be higher
             * than hfuzz->mutationsMax
             */
            if (run->global->mutate.mutationsMax > 0 &&
                curr_exec_cnt > run->global->mutate.mutationsMax) {
                curr_exec_cnt = run->global->mutate.mutationsMax;
            }
            size_t tot_exec_per_sec = elapsed_sec ? (curr_exec_cnt / elapsed_sec) : 0;

            dprintf(run->global->io.statsFileFd,
                "%lu, %lu, %lu, %lu, "
                "%" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n",
                curr_sec,                                 /* unix_time */
                run->global->timing.lastCovUpdate,        /* last_cov_update */
                curr_exec_cnt,                            /* total_exec */
                tot_exec_per_sec,                         /* exec_per_sec */
                run->global->cnts.crashesCnt,             /* crashes */
                run->global->cnts.uniqueCrashesCnt,       /* unique_crashes */
                run->global->cnts.timeoutedCnt,           /* hangs */
                run->global->feedback.hwCnts.softCntEdge, /* edge_cov */
                run->global->feedback.hwCnts.softCntPc    /* block_cov */
            );
        }

        /* Update per-input coverage metrics */
        run->dynfile->cov[0] = softCurEdge + softCurPC + run->hwCnts.bbCnt;
        run->dynfile->cov[1] = softCurCmp;
        run->dynfile->cov[2] = run->hwCnts.cpuInstrCnt + run->hwCnts.cpuBranchCnt;
        run->dynfile->cov[3] = run->dynfile->size ? (64 - util_Log2(run->dynfile->size)) : 64;
        input_addDynamicInput(run);

        if (run->global->socketFuzzer.enabled) {
            LOG_D("SocketFuzzer: fuzz: new BB (perf)");
            fuzz_notifySocketFuzzerNewCov(run->global);
        }
    }
}

/* Return value indicates whether report file should be updated with the current verified crash */
static bool fuzz_runVerifier(run_t* run) {
    if (!run->crashFileName[0] || !run->backtrace) {
        return false;
    }

    uint64_t backtrace = run->backtrace;

    char origCrashPath[PATH_MAX];
    snprintf(origCrashPath, sizeof(origCrashPath), "%s", run->crashFileName);
    /* Workspace is inherited, just append a extra suffix */
    char verFile[PATH_MAX];
    snprintf(verFile, sizeof(verFile), "%s.verified", origCrashPath);

    if (files_exists(verFile)) {
        LOG_D("Crash file to verify '%s' is already verified as '%s'", origCrashPath, verFile);
        return false;
    }

    for (int i = 0; i < _HF_VERIFIER_ITER; i++) {
        LOG_I("Launching verifier for HASH: %" PRIx64 " (iteration: %d out of %d)", run->backtrace,
            i + 1, _HF_VERIFIER_ITER);
        run->timeStartedUSecs = util_timeNowUSecs();
        run->backtrace        = 0;
        run->access           = 0;
        run->exception        = 0;
        run->mainWorker       = false;

        if (!subproc_Run(run)) {
            LOG_F("subproc_Run()");
        }

        /* If stack hash doesn't match skip name tag and exit */
        if (run->backtrace != backtrace) {
            LOG_E("Verifier stack mismatch: (original) %" PRIx64 " != (new) %" PRIx64, backtrace,
                run->backtrace);
            run->backtrace = backtrace;
            return true;
        }

        LOG_I("Verifier for HASH: %" PRIx64 " (iteration: %d, left: %d). MATCH!", run->backtrace,
            i + 1, _HF_VERIFIER_ITER - i - 1);
    }

    /* Copy file with new suffix & remove original copy */
    int fd = TEMP_FAILURE_RETRY(open(verFile, O_CREAT | O_EXCL | O_WRONLY, 0600));
    if (fd == -1 && errno == EEXIST) {
        LOG_I("It seems that '%s' already exists, skipping", verFile);
        return false;
    }
    if (fd == -1) {
        PLOG_E("Couldn't create '%s'", verFile);
        return true;
    }
    defer {
        close(fd);
    };
    if (!files_writeToFd(fd, run->dynfile->data, run->dynfile->size)) {
        LOG_E("Couldn't save verified file as '%s'", verFile);
        unlink(verFile);
        return true;
    }

    LOG_I("Verified crash for HASH: %" PRIx64 " and saved it as '%s'", backtrace, verFile);
    ATOMIC_PRE_INC(run->global->cnts.verifiedCrashesCnt);

    return true;
}

static bool fuzz_fetchInput(run_t* run) {
    {
        fuzzState_t st = fuzz_getState(run->global);
        if (st == _HF_STATE_DYNAMIC_DRY_RUN) {
            run->mutationsPerRun = 0U;
            if (input_prepareStaticFile(run, /* rewind= */ false, /* mangle= */ false)) {
                return true;
            }
            fuzz_setDynamicMainState(run);
            run->mutationsPerRun = run->global->mutate.mutationsPerRun;
        }
    }

    if (fuzz_getState(run->global) == _HF_STATE_DYNAMIC_MINIMIZE) {
        fuzz_minimizeRemoveFiles(run);
        return false;
    }

    if (fuzz_getState(run->global) == _HF_STATE_DYNAMIC_MAIN) {
        if (run->global->exe.externalCommand) {
            if (!input_prepareExternalFile(run)) {
                LOG_E("input_prepareExternalFile() failed");
                return false;
            }
        } else if (run->global->exe.feedbackMutateCommand) {
            if (!input_prepareDynamicInput(run, false)) {
                LOG_E("input_prepareDynamicInput(() failed");
                return false;
            }
        } else if (!input_prepareDynamicInput(run, true)) {
            LOG_E("input_prepareDynamicInput() failed");
            return false;
        }
    }

    if (fuzz_getState(run->global) == _HF_STATE_STATIC) {
        if (run->global->exe.externalCommand) {
            if (!input_prepareExternalFile(run)) {
                LOG_E("input_prepareExternalFile() failed");
                return false;
            }
        } else if (run->global->exe.feedbackMutateCommand) {
            if (!input_prepareStaticFile(run, /* rewind= */ true, /* mangle= */ false)) {
                LOG_E("input_prepareStaticFile() failed");
                return false;
            }
        } else if (!input_prepareStaticFile(run, /* rewind= */ true, /* mangle= */ true)) {
            LOG_E("input_prepareStaticFile() failed");
            return false;
        }
    }

    if (run->global->exe.postExternalCommand &&
        !input_postProcessFile(run, run->global->exe.postExternalCommand)) {
        LOG_E("input_postProcessFile('%s') failed", run->global->exe.postExternalCommand);
        return false;
    }

    if (run->global->exe.feedbackMutateCommand &&
        !input_postProcessFile(run, run->global->exe.feedbackMutateCommand)) {
        LOG_E("input_postProcessFile('%s') failed", run->global->exe.feedbackMutateCommand);
        return false;
    }

    return true;
}

static void fuzz_fuzzLoop(run_t* run) {
    run->timeStartedUSecs = util_timeNowUSecs();
    run->crashFileName[0] = '\0';
    run->pc               = 0;
    run->backtrace        = 0;
    run->access           = 0;
    run->exception        = 0;
    run->report[0]        = '\0';
    run->mainWorker       = true;
    run->mutationsPerRun  = run->global->mutate.mutationsPerRun;
    run->tmOutSignaled    = false;

    run->hwCnts.cpuInstrCnt  = 0;
    run->hwCnts.cpuBranchCnt = 0;
    run->hwCnts.bbCnt        = 0;
    run->hwCnts.newBBCnt     = 0;

    if (!fuzz_fetchInput(run)) {
        if (run->global->cfg.minimize && fuzz_getState(run->global) == _HF_STATE_DYNAMIC_MINIMIZE) {
            fuzz_setTerminating();
            return;
        }
        LOG_F("Cound't prepare input for fuzzing");
    }
    if (!subproc_Run(run)) {
        LOG_F("Couldn't run fuzzed command");
    }

    if (run->global->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_perfFeedback(run);
    }
    if (run->global->cfg.useVerifier && !fuzz_runVerifier(run)) {
        return;
    }
    report_saveReport(run);
}

static void fuzz_fuzzLoopSocket(run_t* run) {
    run->timeStartedUSecs = util_timeNowUSecs();
    run->crashFileName[0] = '\0';
    run->pc               = 0;
    run->backtrace        = 0;
    run->access           = 0;
    run->exception        = 0;
    run->report[0]        = '\0';
    run->mainWorker       = true;
    run->mutationsPerRun  = run->global->mutate.mutationsPerRun;
    run->tmOutSignaled    = false;

    run->hwCnts.cpuInstrCnt  = 0;
    run->hwCnts.cpuBranchCnt = 0;
    run->hwCnts.bbCnt        = 0;
    run->hwCnts.newBBCnt     = 0;

    LOG_I("------------------------------------------------------");

    /* First iteration: Start target
       Other iterations: re-start target, if necessary
       subproc_Run() will decide by itself if a restart is necessary, via
       subproc_New()
    */
    LOG_D("------[ 1: subproc_run");
    if (!subproc_Run(run)) {
        LOG_W("Couldn't run server");
    }

    /* Tell the external fuzzer to send data to target
       The fuzzer will notify us when finished; block until then.
    */
    LOG_D("------[ 2: fetch input");
    if (!fuzz_waitForExternalInput(run)) {
        /* Fuzzer could not connect to target, and told us to
           restart it. Do it on the next iteration.
           or: it crashed by fuzzing. Restart it too.
           */
        LOG_D("------[ 2.1: Target down, will restart it");
        run->pid = 0;    // make subproc_Run() restart it on next iteration
        return;
    }

    LOG_D("------[ 3: feedback");
    if (run->global->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_perfFeedback(run);
    }
    if (run->global->cfg.useVerifier && !fuzz_runVerifier(run)) {
        return;
    }

    report_saveReport(run);
}

static void* fuzz_threadNew(void* arg) {
    honggfuzz_t* hfuzz  = (honggfuzz_t*)arg;
    unsigned int fuzzNo = ATOMIC_POST_INC(hfuzz->threads.threadsActiveCnt);
    LOG_I("Launched new fuzzing thread, no. #%u", fuzzNo);

    if (!util_PinThreadToCPUs(fuzzNo, hfuzz->threads.pinThreadToCPUs)) {
        PLOG_W("Pinning thread #%u to %" PRIu32 " CPUs failed", fuzzNo,
            hfuzz->threads.pinThreadToCPUs);
    }

    run_t run = {
        .global         = hfuzz,
        .pid            = 0,
        .dynfile        = (dynfile_t*)util_Calloc(sizeof(dynfile_t) + hfuzz->io.maxFileSz),
        .fuzzNo         = fuzzNo,
        .persistentSock = -1,
        .tmOutSignaled  = false,
    };
    defer {
        free(run.dynfile);
    };

    /* Do not try to handle input files with socketfuzzer */
    char mapname[32];
    snprintf(mapname, sizeof(mapname), "hf-%u-input", fuzzNo);
    if (!hfuzz->socketFuzzer.enabled) {
        if (!(run.dynfile->data = files_mapSharedMem(hfuzz->mutate.maxInputSz, &(run.dynfile->fd),
                  mapname, /* nocore= */ true, /* exportmap= */ false))) {
            LOG_F("Couldn't create an input file of size: %zu, name:'%s'", hfuzz->mutate.maxInputSz,
                mapname);
        }
    }
    defer {
        if (run.dynfile->fd != -1) {
            close(run.dynfile->fd);
        }
    };

    snprintf(mapname, sizeof(mapname), "hf-%u-perthreadmap", fuzzNo);
    if ((run.perThreadCovFeedbackFd = files_createSharedMem(sizeof(feedback_t), mapname,
             /* exportmap= */ run.global->io.exportFeedback)) == -1) {
        LOG_F("files_createSharedMem(name='%s', sz=%zu, dir='%s') failed", mapname,
            sizeof(feedback_t), run.global->io.workDir);
    }
    defer {
        if (run.perThreadCovFeedbackFd != -1) {
            close(run.perThreadCovFeedbackFd);
        }
    };

    if (!arch_archThreadInit(&run)) {
        LOG_F("Could not initialize the thread");
    }

    for (;;) {
        /* Check if dry run mode with verifier enabled */
        if (run.global->mutate.mutationsPerRun == 0U && run.global->cfg.useVerifier &&
            !hfuzz->socketFuzzer.enabled) {
            if (ATOMIC_POST_INC(run.global->cnts.mutationsCnt) >= run.global->io.fileCnt) {
                break;
            }
        }
        /* Check for max iterations limit if set */
        else if ((ATOMIC_POST_INC(run.global->cnts.mutationsCnt) >=
                     run.global->mutate.mutationsMax) &&
                 run.global->mutate.mutationsMax) {
            break;
        }

        if (hfuzz->socketFuzzer.enabled) {
            fuzz_fuzzLoopSocket(&run);
        } else {
            fuzz_fuzzLoop(&run);
        }

        if (fuzz_isTerminating()) {
            break;
        }

        if (run.global->cfg.exitUponCrash && ATOMIC_GET(run.global->cnts.crashesCnt) > 0) {
            LOG_I("Seen a crash. Terminating all fuzzing threads");
            fuzz_setTerminating();
            break;
        }
    }

    arch_reapKill();

    if (run.pid) {
        kill(run.pid, SIGKILL);
    }

    size_t j = ATOMIC_PRE_INC(run.global->threads.threadsFinished);
    LOG_I("Terminating thread no. #%" PRId32 ", left: %zu", fuzzNo, hfuzz->threads.threadsMax - j);
    return NULL;
}

void fuzz_threadsStart(honggfuzz_t* hfuzz) {
    if (!arch_archInit(hfuzz)) {
        LOG_F("Couldn't prepare arch for fuzzing");
    }
    if (!sanitizers_Init(hfuzz)) {
        LOG_F("Couldn't prepare sanitizer options");
    }

    if (hfuzz->socketFuzzer.enabled) {
        /* Don't do dry run with socketFuzzer */
        LOG_I("Entering phase - Feedback Driven Mode (SocketFuzzer)");
        hfuzz->feedback.state = _HF_STATE_DYNAMIC_MAIN;
    } else if (hfuzz->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        LOG_I("Entering phase 1/3: Dry Run");
        hfuzz->feedback.state = _HF_STATE_DYNAMIC_DRY_RUN;
    } else {
        LOG_I("Entering phase: Static");
        hfuzz->feedback.state = _HF_STATE_STATIC;
    }

    for (size_t i = 0; i < hfuzz->threads.threadsMax; i++) {
        if (!subproc_runThread(
                hfuzz, &hfuzz->threads.threads[i], fuzz_threadNew, /* joinable= */ true)) {
            PLOG_F("Couldn't run a thread #%zu", i);
        }
    }
}
