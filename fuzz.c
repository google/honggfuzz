/*
 *
 * honggfuzz - fuzzing routines
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
 * Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2015 by Google Inc. All Rights Reserved.
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

#include "common.h"
#include "fuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "files.h"
#include "log.h"
#include "mangle.h"
#include "report.h"
#include "sancov.h"
#include "util.h"

extern char **environ;

static pthread_t fuzz_mainThread;

static inline bool fuzz_isPerfCntsSet(honggfuzz_t * hfuzz)
{
    if (hfuzz->hwCnts.cpuInstrCnt > 0ULL || hfuzz->hwCnts.cpuBranchCnt > 0ULL
        || hfuzz->hwCnts.cpuBtsBlockCnt > 0ULL || hfuzz->hwCnts.cpuBtsEdgeCnt > 0ULL
        || hfuzz->hwCnts.customCnt > 0ULL) {
        return true;
    } else {
        return false;
    }
}

static inline void fuzz_resetFeedbackCnts(honggfuzz_t * hfuzz)
{
    /* HW perf counters */
    __sync_fetch_and_and(&hfuzz->hwCnts.cpuInstrCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->hwCnts.cpuBranchCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->hwCnts.cpuBtsBlockCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->hwCnts.cpuBtsEdgeCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->hwCnts.customCnt, 0UL);

    /* Sanitizer coverage counter */
    __sync_fetch_and_and(&hfuzz->sanCovCnts.hitBBCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->sanCovCnts.totalBBCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->sanCovCnts.dsoCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->sanCovCnts.iDsoCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->sanCovCnts.newBBCnt, 0UL);
    __sync_fetch_and_and(&hfuzz->sanCovCnts.crashesCnt, 0UL);

    /*
     * For performance reasons Trie & Bitmap methods are not exposed in arch.h
     * Thus maintain a status flag to destroy runtime data internally at sancov.c
     * when dynFile input seed is replaced.
     */
    hfuzz->clearCovMetadata = true;
}

static void fuzz_getFileName(honggfuzz_t * hfuzz, char *fileName)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    snprintf(fileName, PATH_MAX, "%s/.honggfuzz.%d.%lu.%llx.%s", hfuzz->workDir, (int)getpid(),
             (unsigned long int)tv.tv_sec, (unsigned long long int)util_rndGet(0, 1ULL << 62),
             hfuzz->fileExtn);
}

static bool fuzz_prepareExecve(honggfuzz_t * hfuzz, const char *fileName)
{
    /*
     * Set timeout (prof), real timeout (2*prof), and rlimit_cpu (2*prof)
     */
    if (hfuzz->tmOut) {
        struct itimerval it;

        /*
         * The hfuzz->tmOut is real CPU usage time...
         */
        it.it_value.tv_sec = hfuzz->tmOut;
        it.it_value.tv_usec = 0;
        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = 0;
        if (setitimer(ITIMER_PROF, &it, NULL) == -1) {
            PLOG_D("Couldn't set the ITIMER_PROF timer");
        }

        /*
         * ...so, if a process sleeps, this one should
         * trigger a signal...
         */
        it.it_value.tv_sec = hfuzz->tmOut;
        it.it_value.tv_usec = 0;
        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = 0;
        if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
            PLOG_E("Couldn't set the ITIMER_REAL timer");
            return false;
        }

        /*
         * ..if a process sleeps and catches SIGPROF/SIGALRM
         * rlimits won't help either. However, arch_checkTimeLimit
         * will send a SIGKILL at tmOut + 2 seconds. That should
         * do it :)
         */
        struct rlimit rl;

        rl.rlim_cur = hfuzz->tmOut + 1;
        rl.rlim_max = hfuzz->tmOut + 1;
        if (setrlimit(RLIMIT_CPU, &rl) == -1) {
            PLOG_D("Couldn't enforce the RLIMIT_CPU resource limit");
        }
    }

    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (hfuzz->asLimit) {
        struct rlimit rl = {
            .rlim_cur = hfuzz->asLimit * 1024ULL * 1024ULL,
            .rlim_max = hfuzz->asLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_AS, &rl) == -1) {
            PLOG_D("Couldn't enforce the RLIMIT_AS resource limit, ignoring");
        }
    }

    if (hfuzz->nullifyStdio) {
        util_nullifyStdio();
    }

    if (hfuzz->fuzzStdin) {
        /*
         * Uglyyyyyy ;)
         */
        if (!util_redirectStdin(fileName)) {
            return false;
        }
    }

    if (hfuzz->clearEnv) {
        environ = NULL;
    }
    if (sancov_prepareExecve(hfuzz) == false) {
        LOG_E("sancov_prepareExecve() failed");
        return false;
    }
    for (size_t i = 0; i < ARRAYSIZE(hfuzz->envs) && hfuzz->envs[i]; i++) {
        putenv(hfuzz->envs[i]);
    }
    setsid();

    return true;
}

static bool fuzz_prepareFileDynamically(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    mangle_Resize(hfuzz, fuzzer->dynamicFile, &fuzzer->dynamicFileSz);
    mangle_mangleContent(hfuzz, fuzzer);

    if (files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
         O_WRONLY | O_CREAT | O_EXCL | O_TRUNC) == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFile(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    size_t fileSz =
        files_readFileToBufMax(hfuzz->files[rnd_index], fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (fileSz == 0UL) {
        LOG_E("Couldn't read contents of '%s'", hfuzz->files[rnd_index]);
        return false;
    }
    fuzzer->dynamicFileSz = fileSz;

    /* If flip rate is 0.0, early abort file mangling */
    if (fuzzer->flipRate != 0.0L) {
        mangle_Resize(hfuzz, fuzzer->dynamicFile, &fuzzer->dynamicFileSz);
        mangle_mangleContent(hfuzz, fuzzer);
    }

    if (files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
         O_WRONLY | O_CREAT | O_EXCL) == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFileExternally(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    {
        int dstfd = open(fuzzer->fileName, O_CREAT | O_EXCL | O_RDWR, 0644);
        if (dstfd == -1) {
            PLOG_E("Couldn't create a temporary file '%s'", fuzzer->fileName);
            return false;
        }
        DEFER(close(dstfd));

        LOG_D("Created '%s' as an input file", fuzzer->fileName);

        if (hfuzz->inputFile) {
            size_t fileSz = files_readFileToBufMax(hfuzz->files[rnd_index], fuzzer->dynamicFile,
                                                   hfuzz->maxFileSz);
            if (fileSz == 0UL) {
                LOG_E("Couldn't read '%s'", hfuzz->files[rnd_index]);
                unlink(fuzzer->fileName);
                return false;
            }

            if (files_writeToFd(dstfd, fuzzer->dynamicFile, fileSz) == false) {
                unlink(fuzzer->fileName);
                return false;
            }
        }

    }

    pid_t pid = arch_fork(hfuzz);
    if (pid == -1) {
        PLOG_E("Couldn't fork");
        return false;
    }

    if (!pid) {
        /*
         * child performs the external file modifications
         */
        execl(hfuzz->externalCommand, hfuzz->externalCommand, fuzzer->fileName, NULL);
        PLOG_F("Couldn't execute '%s %s'", hfuzz->externalCommand, fuzzer->fileName);
        return false;
    }

    /*
     * parent waits until child is done fuzzing the input file
     */
    int childStatus;
    int flags = 0;
#if defined(__WNOTHREAD)
    flags |= __WNOTHREAD;
#endif                          /* defined(__WNOTHREAD) */
    while (wait4(pid, &childStatus, flags, NULL) != pid) ;
    if (WIFEXITED(childStatus)) {
        LOG_D("External command exited with status %d", WEXITSTATUS(childStatus));
        return true;
    }
    if (WIFSIGNALED(childStatus)) {
        LOG_E("External command terminated with signal %d", WTERMSIG(childStatus));
        return false;
    }
    LOG_F("External command terminated abnormally, status: %d", childStatus);
    return false;
}

static bool fuzz_runVerifier(honggfuzz_t * hfuzz, fuzzer_t * crashedFuzzer)
{
    int crashFd = -1;
    uint8_t *crashBuf = NULL;
    off_t crashFileSz = 0;

    crashBuf = files_mapFile(crashedFuzzer->crashFileName, &crashFileSz, &crashFd, false);
    if (crashBuf == NULL) {
        LOG_E("Couldn't open and map '%s' in R/O mode", crashedFuzzer->crashFileName);
        return false;
    }
    DEFER(munmap(crashBuf, crashFileSz));
    DEFER(close(crashFd));

    LOG_I("Launching verifier for %" PRIx64 " hash", crashedFuzzer->backtrace);
    for (int i = 0; i < _HF_VERIFIER_ITER; i++) {
        fuzzer_t vFuzzer = {
            .pid = 0,
            .timeStartedMillis = util_timeNowMillis(),
            .crashFileName = {0},
            .pc = 0ULL,
            .backtrace = 0ULL,
            .access = 0ULL,
            .exception = 0,
            .dynamicFileSz = 0,
            .dynamicFile = NULL,
            .hwCnts = {
                       .cpuInstrCnt = 0ULL,
                       .cpuBranchCnt = 0ULL,
                       .cpuBtsBlockCnt = 0ULL,
                       .cpuBtsEdgeCnt = 0ULL,
                       .customCnt = 0ULL,
                       },
            .sanCovCnts = {
                           .hitBBCnt = 0ULL,
                           .totalBBCnt = 0ULL,
                           .dsoCnt = 0ULL,
                           .iDsoCnt = 0ULL,
                           .newBBCnt = 0ULL,
                           .crashesCnt = 0ULL,
                           },
            .report = {'\0'},
            .mainWorker = false
        };

        fuzz_getFileName(hfuzz, vFuzzer.fileName);
        if (files_writeBufToFile
            (vFuzzer.fileName, crashBuf, crashFileSz, O_WRONLY | O_CREAT | O_EXCL) == false) {
            LOG_E("Couldn't write buffer to file '%s'", vFuzzer.fileName);
            return false;
        }

        vFuzzer.pid = arch_fork(hfuzz);
        if (vFuzzer.pid == -1) {
            PLOG_F("Couldn't fork");
            return false;
        }

        if (!vFuzzer.pid) {
            if (fuzz_prepareExecve(hfuzz, crashedFuzzer->crashFileName) == false) {
                LOG_E("fuzz_prepareExecve() failed");
                return false;
            }
            if (!arch_launchChild(hfuzz, crashedFuzzer->crashFileName)) {
                LOG_E("Error launching verifier child process");
                return false;
            }
        }

        arch_reapChild(hfuzz, &vFuzzer);
        unlink(vFuzzer.fileName);

        /* If stack hash doesn't match skip name tag and exit */
        if (crashedFuzzer->backtrace != vFuzzer.backtrace) {
            LOG_D("Verifier stack hash mismatch");
            return false;
        }
    }

    /* Workspace is inherited, just append a extra suffix */
    char verFile[PATH_MAX] = { 0 };
    snprintf(verFile, sizeof(verFile), "%s.verified", crashedFuzzer->crashFileName);

    /* Copy file with new suffix & remove original copy */
    bool dstFileExists = false;
    if (files_copyFile(crashedFuzzer->crashFileName, verFile, &dstFileExists)) {
        LOG_I("Successfully verified, saving as (%s)", verFile);
        __sync_fetch_and_add(&hfuzz->verifiedCrashesCnt, 1UL);
        unlink(crashedFuzzer->crashFileName);
    } else {
        if (dstFileExists) {
            LOG_I("It seems that '%s' already exists, skipping", verFile);
        } else {
            LOG_E("Couldn't copy '%s' to '%s'", crashedFuzzer->crashFileName, verFile);
            return false;
        }
    }

    return true;
}

static void fuzz_perfFeedback(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    LOG_D
        ("File size (New/Best): %zu/%zu, Perf feedback (instr,branch,block,block-edge,custom): Best: [%"
         PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "] / New: [%" PRIu64 ",%" PRIu64
         ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]", fuzzer->dynamicFileSz,
         hfuzz->dynamicFileBestSz, hfuzz->hwCnts.cpuInstrCnt, hfuzz->hwCnts.cpuBranchCnt,
         hfuzz->hwCnts.cpuBtsBlockCnt, hfuzz->hwCnts.cpuBtsEdgeCnt, hfuzz->hwCnts.customCnt,
         fuzzer->hwCnts.cpuInstrCnt, fuzzer->hwCnts.cpuBranchCnt, fuzzer->hwCnts.cpuBtsBlockCnt,
         fuzzer->hwCnts.cpuBtsEdgeCnt, fuzzer->hwCnts.customCnt);

    MX_LOCK(&hfuzz->dynamicFile_mutex);
    DEFER(MX_UNLOCK(&hfuzz->dynamicFile_mutex));

    int64_t diff0 = hfuzz->hwCnts.cpuInstrCnt - fuzzer->hwCnts.cpuInstrCnt;
    int64_t diff1 = hfuzz->hwCnts.cpuBranchCnt - fuzzer->hwCnts.cpuBranchCnt;
    int64_t diff2 = hfuzz->hwCnts.cpuBtsBlockCnt - fuzzer->hwCnts.cpuBtsBlockCnt;
    int64_t diff3 = hfuzz->hwCnts.cpuBtsEdgeCnt - fuzzer->hwCnts.cpuBtsEdgeCnt;
    int64_t diff4 = hfuzz->hwCnts.cpuIptBlockCnt - fuzzer->hwCnts.cpuIptBlockCnt;
    int64_t diff5 = hfuzz->hwCnts.customCnt - fuzzer->hwCnts.customCnt;

    if (diff0 < 0 || diff1 < 0 || diff2 < 0 || diff3 < 0 || diff4 < 0 || diff5 < 0) {

        LOG_I("New: (Size New,Old): %zu,%zu, Perf (Cur,New): "
              "%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
              ",%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64,
              fuzzer->dynamicFileSz, hfuzz->dynamicFileBestSz,
              hfuzz->hwCnts.cpuInstrCnt, hfuzz->hwCnts.cpuBranchCnt,
              hfuzz->hwCnts.cpuBtsBlockCnt, hfuzz->hwCnts.cpuBtsEdgeCnt,
              hfuzz->hwCnts.cpuIptBlockCnt, hfuzz->hwCnts.customCnt,
              fuzzer->hwCnts.cpuInstrCnt, fuzzer->hwCnts.cpuBranchCnt,
              fuzzer->hwCnts.cpuBtsBlockCnt, fuzzer->hwCnts.cpuBtsEdgeCnt,
              fuzzer->hwCnts.cpuIptBlockCnt, fuzzer->hwCnts.customCnt);

        memcpy(hfuzz->dynamicFileBest, fuzzer->dynamicFile, fuzzer->dynamicFileSz);

        hfuzz->dynamicFileBestSz = fuzzer->dynamicFileSz;
        hfuzz->hwCnts.cpuInstrCnt = fuzzer->hwCnts.cpuInstrCnt;
        hfuzz->hwCnts.cpuBranchCnt = fuzzer->hwCnts.cpuBranchCnt;
        hfuzz->hwCnts.cpuBtsBlockCnt = fuzzer->hwCnts.cpuBtsBlockCnt;
        hfuzz->hwCnts.cpuBtsEdgeCnt = fuzzer->hwCnts.cpuBtsEdgeCnt;
        hfuzz->hwCnts.cpuIptBlockCnt = fuzzer->hwCnts.cpuIptBlockCnt;
        hfuzz->hwCnts.customCnt = fuzzer->hwCnts.customCnt;

        char currentBest[PATH_MAX], currentBestTmp[PATH_MAX];
        snprintf(currentBest, PATH_MAX, "%s/CURRENT_BEST", hfuzz->workDir);
        snprintf(currentBestTmp, PATH_MAX, "%s/.tmp.CURRENT_BEST", hfuzz->workDir);

        if (files_writeBufToFile
            (currentBestTmp, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
             O_WRONLY | O_CREAT | O_TRUNC)) {
            rename(currentBestTmp, currentBest);
        }
    }
}

static void fuzz_sanCovFeedback(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    LOG_D
        ("File size (Best/New): %zu/%zu, SanCov feedback (bb,dso): Best: [%" PRIu64
         ",%" PRIu64 "] / New: [%" PRIu64 ",%" PRIu64 "], newBBs:%" PRIu64,
         hfuzz->dynamicFileBestSz, fuzzer->dynamicFileSz, hfuzz->sanCovCnts.hitBBCnt,
         hfuzz->sanCovCnts.iDsoCnt, fuzzer->sanCovCnts.hitBBCnt, fuzzer->sanCovCnts.iDsoCnt,
         fuzzer->sanCovCnts.newBBCnt);

    MX_LOCK(&hfuzz->dynamicFile_mutex);
    DEFER(MX_UNLOCK(&hfuzz->dynamicFile_mutex));

    /* abs diff of total BBs between global counter for chosen seed & current run */
    uint64_t totalBBsDiff;
    if (hfuzz->sanCovCnts.hitBBCnt > fuzzer->sanCovCnts.hitBBCnt) {
        totalBBsDiff = hfuzz->sanCovCnts.hitBBCnt - fuzzer->sanCovCnts.hitBBCnt;
    } else {
        totalBBsDiff = fuzzer->sanCovCnts.hitBBCnt - hfuzz->sanCovCnts.hitBBCnt;
    }

    /*
     * Keep mutated seed if:
     *  a) Newly discovered (not met before) BBs && total hit BBs not significantly dropped
     *  b) More instrumented code accessed (BB hit counter bigger)
     *  c) More instrumented DSOs loaded
     *
     * TODO: (a) method can significantly assist to further improvements in interesting areas
     * discovery if combined with seeds pool/queue support. If a runtime queue is maintained
     * more interesting seeds can be saved between runs instead of instantly discarded
     * based on current absolute elitism (only one mutated seed is promoted).
     */
    if ((fuzzer->sanCovCnts.newBBCnt > 0 && fuzzer->sanCovCnts.newBBCnt >= totalBBsDiff) ||
        hfuzz->sanCovCnts.hitBBCnt < fuzzer->sanCovCnts.hitBBCnt ||
        hfuzz->sanCovCnts.iDsoCnt < fuzzer->sanCovCnts.iDsoCnt) {
        LOG_I("SanCov Update: file size (Cur,New): %zu,%zu, newBBs:%" PRIu64
              ", counters (Cur,New): %" PRIu64 "/%" PRIu64 ",%" PRIu64 "/%" PRIu64,
              hfuzz->dynamicFileBestSz, fuzzer->dynamicFileSz, fuzzer->sanCovCnts.newBBCnt,
              hfuzz->sanCovCnts.hitBBCnt, hfuzz->sanCovCnts.iDsoCnt, fuzzer->sanCovCnts.hitBBCnt,
              fuzzer->sanCovCnts.iDsoCnt);

        memcpy(hfuzz->dynamicFileBest, fuzzer->dynamicFile, fuzzer->dynamicFileSz);

        hfuzz->dynamicFileBestSz = fuzzer->dynamicFileSz;
        hfuzz->sanCovCnts.hitBBCnt = fuzzer->sanCovCnts.hitBBCnt;
        hfuzz->sanCovCnts.dsoCnt = fuzzer->sanCovCnts.dsoCnt;
        hfuzz->sanCovCnts.iDsoCnt = fuzzer->sanCovCnts.iDsoCnt;
        hfuzz->sanCovCnts.crashesCnt += fuzzer->sanCovCnts.crashesCnt;
        hfuzz->sanCovCnts.newBBCnt += fuzzer->sanCovCnts.newBBCnt;

        if (hfuzz->sanCovCnts.totalBBCnt < fuzzer->sanCovCnts.totalBBCnt) {
            /* Keep only the max value (for dlopen cases) to measure total target coverage */
            hfuzz->sanCovCnts.totalBBCnt = fuzzer->sanCovCnts.totalBBCnt;
        }

        char currentBest[PATH_MAX], currentBestTmp[PATH_MAX];
        snprintf(currentBest, PATH_MAX, "%s/CURRENT_BEST", hfuzz->workDir);
        snprintf(currentBestTmp, PATH_MAX, "%s/.tmp.CURRENT_BEST", hfuzz->workDir);

        if (files_writeBufToFile
            (currentBestTmp, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
             O_WRONLY | O_CREAT | O_TRUNC)) {
            rename(currentBestTmp, currentBest);
        }
    }
}

static void fuzz_fuzzLoop(honggfuzz_t * hfuzz)
{
    fuzzer_t fuzzer = {
        .pid = 0,
        .timeStartedMillis = util_timeNowMillis(),
        .crashFileName = {0},
        .pc = 0ULL,
        .backtrace = 0ULL,
        .access = 0ULL,
        .exception = 0,
        .mainWorker = true,
        .flipRate = hfuzz->origFlipRate,

        .sanCovCnts = {
                       .hitBBCnt = 0ULL,
                       .totalBBCnt = 0ULL,
                       .dsoCnt = 0ULL,
                       .iDsoCnt = 0ULL,
                       .newBBCnt = 0ULL,
                       .crashesCnt = 0ULL,
                       },
        .dynamicFileSz = 0,
        .dynamicFile = malloc(hfuzz->maxFileSz),

        .hwCnts = {
                   .cpuInstrCnt = 0ULL,
                   .cpuBranchCnt = 0ULL,
                   .cpuBtsBlockCnt = 0ULL,
                   .cpuBtsEdgeCnt = 0ULL,
                   .customCnt = 0ULL,
                   },
        .report = {'\0'},
    };
    if (fuzzer.dynamicFile == NULL) {
        LOG_F("malloc(%zu) failed", hfuzz->maxFileSz);
    }
    DEFER(free(fuzzer.dynamicFile));

    size_t rnd_index = util_rndGet(0, hfuzz->fileCnt - 1);

    /* If dry run mode, pick the next file and not a random one */
    if (fuzzer.flipRate == 0.0L && hfuzz->useVerifier) {
        rnd_index = __sync_fetch_and_add(&hfuzz->lastCheckedFileIndex, 1UL);
    }
    if (hfuzz->state == _HF_STATE_DYNAMIC_PRE) {
        rnd_index = __sync_fetch_and_add(&hfuzz->lastCheckedFileIndex, 1UL);
        if (rnd_index >= hfuzz->fileCnt) {
            hfuzz->state = _HF_STATE_DYNAMIC_MAIN;
        } else {
            fuzzer.flipRate = 0.0f;
        }
    }

    strncpy(fuzzer.origFileName, files_basename(hfuzz->files[rnd_index]), PATH_MAX);
    fuzz_getFileName(hfuzz, fuzzer.fileName);

    if (hfuzz->state == _HF_STATE_DYNAMIC_MAIN) {
        if (!fuzz_prepareFileDynamically(hfuzz, &fuzzer)) {
            exit(EXIT_FAILURE);
        }
    } else if (hfuzz->state == _HF_STATE_DYNAMIC_PRE) {
        if (!fuzz_prepareFile(hfuzz, &fuzzer, rnd_index)) {
            exit(EXIT_FAILURE);
        }
    } else if (hfuzz->externalCommand != NULL) {
        if (!fuzz_prepareFileExternally(hfuzz, &fuzzer, rnd_index)) {
            exit(EXIT_FAILURE);
        }
    } else {
        if (!fuzz_prepareFile(hfuzz, &fuzzer, rnd_index)) {
            exit(EXIT_FAILURE);
        }
    }

    fuzzer.pid = arch_fork(hfuzz);
    if (fuzzer.pid == -1) {
        PLOG_F("Couldn't fork");
        exit(EXIT_FAILURE);
    }

    if (!fuzzer.pid) {
        if (!fuzz_prepareExecve(hfuzz, fuzzer.fileName)) {
            LOG_E("fuzz_prepareExecve() failed");
            exit(EXIT_FAILURE);
        }
        if (!arch_launchChild(hfuzz, fuzzer.fileName)) {
            LOG_E("Error launching child process");
            exit(EXIT_FAILURE);
        }
    }

    LOG_D("Launched new process, pid: %d, (concurrency: %zd)", fuzzer.pid, hfuzz->threadsMax);

    arch_reapChild(hfuzz, &fuzzer);
    unlink(fuzzer.fileName);

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_perfFeedback(hfuzz, &fuzzer);
    } else if (hfuzz->useSanCov) {
        fuzz_sanCovFeedback(hfuzz, &fuzzer);
    }

    if (hfuzz->useVerifier && (fuzzer.crashFileName[0] != 0) && fuzzer.backtrace) {
        if (!fuzz_runVerifier(hfuzz, &fuzzer)) {
            LOG_I("Failed to verify %s", fuzzer.crashFileName);
        }
    }

    report_Report(hfuzz, fuzzer.report);
}

static void *fuzz_threadNew(void *arg)
{
    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;

    for (;;) {
        /* Check if dry run mode with verifier enabled */
        if (hfuzz->origFlipRate == 0.0L && hfuzz->useVerifier) {
            if (__sync_fetch_and_add(&hfuzz->mutationsCnt, 1UL) >= hfuzz->fileCnt) {
                __sync_fetch_and_add(&hfuzz->threadsFinished, 1UL);
                // All files checked, weak-up the main process
                pthread_kill(fuzz_mainThread, SIGALRM);
                return NULL;
            }
        }
        /* Check for max iterations limit if set */
        else if ((__sync_fetch_and_add(&hfuzz->mutationsCnt, 1UL) >= hfuzz->mutationsMax)
                 && hfuzz->mutationsMax) {
            __sync_fetch_and_add(&hfuzz->threadsFinished, 1UL);
            // Wake-up the main process
            pthread_kill(fuzz_mainThread, SIGALRM);
            return NULL;
        }

        fuzz_fuzzLoop(hfuzz);
    }
}

static void fuzz_runThread(honggfuzz_t * hfuzz, void *(*thread) (void *))
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, _HF_PTHREAD_STACKSIZE);
    pthread_attr_setguardsize(&attr, (size_t) sysconf(_SC_PAGESIZE));

    pthread_t t;
    if (pthread_create(&t, &attr, thread, (void *)hfuzz) < 0) {
        PLOG_F("Couldn't create a new thread");
    }

    return;
}

void fuzz_threads(honggfuzz_t * hfuzz)
{
    fuzz_mainThread = pthread_self();

    if (!arch_archInit(hfuzz)) {
        LOG_F("Couldn't prepare arch for fuzzing");
    }
    if (!sancov_Init(hfuzz)) {
        LOG_F("Couldn't prepare sancov options");
    }

    if (hfuzz->useSanCov || hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        hfuzz->state = _HF_STATE_DYNAMIC_PRE;
    } else {
        hfuzz->state = _HF_STATE_STATIC;
    }

    for (size_t i = 0; i < hfuzz->threadsMax; i++) {
        fuzz_runThread(hfuzz, fuzz_threadNew);
    }
}
