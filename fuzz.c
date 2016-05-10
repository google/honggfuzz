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
    if (hfuzz->persistent == false && hfuzz->tmOut) {
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
    struct dynfile_t *dynfile;

    {
        MX_SCOPED_LOCK(&hfuzz->dynfileq_mutex);

        if (hfuzz->dynfileqCnt == 0) {
            LOG_F("The dynamic file corpus is empty. Apparently, the initial fuzzing of the "
                  "provided file corpus (-f) has not produced any follow-up files with positive "
                  "coverage and/or CPU counters");
        }

        size_t i = 0U;
        size_t dynFilePos = util_rndGet(0, hfuzz->dynfileqCnt - 1);
        TAILQ_FOREACH(dynfile, &hfuzz->dynfileq, pointers) {
            if (i++ == dynFilePos) {
                break;
            }
        }
    }

    memcpy(fuzzer->dynamicFile, dynfile->data, dynfile->size);
    fuzzer->dynamicFileSz = dynfile->size;

    mangle_Resize(hfuzz, fuzzer->dynamicFile, &fuzzer->dynamicFileSz);
    mangle_mangleContent(hfuzz, fuzzer);

    if (hfuzz->persistent == false && files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
         O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC) == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFile(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    ssize_t fileSz =
        files_readFileToBufMax(hfuzz->files[rnd_index], fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (fileSz < 0) {
        LOG_E("Couldn't read contents of '%s'", hfuzz->files[rnd_index]);
        return false;
    }
    fuzzer->dynamicFileSz = fileSz;

    /* If flip rate is 0.0, early abort file mangling */
    if (fuzzer->flipRate != 0.0L) {
        mangle_Resize(hfuzz, fuzzer->dynamicFile, &fuzzer->dynamicFileSz);
        mangle_mangleContent(hfuzz, fuzzer);
    }

    if (hfuzz->persistent == false && files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC) == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFileExternally(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int dstfd = open(fuzzer->fileName, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
    if (dstfd == -1) {
        PLOG_E("Couldn't create a temporary file '%s'", fuzzer->fileName);
        return false;
    }
    close(dstfd);

    LOG_D("Created '%s' as an input file", fuzzer->fileName);

    pid_t pid = fork();
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
    if (WIFSIGNALED(childStatus)) {
        LOG_E("External command terminated with signal %d", WTERMSIG(childStatus));
        return false;
    }
    if (!WIFEXITED(childStatus)) {
        LOG_F("External command terminated abnormally, status: %d", childStatus);
        return false;
    }
    LOG_D("External command exited with status %d", WEXITSTATUS(childStatus));

    ssize_t rsz = files_readFileToBufMax(fuzzer->fileName, fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (rsz < 0) {
        LOG_W("Couldn't read back '%s' to the buffer", fuzzer->fileName);
        return false;
    }
    fuzzer->dynamicFileSz = rsz;

    if (hfuzz->persistent) {
        unlink(fuzzer->fileName);
    }

    return true;
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
    defer {
        munmap(crashBuf, crashFileSz);
        close(crashFd);
    };

    LOG_I("Launching verifier for %" PRIx64 " hash", crashedFuzzer->backtrace);
    for (int i = 0; i < _HF_VERIFIER_ITER; i++) {
        fuzzer_t vFuzzer = {
            .pid = 0,
            .persistentPid = 0,
            .timeStartedMillis = util_timeNowMillis(),
            .crashFileName = {0},
            .pc = 0ULL,
            .backtrace = 0ULL,
            .access = 0ULL,
            .exception = 0,
            .dynamicFileSz = 0,
            .dynamicFile = NULL,
            .sanCovCnts = {
                           .hitBBCnt = 0ULL,
                           .totalBBCnt = 0ULL,
                           .dsoCnt = 0ULL,
                           .iDsoCnt = 0ULL,
                           .newBBCnt = 0ULL,
                           .crashesCnt = 0ULL,
                           },
            .report = {'\0'},
            .mainWorker = false,

            .linux = {
                      .hwCnts = {
                                 .cpuInstrCnt = 0ULL,
                                 .cpuBranchCnt = 0ULL,
                                 .customCnt = 0ULL,
                                 .bbCnt = 0ULL,
                                 .newBBCnt = 0ULL,
                                 },
                      .perfMmapBuf = NULL,
                      .perfMmapAux = NULL,
#if defined(_HF_ARCH_LINUX)
                      .timerId = (timer_t) 0,
#endif                          // defined(_HF_ARCH_LINUX)
                      .attachedPid = 0,
                      .persistentSock = -1,
                      },
        };

        if (arch_archThreadInit(hfuzz, &vFuzzer) == false) {
            LOG_F("Could not initialize the thread");
        }

        fuzz_getFileName(hfuzz, vFuzzer.fileName);
        if (files_writeBufToFile
            (vFuzzer.fileName, crashBuf, crashFileSz,
             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC) == false) {
            LOG_E("Couldn't write buffer to file '%s'", vFuzzer.fileName);
            return false;
        }

        vFuzzer.pid = arch_fork(hfuzz, &vFuzzer);
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
        ATOMIC_POST_INC(hfuzz->verifiedCrashesCnt);
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

static void fuzz_addFileToFileQLocked(honggfuzz_t * hfuzz, uint8_t * data, size_t size,
                                      uint64_t cov)
{
    struct dynfile_t *dynfile = (struct dynfile_t *)util_Malloc(sizeof(struct dynfile_t));
    dynfile->size = size;
    dynfile->data = (uint8_t *) util_Malloc(size);
    memcpy(dynfile->data, data, size);
    TAILQ_INSERT_TAIL(&hfuzz->dynfileq, dynfile, pointers);
    hfuzz->dynfileqCnt++;

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname),
             "%s/COV.RANK.%06" PRIu64 ".PID.%d.COVBB.%07" PRIu64 ".TIME.%" PRIu64 ".RND.%" PRIx64,
             hfuzz->workDir, (uint64_t) 999999ULL - cov, getpid(), cov, (uint64_t) time(NULL),
             util_rndGet(0, 0xFFFFFFFFFFFF));
    if (files_writeBufToFile(fname, data, size, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC)
        == false) {
        LOG_W("Couldn't write buffer to file '%s'", fname);
    }
}

static void fuzz_perfFeedback(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    LOG_D
        ("New file size: %zu, Perf feedback new/cur (instr,branch): %" PRIu64 "/%" PRIu64 ",%"
         PRIu64 "/%" PRIu64 ", BBcnt new/total: %" PRIu64 "/%" PRIu64, fuzzer->dynamicFileSz,
         fuzzer->linux.hwCnts.cpuInstrCnt, hfuzz->linux.hwCnts.cpuInstrCnt,
         fuzzer->linux.hwCnts.cpuBranchCnt, hfuzz->linux.hwCnts.cpuBranchCnt,
         fuzzer->linux.hwCnts.newBBCnt, hfuzz->linux.hwCnts.bbCnt);

    MX_SCOPED_LOCK(&hfuzz->dynfileq_mutex);

    int64_t diff0 = hfuzz->linux.hwCnts.cpuInstrCnt - fuzzer->linux.hwCnts.cpuInstrCnt;
    int64_t diff1 = hfuzz->linux.hwCnts.cpuBranchCnt - fuzzer->linux.hwCnts.cpuBranchCnt;
    int64_t diff2 = hfuzz->linux.hwCnts.customCnt - fuzzer->linux.hwCnts.customCnt;

    if (diff0 < 0 || diff1 < 0 || diff2 < 0 || fuzzer->linux.hwCnts.newBBCnt > 0) {
        LOG_I
            ("New file size: %zu, Perf feedback new/cur (instr,branch): %" PRIu64 "/%" PRIu64 ",%"
             PRIu64 "/%" PRIu64 ", BBcnt new/total: %" PRIu64 "/%" PRIu64, fuzzer->dynamicFileSz,
             fuzzer->linux.hwCnts.cpuInstrCnt, hfuzz->linux.hwCnts.cpuInstrCnt,
             fuzzer->linux.hwCnts.cpuBranchCnt, hfuzz->linux.hwCnts.cpuBranchCnt,
             fuzzer->linux.hwCnts.newBBCnt, hfuzz->linux.hwCnts.bbCnt);

        hfuzz->linux.hwCnts.cpuInstrCnt = fuzzer->linux.hwCnts.cpuInstrCnt;
        hfuzz->linux.hwCnts.cpuBranchCnt = fuzzer->linux.hwCnts.cpuBranchCnt;
        hfuzz->linux.hwCnts.customCnt = fuzzer->linux.hwCnts.customCnt;
        hfuzz->linux.hwCnts.bbCnt += fuzzer->linux.hwCnts.newBBCnt;

        fuzz_addFileToFileQLocked(hfuzz, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
                                  fuzzer->linux.hwCnts.newBBCnt);
    }
}

static void fuzz_sanCovFeedback(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    LOG_D
        ("File size (Best/New): %zu, SanCov feedback (bb,dso): Best: [%" PRIu64
         ",%" PRIu64 "] / New: [%" PRIu64 ",%" PRIu64 "], newBBs:%" PRIu64,
         fuzzer->dynamicFileSz, hfuzz->sanCovCnts.hitBBCnt,
         hfuzz->sanCovCnts.iDsoCnt, fuzzer->sanCovCnts.hitBBCnt, fuzzer->sanCovCnts.iDsoCnt,
         fuzzer->sanCovCnts.newBBCnt);

    MX_SCOPED_LOCK(&hfuzz->dynfileq_mutex);

    /*
     * Keep mutated seed if:
     *  a) Newly discovered (not met before) BBs
     *  b) More instrumented DSOs loaded
     *
     * TODO: (a) method can significantly assist to further improvements in interesting areas
     * discovery if combined with seeds pool/queue support. If a runtime queue is maintained
     * more interesting seeds can be saved between runs instead of instantly discarded
     * based on current absolute elitism (only one mutated seed is promoted).
     */
    if (fuzzer->sanCovCnts.newBBCnt > 0 || hfuzz->sanCovCnts.iDsoCnt < fuzzer->sanCovCnts.iDsoCnt) {
        LOG_I("SanCov Update: file size (Cur): %zu, newBBs:%" PRIu64
              ", counters (Cur,New): %" PRIu64 "/%" PRIu64 ",%" PRIu64 "/%" PRIu64,
              fuzzer->dynamicFileSz, fuzzer->sanCovCnts.newBBCnt,
              hfuzz->sanCovCnts.hitBBCnt, hfuzz->sanCovCnts.iDsoCnt, fuzzer->sanCovCnts.hitBBCnt,
              fuzzer->sanCovCnts.iDsoCnt);

        hfuzz->sanCovCnts.hitBBCnt += fuzzer->sanCovCnts.newBBCnt;
        hfuzz->sanCovCnts.dsoCnt = fuzzer->sanCovCnts.dsoCnt;
        hfuzz->sanCovCnts.iDsoCnt = fuzzer->sanCovCnts.iDsoCnt;
        hfuzz->sanCovCnts.crashesCnt += fuzzer->sanCovCnts.crashesCnt;
        hfuzz->sanCovCnts.newBBCnt = fuzzer->sanCovCnts.newBBCnt;

        if (hfuzz->sanCovCnts.totalBBCnt < fuzzer->sanCovCnts.totalBBCnt) {
            /* Keep only the max value (for dlopen cases) to measure total target coverage */
            hfuzz->sanCovCnts.totalBBCnt = fuzzer->sanCovCnts.totalBBCnt;
        }

        fuzz_addFileToFileQLocked(hfuzz, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
                                  fuzzer->sanCovCnts.hitBBCnt);
    }
}

static fuzzState_t fuzz_getState(honggfuzz_t * hfuzz)
{
    return ATOMIC_GET(hfuzz->state);
}

static void fuzz_setState(honggfuzz_t * hfuzz, fuzzState_t state)
{
    ATOMIC_SET(hfuzz->state, state);
}

static void fuzz_fuzzLoop(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    fuzzer->pid = 0;
    fuzzer->timeStartedMillis = util_timeNowMillis();
    fuzzer->crashFileName[0] = '\0';
    fuzzer->pc = 0ULL;
    fuzzer->backtrace = 0ULL;
    fuzzer->access = 0ULL;
    fuzzer->exception = 0;
    fuzzer->report[0] = '\0';
    fuzzer->mainWorker = true;
    fuzzer->origFileName = "DYNAMIC";
    fuzzer->flipRate = hfuzz->origFlipRate;
    fuzzer->dynamicFileSz = 0;

    fuzzer->sanCovCnts.hitBBCnt = 0ULL;
    fuzzer->sanCovCnts.totalBBCnt = 0ULL;
    fuzzer->sanCovCnts.dsoCnt = 0ULL;
    fuzzer->sanCovCnts.newBBCnt = 0ULL;
    fuzzer->sanCovCnts.crashesCnt = 0ULL;

    fuzzer->linux.hwCnts.cpuInstrCnt = 0ULL;
    fuzzer->linux.hwCnts.cpuBranchCnt = 0ULL;
    fuzzer->linux.hwCnts.customCnt = 0ULL;
    fuzzer->linux.hwCnts.bbCnt = 0ULL;
    fuzzer->linux.hwCnts.newBBCnt = 0ULL;
    fuzzer->linux.perfMmapBuf = NULL;
    fuzzer->linux.perfMmapAux = NULL;

    size_t rnd_index = util_rndGet(0, hfuzz->fileCnt - 1);

    /* If dry run mode, pick the next file and not a random one */
    if (fuzzer->flipRate == 0.0L && hfuzz->useVerifier) {
        rnd_index = ATOMIC_POST_INC(hfuzz->lastFileIndex);
    }

    if (fuzz_getState(hfuzz) == _HF_STATE_DYNAMIC_PRE) {
        rnd_index = ATOMIC_POST_INC(hfuzz->lastFileIndex);
        if (rnd_index >= hfuzz->fileCnt) {
            /*
             * The waiting logic (for the DYNAMIC_PRE phase to finish) should be based on cond-waits
             * or mutexes, but it'd complicate code too much
             */
            while (fuzz_getState(hfuzz) == _HF_STATE_DYNAMIC_PRE) {
                sleep(1);
            }
        }
    }

    fuzzState_t state = fuzz_getState(hfuzz);
    if (state != _HF_STATE_DYNAMIC_MAIN) {
        fuzzer->origFileName = files_basename(hfuzz->files[rnd_index]);
    }

    fuzz_getFileName(hfuzz, fuzzer->fileName);

    if (hfuzz->externalCommand) {
        if (!fuzz_prepareFileExternally(hfuzz, fuzzer)) {
            LOG_F("fuzz_prepareFileExternally() failed");
        }
    } else if (state == _HF_STATE_DYNAMIC_MAIN) {
        if (!fuzz_prepareFileDynamically(hfuzz, fuzzer)) {
            LOG_F("fuzz_prepareFileDynamically() failed");
        }
    } else if (state == _HF_STATE_DYNAMIC_PRE) {
        fuzzer->flipRate = 0.0f;
        if (!fuzz_prepareFile(hfuzz, fuzzer, rnd_index)) {
            LOG_F("fuzz_prepareFile() failed");
        }
    } else {
        if (!fuzz_prepareFile(hfuzz, fuzzer, rnd_index)) {
            LOG_F("fuzz_prepareFile() failed");
        }
    }

    fuzzer->pid = fuzzer->persistentPid;
    if (fuzzer->pid == 0) {
        fuzzer->pid = arch_fork(hfuzz, fuzzer);
        if (fuzzer->pid == -1) {
            PLOG_F("Couldn't fork");
        }

        if (!fuzzer->pid) {
            if (!fuzz_prepareExecve(hfuzz, fuzzer->fileName)) {
                LOG_E("fuzz_prepareExecve() failed");
                exit(EXIT_FAILURE);
            }
            if (!arch_launchChild(hfuzz, fuzzer->fileName)) {
                LOG_E("Error launching child process");
                exit(EXIT_FAILURE);
            }
        }

        if (hfuzz->persistent) {
            LOG_I("Persistent mode: Launched new persistent PID: %d", (int)fuzzer->pid);
            fuzzer->persistentPid = fuzzer->pid;
        }
    }

    LOG_D("Launched new process, pid: %d, (concurrency: %zd)", fuzzer->pid, hfuzz->threadsMax);

    arch_reapChild(hfuzz, fuzzer);
    if (hfuzz->persistent == false) {
        unlink(fuzzer->fileName);
    }

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_perfFeedback(hfuzz, fuzzer);
    }
    if (hfuzz->useSanCov) {
        fuzz_sanCovFeedback(hfuzz, fuzzer);
    }

    if (hfuzz->useVerifier && (fuzzer->crashFileName[0] != 0) && fuzzer->backtrace) {
        if (!fuzz_runVerifier(hfuzz, fuzzer)) {
            LOG_I("Failed to verify %s", fuzzer->crashFileName);
        }
    }

    {
        MX_SCOPED_LOCK(&hfuzz->report_mutex);
        report_Report(hfuzz, fuzzer->report);
    }

    if (state == _HF_STATE_DYNAMIC_PRE && ATOMIC_PRE_INC(hfuzz->doneFileIndex) >= hfuzz->fileCnt) {
        fuzz_setState(hfuzz, _HF_STATE_DYNAMIC_MAIN);
    }
}

static void *fuzz_threadNew(void *arg)
{
    LOG_I("Launched new fuzzing thread");

    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;

    fuzzer_t fuzzer = {
        .pid = 0,
        .persistentPid = 0,
        .dynamicFile = util_Malloc(hfuzz->maxFileSz),

#if defined(_HF_ARCH_LINUX)
        .linux.timerId = (timer_t) 0,
#endif                          // defined(_HF_ARCH_LINUX)
        .linux.attachedPid = 0,.linux.persistentSock = -1,
    };
    defer {
        free(fuzzer.dynamicFile);
    };

    if (arch_archThreadInit(hfuzz, &fuzzer) == false) {
        LOG_F("Could not initialize the thread");
    }

    for (;;) {
        /* Check if dry run mode with verifier enabled */
        if (hfuzz->origFlipRate == 0.0L && hfuzz->useVerifier) {
            if (ATOMIC_POST_INC(hfuzz->mutationsCnt) >= hfuzz->fileCnt) {
                ATOMIC_POST_INC(hfuzz->threadsFinished);
                // All files checked, weak-up the main process
                pthread_kill(fuzz_mainThread, SIGALRM);
                return NULL;
            }
        }
        /* Check for max iterations limit if set */
        else if ((ATOMIC_POST_INC(hfuzz->mutationsCnt) >= hfuzz->mutationsMax)
                 && hfuzz->mutationsMax) {
            ATOMIC_POST_INC(hfuzz->threadsFinished);
            // Wake-up the main process
            pthread_kill(fuzz_mainThread, SIGALRM);
            return NULL;
        }

        fuzz_fuzzLoop(hfuzz, &fuzzer);
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
        fuzz_setState(hfuzz, _HF_STATE_DYNAMIC_PRE);
    } else {
        fuzz_setState(hfuzz, _HF_STATE_STATIC);
    }

    for (size_t i = 0; i < hfuzz->threadsMax; i++) {
        fuzz_runThread(hfuzz, fuzz_threadNew);
    }
}
