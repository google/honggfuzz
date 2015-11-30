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
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "display.h"
#include "files.h"
#include "log.h"
#include "mangle.h"
#include "report.h"
#include "util.h"

static int fuzz_sigReceived = 0;

static pthread_t fuzz_mainThread;

static void fuzz_sigHandler(int sig)
{
    /* We should not terminate upon SIGALRM delivery */
    if (sig == SIGALRM) {
        return;
    }

    fuzz_sigReceived = sig;
}

static void fuzz_getFileName(honggfuzz_t * hfuzz, char *fileName)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    snprintf(fileName, PATH_MAX, "%s/.honggfuzz.%d.%lu.%llx.%s", hfuzz->workDir, (int)getpid(),
             (unsigned long int)tv.tv_sec, (unsigned long long int)util_rndGet(0, 1ULL << 62),
             hfuzz->fileExtn);

    return;
}

static bool fuzz_prepareFileDynamically(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    MX_LOCK(&hfuzz->dynamicFile_mutex);

    if (hfuzz->inputFile && hfuzz->hwCnts.cpuInstrCnt == 0ULL && hfuzz->hwCnts.cpuBranchCnt == 0ULL
        && hfuzz->hwCnts.pcCnt == 0ULL && hfuzz->hwCnts.pathCnt == 0ULL
        && hfuzz->hwCnts.customCnt == 0ULL) {
        size_t fileSz = files_readFileToBufMax(hfuzz->files[rnd_index], hfuzz->dynamicFileBest,
                                               hfuzz->maxFileSz);
        if (fileSz == 0) {
            MX_UNLOCK(&hfuzz->dynamicFile_mutex);
            LOG_E("Couldn't read '%s'", hfuzz->files[rnd_index]);
            return false;
        }
        hfuzz->dynamicFileBestSz = fileSz;
    }

    if (hfuzz->dynamicFileBestSz > hfuzz->maxFileSz) {
        LOG_F("Current BEST file Sz > maxFileSz (%zu > %zu)", hfuzz->dynamicFileBestSz,
              hfuzz->maxFileSz);
    }

    fuzzer->dynamicFileSz = hfuzz->dynamicFileBestSz;
    memcpy(fuzzer->dynamicFile, hfuzz->dynamicFileBest, hfuzz->dynamicFileBestSz);

    MX_UNLOCK(&hfuzz->dynamicFile_mutex);

    /* 
     * if flip rate is 0.0, early abort file mangling. This will leave perf counters
     * with values equal to dry runs against input corpus.
     */
    if (hfuzz->flipRate != 0.0L) {
        goto skipMangling;
    }
    /* The first pass should be on an empty/initial file */
    if (hfuzz->hwCnts.cpuInstrCnt > 0 || hfuzz->hwCnts.cpuBranchCnt > 0 || hfuzz->hwCnts.pcCnt > 0
        || hfuzz->hwCnts.pathCnt > 0 || hfuzz->hwCnts.customCnt > 0) {
        mangle_Resize(hfuzz, fuzzer->dynamicFile, &fuzzer->dynamicFileSz);
        mangle_mangleContent(hfuzz, fuzzer->dynamicFile, fuzzer->dynamicFileSz);
    }

 skipMangling:
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

    /* If flip rate is 0.0, early abort file mangling */
    if (hfuzz->flipRate != 0.0L) {
        mangle_Resize(hfuzz, fuzzer->dynamicFile, &fileSz);
        mangle_mangleContent(hfuzz, fuzzer->dynamicFile, fileSz);
    }

    if (files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fileSz, O_WRONLY | O_CREAT | O_EXCL) == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFileExternally(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    int dstfd = open(fuzzer->fileName, O_CREAT | O_EXCL | O_RDWR, 0644);
    if (dstfd == -1) {
        PLOG_E("Couldn't create a temporary file '%s'", fuzzer->fileName);
        return false;
    }

    LOG_D("Created '%s' as an input file", fuzzer->fileName);

    if (hfuzz->inputFile) {
        size_t fileSz =
            files_readFileToBufMax(hfuzz->files[rnd_index], fuzzer->dynamicFile, hfuzz->maxFileSz);
        if (fileSz == 0UL) {
            LOG_E("Couldn't read '%s'", hfuzz->files[rnd_index]);
            unlink(fuzzer->fileName);
            return false;
        }

        if (files_writeToFd(dstfd, fuzzer->dynamicFile, fileSz) == false) {
            close(dstfd);
            unlink(fuzzer->fileName);
            return false;
        }
    }

    close(dstfd);

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

    abort();                    /* NOTREACHED */
}

static bool fuzz_runVerifier(honggfuzz_t * hfuzz, fuzzer_t * crashedFuzzer)
{
    bool ret = false;
    int crashFd = -1;
    uint8_t *crashBuf = NULL;
    off_t crashFileSz = 0;

    crashBuf = files_mapFile(crashedFuzzer->crashFileName, &crashFileSz, &crashFd, false);
    if (crashBuf == NULL) {
        LOG_E("Couldn't open and map '%s' in R/O mode", crashedFuzzer->crashFileName);
        goto bail;
    }

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
                       .pcCnt = 0ULL,
                       .pathCnt = 0ULL,
                       .customCnt = 0ULL,
                       },
            .report = {'\0'},
            .mainWorker = false
        };

        fuzz_getFileName(hfuzz, vFuzzer.fileName);
        if (files_writeBufToFile
            (vFuzzer.fileName, crashBuf, crashFileSz, O_WRONLY | O_CREAT | O_EXCL) == false) {
            LOG_E("Couldn't write buffer to file '%s'", vFuzzer.fileName);
            goto bail;
        }

        vFuzzer.pid = arch_fork(hfuzz);
        if (vFuzzer.pid == -1) {
            PLOG_F("Couldn't fork");
            return false;
        }

        if (!vFuzzer.pid) {
            if (!arch_launchChild(hfuzz, crashedFuzzer->crashFileName)) {
                LOG_E("Error launching verifier child process");
                goto bail;
            }
        }

        arch_reapChild(hfuzz, &vFuzzer);
        unlink(vFuzzer.fileName);

        /* If stack hash doesn't match skip name tag and exit */
        if (crashedFuzzer->backtrace != vFuzzer.backtrace) {
            LOG_D("Verifier stack hash mismatch");
            goto bail;
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
            goto bail;
        }
    }

    ret = true;

 bail:
    if (crashBuf) {
        munmap(crashBuf, crashFileSz);
    }
    if (crashFd != -1) {
        close(crashFd);
    }
    return ret;
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
        .dynamicFileSz = 0,
        .dynamicFile = malloc(hfuzz->maxFileSz),
        .hwCnts = {
                   .cpuInstrCnt = 0ULL,
                   .cpuBranchCnt = 0ULL,
                   .pcCnt = 0ULL,
                   .pathCnt = 0ULL,
                   .customCnt = 0ULL,
                   },
        .report = {'\0'},
        .mainWorker = true
    };
    if (fuzzer.dynamicFile == NULL) {
        LOG_F("malloc(%zu) failed", hfuzz->maxFileSz);
    }

    size_t rnd_index = util_rndGet(0, hfuzz->fileCnt - 1);

    /* If dry run mode, pick the next file and not a random one */
    if (hfuzz->flipRate == 0.0L && hfuzz->useVerifier) {
        rnd_index = __sync_fetch_and_add(&hfuzz->lastCheckedFileIndex, 1UL);
    }

    strncpy(fuzzer.origFileName, files_basename(hfuzz->files[rnd_index]), PATH_MAX);
    fuzz_getFileName(hfuzz, fuzzer.fileName);

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        if (!fuzz_prepareFileDynamically(hfuzz, &fuzzer, rnd_index)) {
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
        /*
         * Ok, kill the parent if this fails
         */
        if (!arch_launchChild(hfuzz, fuzzer.fileName)) {
            LOG_E("Error launching child process, killing parent");
            exit(EXIT_FAILURE);
        }
    }

    LOG_D("Launched new process, pid: %d, (concurrency: %zd)", fuzzer.pid, hfuzz->threadsMax);

    arch_reapChild(hfuzz, &fuzzer);
    unlink(fuzzer.fileName);

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        LOG_D
            ("File size (New/Best): %zu/%zu, Perf feedback (instr/branch/block/block-edge/custom): Best: [%"
             PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "] / New: [%" PRIu64 ",%" PRIu64
             ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]", fuzzer.dynamicFileSz,
             hfuzz->dynamicFileBestSz, hfuzz->hwCnts.cpuInstrCnt, hfuzz->hwCnts.cpuBranchCnt,
             hfuzz->hwCnts.pcCnt, hfuzz->hwCnts.pathCnt, hfuzz->hwCnts.customCnt,
             fuzzer.hwCnts.cpuInstrCnt, fuzzer.hwCnts.cpuBranchCnt, fuzzer.hwCnts.pcCnt,
             fuzzer.hwCnts.pathCnt, fuzzer.hwCnts.customCnt);

        MX_LOCK(&hfuzz->dynamicFile_mutex);

        int64_t diff0 = hfuzz->hwCnts.cpuInstrCnt - fuzzer.hwCnts.cpuInstrCnt;
        int64_t diff1 = hfuzz->hwCnts.cpuBranchCnt - fuzzer.hwCnts.cpuBranchCnt;
        int64_t diff2 = hfuzz->hwCnts.pcCnt - fuzzer.hwCnts.pcCnt;
        int64_t diff3 = hfuzz->hwCnts.pathCnt - fuzzer.hwCnts.pathCnt;
        int64_t diff4 = hfuzz->hwCnts.customCnt - fuzzer.hwCnts.customCnt;

        if (diff0 <= 0 && diff1 <= 0 && diff2 <= 0 && diff3 <= 0 && diff4 <= 0) {

            LOG_I("New: (Size New,Old): %zu,%zu, Perf (Cur,New): %"
                  PRId64 "/%" PRId64 "/%" PRId64 "/%" PRId64 "/%" PRId64 ",%" PRId64 "/%" PRId64
                  "/%" PRId64 "/%" PRId64 "/%" PRId64, fuzzer.dynamicFileSz,
                  hfuzz->dynamicFileBestSz, hfuzz->hwCnts.cpuInstrCnt, hfuzz->hwCnts.cpuBranchCnt,
                  hfuzz->hwCnts.pcCnt, hfuzz->hwCnts.pathCnt, hfuzz->hwCnts.customCnt,
                  fuzzer.hwCnts.cpuInstrCnt, fuzzer.hwCnts.cpuBranchCnt, fuzzer.hwCnts.pcCnt,
                  fuzzer.hwCnts.pathCnt, fuzzer.hwCnts.customCnt);

            memcpy(hfuzz->dynamicFileBest, fuzzer.dynamicFile, fuzzer.dynamicFileSz);

            hfuzz->dynamicFileBestSz = fuzzer.dynamicFileSz;
            hfuzz->hwCnts.cpuInstrCnt = fuzzer.hwCnts.cpuInstrCnt;
            hfuzz->hwCnts.cpuBranchCnt = fuzzer.hwCnts.cpuBranchCnt;
            hfuzz->hwCnts.pcCnt = fuzzer.hwCnts.pcCnt;
            hfuzz->hwCnts.pathCnt = fuzzer.hwCnts.pathCnt;
            hfuzz->hwCnts.customCnt = fuzzer.hwCnts.customCnt;

            char currentBest[PATH_MAX], currentBestTmp[PATH_MAX];
            snprintf(currentBest, PATH_MAX, "%s/CURRENT_BEST", hfuzz->workDir);
            snprintf(currentBestTmp, PATH_MAX, "%s/.tmp.CURRENT_BEST", hfuzz->workDir);

            if (files_writeBufToFile
                (currentBestTmp, fuzzer.dynamicFile, fuzzer.dynamicFileSz,
                 O_WRONLY | O_CREAT | O_TRUNC)) {
                rename(currentBestTmp, currentBest);
            }
        }
        MX_UNLOCK(&hfuzz->dynamicFile_mutex);
    }

    if (hfuzz->useVerifier && (fuzzer.crashFileName[0] != 0) && fuzzer.backtrace) {
        if (!fuzz_runVerifier(hfuzz, &fuzzer)) {
            LOG_I("Failed to verify %s", fuzzer.crashFileName);
        }
    }

    report_Report(hfuzz, fuzzer.report);
    free(fuzzer.dynamicFile);

}

static void *fuzz_threadNew(void *arg)
{
    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;
    for (;;) {
        /* Check if dry run mode with verifier enabled */
        if (hfuzz->flipRate == 0.0L && hfuzz->useVerifier) {
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

bool fuzz_setupTimer(void)
{
    struct itimerval it = {
        .it_value = {.tv_sec = 0,.tv_usec = 1},
        .it_interval = {.tv_sec = 1,.tv_usec = 0},
    };
    if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
        PLOG_E("setitimer(ITIMER_REAL)");
        return false;
    }
    return true;
}

void fuzz_main(honggfuzz_t * hfuzz)
{
    fuzz_mainThread = pthread_self();

    struct sigaction sa = {
        .sa_handler = fuzz_sigHandler,
        .sa_flags = 0,
    };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGTERM) failed");
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGINT) failed");
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGQUIT) failed");
    }
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGALRM) failed");
    }
    if (fuzz_setupTimer() == false) {
        LOG_F("fuzz_setupTimer()");
    }

    if (!arch_archInit(hfuzz)) {
        LOG_F("Couldn't prepare arch for fuzzing");
    }

    for (size_t i = 0; i < hfuzz->threadsMax; i++) {
        fuzz_runThread(hfuzz, fuzz_threadNew);
    }

    for (;;) {
        if (hfuzz->useScreen) {
            display_display(hfuzz);
        }
        if (fuzz_sigReceived > 0) {
            break;
        }
        if (__sync_fetch_and_add(&hfuzz->threadsFinished, 0UL) >= hfuzz->threadsMax) {
            break;
        }
        pause();
    }

    if (fuzz_sigReceived > 0) {
        LOG_I("Signal %d (%s) received, terminating", fuzz_sigReceived,
              strsignal(fuzz_sigReceived));
    }

    free(hfuzz->files);
    free(hfuzz->dynamicFileBest);
    if (hfuzz->dictionary) {
        free(hfuzz->dictionary);
    }
    if (hfuzz->blacklist) {
        free(hfuzz->blacklist);
    }

    _exit(EXIT_SUCCESS);
}
