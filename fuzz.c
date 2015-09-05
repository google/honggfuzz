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
#include "files.h"
#include "log.h"
#include "mangle.h"
#include "report.h"
#include "util.h"

#if defined(__ANDROID__) && !defined(__NR_fork)
#include <sys/syscall.h>

pid_t honggfuzz_aarch64_fork(void)
{
    return syscall(__NR_clone, SIGCHLD, 0, 0, 0);
}

#define fork honggfuzz_aarch64_fork
#endif

static int fuzz_sigReceived = 0;

static void fuzz_sigHandler(int sig, siginfo_t * si, void *v)
{
    fuzz_sigReceived = sig;
    return;
    if (si == NULL) {
        return;
    }
    if (v == NULL) {
        return;
    }
}

static void fuzz_getFileName(honggfuzz_t * hfuzz, char *fileName)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    snprintf(fileName, PATH_MAX, ".honggfuzz.%d.%lu.%llx.%s", (int)getpid(),
             (unsigned long int)tv.tv_sec, (unsigned long long int)util_rndGet(0, 1ULL << 62),
             hfuzz->fileExtn);

    return;
}

static bool fuzz_prepareFileDynamically(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    MX_LOCK(&hfuzz->dynamicFile_mutex);

    if (hfuzz->inputFile && hfuzz->branchBestCnt[0] == 0 && hfuzz->branchBestCnt[1] == 0
        && hfuzz->branchBestCnt[2] == 0 && hfuzz->branchBestCnt[3] == 0) {
        size_t fileSz = files_readFileToBufMax(hfuzz->files[rnd_index], hfuzz->dynamicFileBest,
                                               hfuzz->maxFileSz);
        if (fileSz == 0) {
            MX_UNLOCK(&hfuzz->dynamicFile_mutex);
            LOGMSG(l_ERROR, "Couldn't read '%s'", hfuzz->files[rnd_index]);
            return false;
        }
        hfuzz->dynamicFileBestSz = fileSz;
    }

    if (hfuzz->dynamicFileBestSz > hfuzz->maxFileSz) {
        LOGMSG(l_FATAL, "Current BEST file Sz > maxFileSz (%zu > %zu)", hfuzz->dynamicFileBestSz,
               hfuzz->maxFileSz);
    }

    fuzzer->dynamicFileSz = hfuzz->dynamicFileBestSz;
    memcpy(fuzzer->dynamicFile, hfuzz->dynamicFileBest, hfuzz->dynamicFileBestSz);

    MX_UNLOCK(&hfuzz->dynamicFile_mutex);

    /* The first pass should be on an empty/initial file */
    if (hfuzz->branchBestCnt[0] > 0 || hfuzz->branchBestCnt[1] > 0 || hfuzz->branchBestCnt[2] > 0
        || hfuzz->branchBestCnt[3] > 0) {
        mangle_Resize(hfuzz, fuzzer->dynamicFile, &fuzzer->dynamicFileSz);
        mangle_mangleContent(hfuzz, fuzzer->dynamicFile, fuzzer->dynamicFileSz);
    }

    if (files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
         O_WRONLY | O_CREAT | O_EXCL | O_TRUNC) == false) {
        LOGMSG(l_ERROR, "Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFile(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    size_t fileSz =
        files_readFileToBufMax(hfuzz->files[rnd_index], fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (fileSz == 0UL) {
        LOGMSG(l_ERROR, "Couldn't read contents of '%s'", hfuzz->files[rnd_index]);
        return false;
    }

    mangle_Resize(hfuzz, fuzzer->dynamicFile, &fileSz);
    mangle_mangleContent(hfuzz, fuzzer->dynamicFile, fileSz);

    if (files_writeBufToFile
        (fuzzer->fileName, fuzzer->dynamicFile, fileSz, O_WRONLY | O_CREAT | O_EXCL) == false) {
        LOGMSG(l_ERROR, "Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFileExternally(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int rnd_index)
{
    int dstfd = open(fuzzer->fileName, O_CREAT | O_EXCL | O_RDWR, 0644);
    if (dstfd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't create a temporary file '%s' in the current directory",
                 fuzzer->fileName);
        return false;
    }

    LOGMSG(l_DEBUG, "Created '%f' as an input file", fuzzer->fileName);

    if (hfuzz->inputFile) {
        size_t fileSz =
            files_readFileToBufMax(hfuzz->files[rnd_index], fuzzer->dynamicFile, hfuzz->maxFileSz);
        if (fileSz == 0UL) {
            LOGMSG(l_ERROR, "Couldn't read '%s'", hfuzz->files[rnd_index]);
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

    pid_t pid = fork();
    if (pid == -1) {
        LOGMSG_P(l_ERROR, "Couldn't vfork");
        return false;
    }

    if (!pid) {
        /*
         * child performs the external file modifications
         */
        execl(hfuzz->externalCommand, hfuzz->externalCommand, fuzzer->fileName, NULL);
        LOGMSG_P(l_FATAL, "Couldn't execute '%s %s'", hfuzz->externalCommand, fuzzer->fileName);
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
        LOGMSG(l_DEBUG, "External command exited with status %d", WEXITSTATUS(childStatus));
        return true;
    }
    if (WIFSIGNALED(childStatus)) {
        LOGMSG(l_ERROR, "External command terminated with signal %d", WTERMSIG(childStatus));
        return false;
    }
    LOGMSG(l_FATAL, "External command terminated abnormally, status: %d", childStatus);
    return false;

    abort();                    /* NOTREACHED */
}

static void fuzz_fuzzLoop(honggfuzz_t * hfuzz)
{
    fuzzer_t fuzzer = {
        .pid = 0,
        .timeStartedMillis = util_timeNowMillis(),
        .pc = 0ULL,
        .backtrace = 0ULL,
        .access = 0ULL,
        .exception = 0,
        .dynamicFileSz = 0,
        .dynamicFile = malloc(hfuzz->maxFileSz),
        .branchCnt = {[0 ... (ARRAYSIZE(fuzzer.branchCnt) - 1)] = 0},
        .report = {'\0'}
    };
    if (fuzzer.dynamicFile == NULL) {
        LOGMSG(l_FATAL, "malloc(%zu) failed", hfuzz->maxFileSz);
    }

    int rnd_index = util_rndGet(0, hfuzz->fileCnt - 1);
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

#if defined(_HF_ARCH_LINUX) && defined(__NR_fork)
#include <unistd.h>
#include <sys/syscall.h>
    fuzzer.pid = syscall(__NR_fork);
#else                           /* defined(_HF_ARCH_LINUX) */
    fuzzer.pid = fork();
#endif                          /* defined(_HF_ARCH_LINUX) */

    if (fuzzer.pid == -1) {
        LOGMSG_P(l_FATAL, "Couldn't fork");
        exit(EXIT_FAILURE);
    }

    if (!fuzzer.pid) {
        /*
         * Ok, kill the parent if this fails
         */
        if (!arch_launchChild(hfuzz, fuzzer.fileName)) {
            LOGMSG(l_ERROR, "Error launching child process, killing parent");
            exit(EXIT_FAILURE);
        }
    }

    LOGMSG(l_INFO, "Launched new process, pid: %d, (concurrency: %d)", fuzzer.pid,
           hfuzz->threadsMax);

    arch_reapChild(hfuzz, &fuzzer);
    unlink(fuzzer.fileName);

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        MX_LOCK(&hfuzz->dynamicFile_mutex);

        LOGMSG(l_INFO,
               "File size (New/Best): %zu/%zu, Perf feedback (instr/branch/block-edge/custom): Best: [%"
               PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "] / New: [%" PRIu64 ",%" PRIu64 ",%"
               PRIu64 ",%" PRIu64 "]", fuzzer.dynamicFileSz, hfuzz->dynamicFileBestSz,
               hfuzz->branchBestCnt[0], hfuzz->branchBestCnt[1], hfuzz->branchBestCnt[2],
               hfuzz->branchBestCnt[3], fuzzer.branchCnt[0], fuzzer.branchCnt[1],
               fuzzer.branchCnt[2], fuzzer.branchCnt[3]);

        int64_t diff0 = hfuzz->branchBestCnt[0] - fuzzer.branchCnt[0];
        int64_t diff1 = hfuzz->branchBestCnt[1] - fuzzer.branchCnt[1];
        int64_t diff2 = hfuzz->branchBestCnt[2] - fuzzer.branchCnt[2];
        int64_t diff3 = hfuzz->branchBestCnt[3] - fuzzer.branchCnt[3];

        if (diff2 < 0) {
            diff0 = hfuzz->branchBestCnt[0] = fuzzer.branchCnt[0] = 0;
            diff1 = hfuzz->branchBestCnt[1] = fuzzer.branchCnt[1] = 0;
            diff3 = hfuzz->branchBestCnt[3] = fuzzer.branchCnt[3] = 0;
        }

        if (diff0 <= hfuzz->dynamicRegressionCnt && diff1 <= hfuzz->dynamicRegressionCnt
            && diff2 <= hfuzz->dynamicRegressionCnt && diff3 <= hfuzz->dynamicRegressionCnt) {

            LOGMSG(l_WARN,
                   "New BEST feedback: File Size (New/Old): %zu/%zu', Perf feedback (Curr, High): %"
                   PRId64 "/%" PRId64 "/%" PRId64 "/%" PRId64 ",%" PRId64 "/%" PRId64 "/%"
                   PRId64 "/%" PRId64, fuzzer.dynamicFileSz, hfuzz->dynamicFileBestSz,
                   fuzzer.branchCnt[0], fuzzer.branchCnt[1], fuzzer.branchCnt[2],
                   fuzzer.branchCnt[3], hfuzz->branchBestCnt[0], hfuzz->branchBestCnt[1],
                   hfuzz->branchBestCnt[2], hfuzz->branchBestCnt[3]);

            memcpy(hfuzz->dynamicFileBest, fuzzer.dynamicFile, fuzzer.dynamicFileSz);

            hfuzz->dynamicFileBestSz = fuzzer.dynamicFileSz;
            hfuzz->branchBestCnt[0] =
                fuzzer.branchCnt[0] >
                hfuzz->branchBestCnt[0] ? fuzzer.branchCnt[0] : hfuzz->branchBestCnt[0];
            hfuzz->branchBestCnt[1] =
                fuzzer.branchCnt[1] >
                hfuzz->branchBestCnt[1] ? fuzzer.branchCnt[1] : hfuzz->branchBestCnt[1];
            hfuzz->branchBestCnt[2] =
                fuzzer.branchCnt[2] >
                hfuzz->branchBestCnt[2] ? fuzzer.branchCnt[2] : hfuzz->branchBestCnt[2];
            hfuzz->branchBestCnt[3] =
                fuzzer.branchCnt[3] >
                hfuzz->branchBestCnt[3] ? fuzzer.branchCnt[3] : hfuzz->branchBestCnt[3];

#define _HF_CURRENT_BEST "CURRENT_BEST"
#define _HF_CURRENT_BEST_TMP ".tmp.CURRENT_BEST"
            if (files_writeBufToFile
                (_HF_CURRENT_BEST_TMP, fuzzer.dynamicFile, fuzzer.dynamicFileSz,
                 O_WRONLY | O_CREAT | O_TRUNC)) {
                rename(_HF_CURRENT_BEST_TMP, _HF_CURRENT_BEST);
            }
        }
        MX_UNLOCK(&hfuzz->dynamicFile_mutex);
    }

    report_Report(hfuzz, fuzzer.report);
    free(fuzzer.dynamicFile);

}

static void *fuzz_threadNew(void *arg)
{
    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;
    for (;;) {
        MX_LOCK(&hfuzz->threads_mutex);
        if (hfuzz->mutationsMax && hfuzz->mutationsCnt >= hfuzz->mutationsMax) {
            hfuzz->threadsFinished++;
            MX_UNLOCK(&hfuzz->threads_mutex);
            sem_post(hfuzz->sem);
            return NULL;
        }
        hfuzz->mutationsCnt++;
        MX_UNLOCK(&hfuzz->threads_mutex);

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
        LOGMSG_P(l_FATAL, "Couldn't create a new thread");
    }

    return;
}

void fuzz_main(honggfuzz_t * hfuzz)
{
    struct sigaction sa = {
        .sa_sigaction = fuzz_sigHandler,
        .sa_flags = SA_SIGINFO,
    };
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        LOGMSG_P(l_FATAL, "sigaction(SIGTERM) failed");
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        LOGMSG_P(l_FATAL, "sigaction(SIGINT) failed");
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        LOGMSG_P(l_FATAL, "sigaction(SIGQUIT) failed");
    }
    // Android doesn't support named semaphores
#if !defined(__ANDROID__)
    /*
     * In OS X semName cannot exceed SEM_NAME_LEN characters otherwise
     * sem_open() will fail with ENAMETOOLONG. Apple, doesn't define
     * SEM_NAME_LEN in any header file so we define it here using the value
     * of PSEMNAMLEN from bsd/kern/posix_sem.c.
     */
#define _HF_SEM_NAME_LEN 31
    char semName[_HF_SEM_NAME_LEN];
    snprintf(semName, sizeof(semName), "/hgfz.%d.%" PRIx64, getpid(), util_rndGet(1, 1ULL << 62));

    hfuzz->sem = sem_open(semName, O_CREAT, 0644, 0);

#else                           /* !defined(__ANDROID__) */
    sem_t semName;
    if (sem_init(&semName, 1, 0)) {
        LOGMSG(l_FATAL, "sem_init() failed");
    }
    hfuzz->sem = &semName;
#endif                          /* defined(__ANDROID__) */

    if (hfuzz->sem == SEM_FAILED) {
        LOGMSG_P(l_FATAL, "sem_open() failed");
    }

    if (!arch_archInit(hfuzz)) {
        LOGMSG(l_FATAL, "Couldn't prepare arch for fuzzing");
    }

    for (size_t i = 0; i < hfuzz->threadsMax; i++) {
        fuzz_runThread(hfuzz, fuzz_threadNew);
    }

    for (;;) {
        if (sem_wait(hfuzz->sem) == -1 && errno != EINTR) {
            LOGMSG_P(l_FATAL, "sem_wait() failed");
        }
        if (fuzz_sigReceived > 0) {
            break;
        }
        MX_LOCK(&hfuzz->threads_mutex);
        if (hfuzz->threadsFinished == hfuzz->threadsMax) {
            MX_UNLOCK(&hfuzz->threads_mutex);
            break;
        }
        MX_UNLOCK(&hfuzz->threads_mutex);
    }

    LOGMSG(l_INFO, "Finished fuzzing %zu times", hfuzz->mutationsCnt);

    if (fuzz_sigReceived > 0) {
        LOGMSG(l_INFO, "Signal %d received, terminating", fuzz_sigReceived);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        raise(fuzz_sigReceived);
    }
#ifdef __ANDROID__
    sem_destroy(&semName);
#else
    sem_unlink(semName);
#endif
    exit(EXIT_SUCCESS);
}
