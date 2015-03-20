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
    while (pthread_mutex_lock(&hfuzz->dynamicFile_mutex)) ;

    if (hfuzz->inputFile && hfuzz->branchBestCnt[0] == 0 && hfuzz->branchBestCnt[1] == 0
        && hfuzz->branchBestCnt[2] == 0 && hfuzz->branchBestCnt[3] == 0) {
        size_t fileSz = files_readFileToBufMax(hfuzz->files[rnd_index], hfuzz->dynamicFileBest,
                                               hfuzz->maxFileSz);
        if (fileSz == 0) {
            while (pthread_mutex_unlock(&hfuzz->dynamicFile_mutex)) ;
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

    while (pthread_mutex_unlock(&hfuzz->dynamicFile_mutex)) ;

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

static int fuzz_numOfProc(honggfuzz_t * hfuzz)
{
    int i;
    sem_getvalue(hfuzz->sem, &i);
    return hfuzz->threadsMax - i;
}

static void *fuzz_threadNew(void *arg)
{
    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;
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

#if defined(_HF_ARCH_LINUX)
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

    LOGMSG(l_INFO, "Launched new process, pid: %d, (%d/%d)", fuzzer.pid, fuzz_numOfProc(hfuzz),
           hfuzz->threadsMax);

    arch_reapChild(hfuzz, &fuzzer);
    unlink(fuzzer.fileName);

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        while (pthread_mutex_lock(&hfuzz->dynamicFile_mutex)) ;

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

        if (diff0 <= hfuzz->dynamicRegressionCnt && diff1 <= hfuzz->dynamicRegressionCnt
            && diff2 <= hfuzz->dynamicRegressionCnt && diff3 <= hfuzz->dynamicRegressionCnt) {

            LOGMSG(l_INFO,
                   "New BEST feedback: File Size (New/Old): %zu/%zu', Perf feedback (Curr, High): %"
                   PRId64 "/%" PRId64 "/%" PRId64 "/%" PRId64 ",%" PRId64 "/%" PRId64 "/%" PRId64
                   "/%" PRId64, fuzzer.dynamicFileSz, hfuzz->dynamicFileBestSz, fuzzer.branchCnt[0],
                   fuzzer.branchCnt[1], fuzzer.branchCnt[2], fuzzer.branchCnt[3],
                   hfuzz->branchBestCnt[0], hfuzz->branchBestCnt[1], hfuzz->branchBestCnt[2],
                   hfuzz->branchBestCnt[3]);

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
        while (pthread_mutex_unlock(&hfuzz->dynamicFile_mutex)) ;
    }

    report_Report(hfuzz, fuzzer.report);
    free(fuzzer.dynamicFile);

    sem_post(hfuzz->sem);

    return NULL;
}

static void *fuzz_threadPid(void *arg)
{
    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;
    if (!arch_archInit(hfuzz)) {
        LOGMSG(l_FATAL, "Couldn't prepare parent for fuzzing");
    }

    fuzzer_t fuzzer = {
        .pid = hfuzz->pid,
        .timeStartedMillis = util_timeNowMillis(),
        .pc = 0ULL,
        .backtrace = 0ULL,
        .access = 0ULL,
        .exception = 0,
        .dynamicFileSz = 0,
        .dynamicFile = malloc(hfuzz->maxFileSz),
        .branchCnt = {[0 ... (ARRAYSIZE(fuzzer.branchCnt) - 1)] = 0}
        ,
        .report = {'\0'}
    };
    if (fuzzer.dynamicFile == NULL) {
        LOGMSG(l_FATAL, "malloc(%zu) failed", hfuzz->maxFileSz);
    }

    char fileName[] = ".honggfuzz.empty.XXXXXX";
    int fd;
    if ((fd = mkstemp(fileName)) == -1) {
        free(fuzzer.dynamicFile);
        LOGMSG_P(l_ERROR, "Couldn't create a temporary file");
        return NULL;
    }
    close(fd);

    strncpy(fuzzer.origFileName, "PID_FUZZING", PATH_MAX);
    strncpy(fuzzer.fileName, fileName, PATH_MAX);

    arch_reapChild(hfuzz, &fuzzer);
    unlink(fuzzer.fileName);
    report_Report(hfuzz, fuzzer.report);
    free(fuzzer.dynamicFile);

    // There's no more hfuzz->pid to analyze. Just exit
    LOGMSG(l_INFO, "PID: %d exited. Exiting", fuzzer.pid);
    exit(EXIT_SUCCESS);

    return NULL;
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
    char semName[PATH_MAX];
    snprintf(semName, sizeof(semName), "/honggfuzz.%d.%d.%" PRIx64, getpid(),
             (int)time(NULL), util_rndGet(1, 1ULL << 62));

    hfuzz->sem = sem_open(semName, O_CREAT, 0644, hfuzz->threadsMax);
    if (hfuzz->sem == SEM_FAILED) {
        LOGMSG_P(l_FATAL, "sem_open() failed");
    }
    // If we're doing a PID fuzzing, the parent of the PID will be a
    // dedicated thread anyway
    if (hfuzz->pid) {
        fuzz_runThread(hfuzz, fuzz_threadPid);
    } else {
        if (!arch_archInit(hfuzz)) {
            LOGMSG(l_FATAL, "Couldn't prepare parent for fuzzing");
        }
    }

    for (;;) {
        if (sem_wait(hfuzz->sem) == -1) {
            LOGMSG_P(l_FATAL, "sem_wait() failed");
        }

        if (hfuzz->mutationsMax && (hfuzz->mutationsCnt >= hfuzz->mutationsMax)) {
#if defined(_HF_ARCH_DARWIN)
            /*
             * Sleep a bit to let any running fuzzers terminate
             */
            usleep(1.2 * hfuzz->tmOut * 1000000);
#else                           /* defined(_HF_ARCH_DARWIN) */
            while (fuzz_numOfProc(hfuzz) > 1) {
                usleep(10000);
            }
#endif                          /* defined(_HF_ARCH_DARWIN) */
            LOGMSG(l_INFO, "Finished fuzzing %ld times.", hfuzz->mutationsMax);
            sem_destroy(hfuzz->sem);
            exit(EXIT_SUCCESS);
        }

        hfuzz->mutationsCnt++;
        fuzz_runThread(hfuzz, fuzz_threadNew);
    }
}
