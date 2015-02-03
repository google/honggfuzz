/*

   honggfuzz - fuzzing routines
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>
           Felix Gröbert <groebert@google.com>

   Copyright 2010-2015 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "common.h"
#include "fuzz.h"

#include <errno.h>
#include <fcntl.h>
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

#include "log.h"
#include "arch.h"
#include "util.h"
#include "files.h"

static void fuzz_mangleContent(honggfuzz_t * hfuzz, uint8_t * buf, off_t fileSz)
{
    /*
     * Just copy the file if "-r 0"
     */
    if (hfuzz->flipRate == 0.0) {
        return;
    }

    uint64_t changesCnt = fileSz * hfuzz->flipRate;

    if (hfuzz->flipMode == 'b') {
        changesCnt *= 8UL;
    }

    changesCnt = util_rndGet(1, changesCnt);

    for (uint64_t x = 0; x < changesCnt; x++) {
        off_t pos = util_rndGet(0, fileSz - 1);

        if (hfuzz->flipMode == 'b') {
            buf[pos] ^= (1 << util_rndGet(0, 7));
        } else {
            buf[pos] = (uint8_t) util_rndGet(0, 255);
        }
    }
}

static void fuzz_getFileName(honggfuzz_t * hfuzz, char *fileName)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    snprintf(fileName, PATH_MAX, ".honggfuzz.%d.%lu.%lu.%lu.%s", (int)getpid(),
             (unsigned long int)tv.tv_sec, (unsigned long int)tv.tv_usec,
             (unsigned long int)util_rndGet(0, 1 << 30), hfuzz->fileExtn);

    return;
}

static void fuzz_appendOrTrunc(int fd, off_t fileSz)
{
    const int chance_one_in_x = 10;
    if (util_rndGet(1, chance_one_in_x) != 1) {
        return;
    }

    off_t maxSz = 2 * fileSz;
    if (fileSz > (1024 * 1024 * 20)) {
        maxSz = fileSz + (fileSz / 4);
    }
    if (fileSz > (1024 * 1024 * 100)) {
        maxSz = fileSz;
    }

    off_t newSz = util_rndGet(1, maxSz);
    if (ftruncate(fd, newSz) == -1) {
        LOGMSG_P(l_WARN, "Couldn't truncate file from '%ld' to '%ld' bytes", (long)fileSz,
                 (long)newSz);
        return;
    }
}

static bool fuzz_prepareFile(honggfuzz_t * hfuzz, char *fileName, int rnd_index)
{
    off_t fileSz;
    int srcfd;

    uint8_t *buf = files_mapFileToRead(hfuzz->files[rnd_index], &fileSz, &srcfd);
    if (buf == NULL) {
        LOGMSG(l_ERROR, "Couldn't open and map '%s' in R/O mode", hfuzz->files[rnd_index]);
        return false;
    }

    LOGMSG(l_DEBUG, "Mmaped '%s' in R/O mode, size: %d", hfuzz->files[rnd_index], fileSz);

    int dstfd = open(fileName, O_CREAT | O_EXCL | O_RDWR, 0644);
    if (dstfd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't create a temporary file '%s' in the current directory",
                 fileName);
        munmap(buf, fileSz);
        close(srcfd);
        return false;
    }

    fuzz_mangleContent(hfuzz, buf, fileSz);

    if (!files_writeToFd(dstfd, buf, fileSz)) {
        munmap(buf, fileSz);
        close(srcfd);
        close(dstfd);
        return false;
    }

    munmap(buf, fileSz);

    fuzz_appendOrTrunc(dstfd, fileSz);

    close(srcfd);
    close(dstfd);
    return true;
}

static bool fuzz_prepareFileExternally(honggfuzz_t * hfuzz, char *fileName, int rnd_index)
{
    off_t fileSz;
    int srcfd;

    int dstfd = open(fileName, O_CREAT | O_EXCL | O_RDWR, 0644);
    if (dstfd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't create a temporary file '%s' in the current directory",
                 fileName);
        return false;
    }

    LOGMSG(l_DEBUG, "Created '%f' as an input file", fileName);

    if (hfuzz->inputFile) {
        uint8_t *buf = files_mapFileToRead(hfuzz->files[rnd_index], &fileSz, &srcfd);
        if (buf == NULL) {
            LOGMSG(l_ERROR, "Couldn't open and map '%s' in R/O mode", hfuzz->files[rnd_index]);
            close(dstfd);
            return false;
        }

        LOGMSG(l_DEBUG, "Mmaped '%s' in R/O mode, size: %d", hfuzz->files[rnd_index], fileSz);

        bool ret = files_writeToFd(dstfd, buf, fileSz);
        munmap(buf, fileSz);
        close(srcfd);

        if (!ret) {
            close(dstfd);
            return false;
        }
    }

    close(dstfd);

    pid_t pid = fork();
    if (pid == -1) {
        LOGMSG_P(l_ERROR, "Couldn't fork");
        return false;
    }

    if (!pid) {
        /*
         * child does the external file modifications
         */
        execl(hfuzz->externalCommand, hfuzz->externalCommand, fileName, NULL);
        LOGMSG_P(l_FATAL, "Couldn't execute '%s %s'", hfuzz->externalCommand, fileName);
        return false;
    } else {
        /*
         * parent waits until child is done fuzzing the input file
         */

        int childStatus;
        pid_t terminatedPid;
        do {
            terminatedPid = wait(&childStatus);
        } while (terminatedPid != pid);

        if (WIFEXITED(childStatus)) {
            LOGMSG(l_DEBUG, "External command exited with status %d", WEXITSTATUS(childStatus));
            return true;
        } else if (WIFSIGNALED(childStatus)) {
            LOGMSG(l_ERROR, "External command terminated  with signal %d", WTERMSIG(childStatus));
            return false;
        }
        LOGMSG(l_FATAL, "External command terminated abnormally, status: %d", childStatus);
        return false;
    }

    abort();                    /* NOTREACHED */
}

static void fuzz_reapChild(honggfuzz_t * hfuzz)
{
    pid_t pid = arch_reapChild(hfuzz);
    if (pid <= 0) {
        return;
    }

    int idx = HF_SLOT(hfuzz, pid);
    // Might be a process we are attached to
    if (idx == -1) {
        return;
    }

    unlink(hfuzz->fuzzers[idx].fileName);
    hfuzz->fuzzers[idx].pid = 0;
    hfuzz->threadsCnt--;
}

static void fuzz_runNext(honggfuzz_t * hfuzz)
{
    int i = HF_SLOT(hfuzz, 0);
    int rnd_index = util_rndGet(0, hfuzz->fileCnt - 1);

    strncpy(hfuzz->fuzzers[i].origFileName, files_basename(hfuzz->files[rnd_index]), PATH_MAX);

    fuzz_getFileName(hfuzz, hfuzz->fuzzers[i].fileName);

    /*
     * Store when we started the target
     */
    hfuzz->fuzzers[i].timeStarted = time(NULL);

    pid_t pid = fork();

    if (pid == -1) {
        LOGMSG_P(l_FATAL, "Couldn't fork");
        exit(EXIT_FAILURE);
    }

    if (!pid) {
        /*
         *  We've forked, other pid's might have the same rnd seeds now,
         *  reinitialize it
         */
        util_rndInit();

        hfuzz->fuzzers[i].pid = getpid();

        if (hfuzz->externalCommand != NULL) {
            if (!fuzz_prepareFileExternally(hfuzz, hfuzz->fuzzers[i].fileName, rnd_index)) {
                exit(EXIT_FAILURE);
            }
        } else {
            if (!fuzz_prepareFile(hfuzz, hfuzz->fuzzers[i].fileName, rnd_index)) {
                exit(EXIT_FAILURE);
            }
        }

        /*
         * Ok, kill the parent
         */

        if (!arch_launchChild(hfuzz, hfuzz->fuzzers[i].fileName)) {
            LOGMSG(l_DEBUG, "Error launching child process, killing parent");
            kill(getppid(), SIGTERM);
            exit(EXIT_FAILURE);
        }
    }

    hfuzz->threadsCnt++;
    hfuzz->fuzzers[i].pid = pid;

    LOGMSG(l_INFO, "Launched new process, pid: %d, (%d/%d)", pid,
           hfuzz->threadsCnt, hfuzz->threadsMax);
    return;
}

void fuzz_main(honggfuzz_t * hfuzz)
{
    if (!arch_prepareParent(hfuzz)) {
        LOGMSG(l_FATAL, "Couldn't prepare parent for fuzzing");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        while (hfuzz->threadsCnt < hfuzz->threadsMax) {
            fuzz_runNext(hfuzz);

            if (hfuzz->mutationsMax != 0) {
                /* We just want a limited number of mutations */
                hfuzz->mutationsCnt++;

                if (hfuzz->mutationsCnt >= hfuzz->mutationsMax) {
                    LOGMSG(l_INFO, "Waiting for childs and exiting.");

                    while (hfuzz->threadsCnt != 0) {
                        fuzz_reapChild(hfuzz);
                    }
                    LOGMSG(l_INFO, "Finished fuzzing %ld times.", hfuzz->mutationsMax);
                    exit(EXIT_SUCCESS);
                }
            }
        }
        fuzz_reapChild(hfuzz);
    }
}
