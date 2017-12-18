/*
 *
 * honggfuzz - the main file
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

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "cmdline.h"
#include "display.h"
#include "fuzz.h"
#include "input.h"
#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/util.h"

static int sigReceived = 0;

/*
 * CygWin/MinGW incorrectly copies stack during fork(), so we need to keep some
 * structures in the data section
 */
honggfuzz_t hfuzz;

static void exitWithMsg(const char* msg, int exit_code) {
    UNUSED ssize_t sz = write(STDERR_FILENO, msg, strlen(msg));
    exit(exit_code);
    abort();
}

void sigHandler(int sig) {
    /* We should not terminate upon SIGALRM delivery */
    if (sig == SIGALRM) {
        if (fuzz_shouldTerminate()) {
            exitWithMsg("Terminating forcefully\n", EXIT_FAILURE);
        }
        return;
    }

    if (ATOMIC_GET(sigReceived) != 0) {
        exitWithMsg("Repeated termination signal caugth\n", EXIT_FAILURE);
    }

    ATOMIC_SET(sigReceived, sig);
}

static void setupTimer(void) {
    struct itimerval it = {
        .it_value = {.tv_sec = 1, .tv_usec = 0},
        .it_interval = {.tv_sec = 1, .tv_usec = 0},
    };
    if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
        PLOG_F("setitimer(ITIMER_REAL)");
    }
}

static void setupSignalsPreThr(void) {
    /* Block signals which should be handled or blocked in the main thread */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGQUIT);
    sigaddset(&ss, SIGALRM);
    sigaddset(&ss, SIGPIPE);
    sigaddset(&ss, SIGIO);
    sigaddset(&ss, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(SIG_BLOCK)");
    }
}

static void setupSignalsPostThr(void) {
    struct sigaction sa = {
        .sa_handler = sigHandler,
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
        PLOG_F("sigaction(SIGQUIT) failed");
    }
    /* Unblock signals which should be handled by the main thread */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGQUIT);
    sigaddset(&ss, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(SIG_UNBLOCK)");
    }
}

int main(int argc, char** argv) {
    /*
     * Work around CygWin/MinGW
     */
    char** myargs = (char**)util_Malloc(sizeof(char*) * (argc + 1));
    defer { free(myargs); };

    int i;
    for (i = 0U; i < argc; i++) {
        myargs[i] = argv[i];
    }
    myargs[i] = NULL;

    if (cmdlineParse(argc, myargs, &hfuzz) == false) {
        LOG_F("Parsing of the cmd-line arguments failed");
    }

    if (hfuzz.useScreen) {
        display_init();
    }

    if (!input_init(&hfuzz)) {
        LOG_F("Couldn't load input corpus");
        exit(EXIT_FAILURE);
    }

    if (hfuzz.dictionaryFile && (input_parseDictionary(&hfuzz) == false)) {
        LOG_F("Couldn't parse dictionary file ('%s')", hfuzz.dictionaryFile);
    }

    if (hfuzz.blacklistFile && (input_parseBlacklist(&hfuzz) == false)) {
        LOG_F("Couldn't parse stackhash blacklist file ('%s')", hfuzz.blacklistFile);
    }
#define hfuzzl hfuzz.linux
    if (hfuzzl.symsBlFile &&
        ((hfuzzl.symsBlCnt = files_parseSymbolFilter(hfuzzl.symsBlFile, &hfuzzl.symsBl)) == 0)) {
        LOG_F("Couldn't parse symbols blacklist file ('%s')", hfuzzl.symsBlFile);
    }

    if (hfuzzl.symsWlFile &&
        ((hfuzzl.symsWlCnt = files_parseSymbolFilter(hfuzzl.symsWlFile, &hfuzzl.symsWl)) == 0)) {
        LOG_F("Couldn't parse symbols whitelist file ('%s')", hfuzzl.symsWlFile);
    }

    if (hfuzz.dynFileMethod != _HF_DYNFILE_NONE) {
        hfuzz.feedback = files_mapSharedMem(sizeof(feedback_t), &hfuzz.bbFd, hfuzz.io.workDir);
        if (hfuzz.feedback == MAP_FAILED) {
            LOG_F("files_mapSharedMem(sz=%zu, dir='%s') failed", sizeof(feedback_t),
                hfuzz.io.workDir);
        }
    }

    /*
     * So far, so good
     */
    pthread_t threads[hfuzz.threads.threadsMax];

    setupSignalsPreThr();
    fuzz_threadsStart(&hfuzz, threads);
    setupSignalsPostThr();

    setupTimer();
    for (;;) {
        if (hfuzz.useScreen) {
            display_display(&hfuzz);
        }
        if (ATOMIC_GET(sigReceived) > 0) {
            LOG_I("Signal %d (%s) received, terminating", ATOMIC_GET(sigReceived),
                strsignal(ATOMIC_GET(sigReceived)));
            break;
        }
        if (ATOMIC_GET(hfuzz.threads.threadsFinished) >= hfuzz.threads.threadsMax) {
            break;
        }
        if (hfuzz.timing.runEndTime > 0 && (time(NULL) > hfuzz.timing.runEndTime)) {
            LOG_I("Maximum run time reached, terminating");
            fuzz_setTerminating();
            break;
        }
        pause();
    }

    fuzz_setTerminating();

    fuzz_threadsStop(&hfuzz, threads);

    /* Clean-up global buffers */
    if (hfuzz.blacklist) {
        free(hfuzz.blacklist);
    }
    if (hfuzz.linux.symsBl) {
        free(hfuzz.linux.symsBl);
    }
    if (hfuzz.linux.symsWl) {
        free(hfuzz.linux.symsWl);
    }
    if (hfuzz.sanOpts.asanOpts) {
        free(hfuzz.sanOpts.asanOpts);
    }
    if (hfuzz.sanOpts.ubsanOpts) {
        free(hfuzz.sanOpts.ubsanOpts);
    }
    if (hfuzz.sanOpts.msanOpts) {
        free(hfuzz.sanOpts.msanOpts);
    }

    return EXIT_SUCCESS;
}
