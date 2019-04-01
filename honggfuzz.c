/*
 *
 * honggfuzz - the main file
 * -----------------------------------------
 *
 * Authors: Robert Swiecki <swiecki@google.com>
 *          Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2019 by Google Inc. All Rights Reserved.
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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "cmdline.h"
#include "display.h"
#include "fuzz.h"
#include "input.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "socketfuzzer.h"
#include "subproc.h"

static int sigReceived = 0;

/*
 * CygWin/MinGW incorrectly copies stack during fork(), so we need to keep some
 * structures in the data section
 */
honggfuzz_t hfuzz;

static void exitWithMsg(const char* msg, int exit_code) {
    HF_ATTR_UNUSED ssize_t sz = write(STDERR_FILENO, msg, strlen(msg));
    for (;;) {
        exit(exit_code);
        _exit(exit_code);
        abort();
        __builtin_trap();
    }
}

static void sigHandler(int sig) {
    /* We should not terminate upon SIGALRM delivery */
    if (sig == SIGALRM) {
        if (fuzz_shouldTerminate()) {
            exitWithMsg("Terminating forcefully\n", EXIT_FAILURE);
        }
        return;
    }
    /* Do nothing with pings from the main thread */
    if (sig == SIGUSR1) {
        return;
    }
    /* It's handled in the signal thread */
    if (sig == SIGCHLD) {
        return;
    }

    if (ATOMIC_GET(sigReceived) != 0) {
        exitWithMsg("Repeated termination signal caugth\n", EXIT_FAILURE);
    }

    ATOMIC_SET(sigReceived, sig);
}

static void setupRLimits(void) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        PLOG_W("getrlimit(RLIMIT_NOFILE)");
        return;
    }
    if (rlim.rlim_cur >= 1024) {
        return;
    }
    if (rlim.rlim_max < 1024) {
        LOG_E("RLIMIT_NOFILE max limit < 1024 (%zu). Expect troubles!", (size_t)rlim.rlim_max);
        return;
    }
    rlim.rlim_cur = MIN(1024, rlim.rlim_max);  // we don't need more
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        PLOG_E("Couldn't setrlimit(RLIMIT_NOFILE, cur=%zu/max=%zu)", (size_t)rlim.rlim_cur,
            (size_t)rlim.rlim_max);
    }
}

static void setupMainThreadTimer(void) {
    const struct itimerval it = {
        .it_value =
            {
                .tv_sec = 1,
                .tv_usec = 0,
            },
        .it_interval =
            {
                .tv_sec = 0,
                .tv_usec = 1000ULL * 200ULL,
            },
    };
    if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
        PLOG_F("setitimer(ITIMER_REAL)");
    }
}

static void setupSignalsPreThreads(void) {
    /* Block signals which should be handled or blocked in the main thread */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGQUIT);
    sigaddset(&ss, SIGALRM);
    sigaddset(&ss, SIGPIPE);
    /* Linux/arch uses it to discover events from persistent fuzzing processes */
    sigaddset(&ss, SIGIO);
    /* Let the signal thread catch SIGCHLD */
    sigaddset(&ss, SIGCHLD);
    /* This is checked for via sigwaitinfo/sigtimedwait */
    sigaddset(&ss, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &ss, NULL) != 0) {
        PLOG_F("sigprocmask(SIG_SETMASK)");
    }

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
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGUSR1) failed");
    }
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGCHLD) failed");
    }
}

static void setupSignalsMainThread(void) {
    /* Unblock signals which should be handled by the main thread */
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGQUIT);
    sigaddset(&ss, SIGALRM);
    if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(SIG_UNBLOCK)");
    }
}

static void printSummary(honggfuzz_t* hfuzz) {
    uint64_t exec_per_sec = 0;
    uint64_t elapsed_sec = time(NULL) - hfuzz->timing.timeStart;
    if (elapsed_sec) {
        exec_per_sec = hfuzz->cnts.mutationsCnt / elapsed_sec;
    }
    LOG_I("Summary iterations:%zu time:%" PRIu64 " speed:%" PRIu64, hfuzz->cnts.mutationsCnt,
        elapsed_sec, exec_per_sec);
}

static void pingThreads(honggfuzz_t* hfuzz) {
    for (size_t i = 0; i < hfuzz->threads.threadsMax; i++) {
        if (pthread_kill(hfuzz->threads.threads[i], SIGUSR1) != 0 && errno != EINTR) {
            PLOG_W("pthread_kill(thread=%zu, SIGUSR1)", i);
        }
    }
}

static void* signalThread(void* arg) {
    honggfuzz_t* hfuzz = (honggfuzz_t*)arg;

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGCHLD);
    if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("Couldn't unblock SIGCHLD in the signal thread");
    }

    for (;;) {
        int sig;
        if (sigwait(&ss, &sig) != 0 && errno != EINTR) {
            PLOG_F("sigwait(SIGCHLD)");
        }
        if (fuzz_isTerminating()) {
            break;
        }

        if (sig == SIGCHLD) {
            pingThreads(hfuzz);
        }
    }

    return NULL;
}

int main(int argc, char** argv) {
    /*
     * Work around CygWin/MinGW
     */
    char** myargs = (char**)util_Malloc(sizeof(char*) * (argc + 1));
    defer {
        free(myargs);
    };

    int i;
    for (i = 0U; i < argc; i++) {
        myargs[i] = argv[i];
    }
    myargs[i] = NULL;

    if (cmdlineParse(argc, myargs, &hfuzz) == false) {
        LOG_F("Parsing of the cmd-line arguments failed");
    }

    if (hfuzz.display.useScreen) {
        display_init();
    }

    if (hfuzz.socketFuzzer.enabled) {
        LOG_I("No input file corpus loaded, the external socket_fuzzer is responsible for "
              "creating the fuzz data");
        setupSocketFuzzer(&hfuzz);
    } else if (!input_init(&hfuzz)) {
        LOG_F("Couldn't load input corpus");
        exit(EXIT_FAILURE);
    }

    if (hfuzz.mutate.dictionaryFile && (input_parseDictionary(&hfuzz) == false)) {
        LOG_F("Couldn't parse dictionary file ('%s')", hfuzz.mutate.dictionaryFile);
    }

    if (hfuzz.feedback.blacklistFile && (input_parseBlacklist(&hfuzz) == false)) {
        LOG_F("Couldn't parse stackhash blacklist file ('%s')", hfuzz.feedback.blacklistFile);
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

    if (hfuzz.feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        if (!(hfuzz.feedback.feedbackMap = files_mapSharedMem(
                  sizeof(feedback_t), &hfuzz.feedback.bbFd, "hfuzz-feedback", hfuzz.io.workDir))) {
            LOG_F("files_mapSharedMem(sz=%zu, dir='%s') failed", sizeof(feedback_t),
                hfuzz.io.workDir);
        }
    }

    setupRLimits();
    setupSignalsPreThreads();
    fuzz_threadsStart(&hfuzz);

    pthread_t sigthread;
    if (!subproc_runThread(&hfuzz, &sigthread, signalThread, /* joinable= */ false)) {
        LOG_F("Couldn't start the signal thread");
    }

    setupSignalsMainThread();
    setupMainThreadTimer();

    for (;;) {
        if (hfuzz.display.useScreen) {
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
            break;
        }
        pingThreads(&hfuzz);
        pause();
    }

    fuzz_setTerminating();

    for (;;) {
        if (ATOMIC_GET(hfuzz.threads.threadsFinished) >= hfuzz.threads.threadsMax) {
            break;
        }
        pingThreads(&hfuzz);
        util_sleepForMSec(50); /* 50ms */
    }

    /* Clean-up global buffers */
    if (hfuzz.feedback.blacklist) {
        free(hfuzz.feedback.blacklist);
    }
#if defined(_HF_ARCH_LINUX)
    if (hfuzz.linux.symsBl) {
        free(hfuzz.linux.symsBl);
    }
    if (hfuzz.linux.symsWl) {
        free(hfuzz.linux.symsWl);
    }
#elif defined(_HF_ARCH_NETBSD)
    if (hfuzz.netbsd.symsBl) {
        free(hfuzz.netbsd.symsBl);
    }
    if (hfuzz.netbsd.symsWl) {
        free(hfuzz.netbsd.symsWl);
    }
#endif
    if (hfuzz.socketFuzzer.enabled) {
        cleanupSocketFuzzer();
    }

    printSummary(&hfuzz);

    return EXIT_SUCCESS;
}
