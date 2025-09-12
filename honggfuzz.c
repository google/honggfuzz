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
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if defined(__FreeBSD__)
#include <sys/procctl.h>
#endif

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

static int  sigReceived = 0;
static bool clearWin    = false;

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
    if (sig == SIGWINCH) {
        ATOMIC_SET(clearWin, true);
        return;
    }

    /* It's handled in the signal thread */
    if (sig == SIGCHLD) {
        return;
    }

    if (ATOMIC_GET(sigReceived) != 0) {
        exitWithMsg("Repeated termination signal caught\n", EXIT_FAILURE);
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
    rlim.rlim_cur = HF_MIN(1024, rlim.rlim_max);    // we don't need more
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        PLOG_E("Couldn't setrlimit(RLIMIT_NOFILE, cur=%zu/max=%zu)", (size_t)rlim.rlim_cur,
            (size_t)rlim.rlim_max);
    }
}

static void setupMainThreadTimer(void) {
    const struct itimerval it = {
        .it_value =
            {
                .tv_sec  = 1,
                .tv_usec = 0,
            },
        .it_interval =
            {
                .tv_sec  = 0,
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
    sigaddset(&ss, SIGWINCH);
    if (sigprocmask(SIG_SETMASK, &ss, NULL) != 0) {
        PLOG_F("sigprocmask(SIG_SETMASK)");
    }

    struct sigaction sa = {
        .sa_handler = sigHandler,
        .sa_flags   = 0,
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
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGCHLD) failed");
    }
    if (sigaction(SIGWINCH, &sa, NULL) == -1) {
        PLOG_F("sigaction(SIGWINCH) failed");
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
    sigaddset(&ss, SIGWINCH);
    if (pthread_sigmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(SIG_UNBLOCK)");
    }
}

static void printSummary(honggfuzz_t* hfuzz) {
    uint64_t exec_per_sec = 0;
    uint64_t elapsed_sec  = time(NULL) - hfuzz->timing.timeStart;
    if (elapsed_sec) {
        exec_per_sec = hfuzz->cnts.mutationsCnt / elapsed_sec;
    }
    uint64_t guardNb = ATOMIC_GET(hfuzz->feedback.covFeedbackMap->guardNb);
    uint64_t branch_percent_cov =
        guardNb ? ((100 * ATOMIC_GET(hfuzz->feedback.hwCnts.softCntEdge)) / guardNb) : 0;
    struct rusage usage;
    if (getrusage(RUSAGE_CHILDREN, &usage)) {
        PLOG_W("getrusage  failed");
        usage.ru_maxrss = 0;    // 0 means something went wrong with rusage
    }
#ifdef _HF_ARCH_DARWIN
    usage.ru_maxrss >>= 20;
#else
    usage.ru_maxrss >>= 10;
#endif
    LOG_I("Summary iterations:%zu time:%" PRIu64 " speed:%" PRIu64 " "
          "crashes_count:%zu timeout_count:%zu new_units_added:%zu "
          "slowest_unit_ms:%" PRId64 " guard_nb:%" PRIu64 " branch_coverage_percent:%" PRIu64 " "
          "peak_rss_mb:%lu",
        hfuzz->cnts.mutationsCnt, elapsed_sec, exec_per_sec, hfuzz->cnts.crashesCnt,
        hfuzz->cnts.timeoutedCnt, hfuzz->io.newUnitsAdded,
        hfuzz->timing.timeOfLongestUnitUSecs / 1000U, hfuzz->feedback.covFeedbackMap->guardNb,
        branch_percent_cov, usage.ru_maxrss);
}

static void pingThreads(honggfuzz_t* hfuzz) {
    for (size_t i = 0; i < hfuzz->threads.threadsMax; i++) {
        if (pthread_kill(hfuzz->threads.threads[i], SIGCHLD) != 0 && errno != EINTR && errno != 0) {
            PLOG_W("pthread_kill(thread=%zu, SIGCHLD)", i);
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
        int sig = 0;
        errno   = 0;
        int ret = sigwait(&ss, &sig);
        if (ret == EINTR) {
            continue;
        }
        if (ret != 0 && errno == EINTR) {
            continue;
        }
        if (ret != 0) {
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

static uint8_t mainThreadLoop(honggfuzz_t* hfuzz) {
    setupSignalsMainThread();
    setupMainThreadTimer();

    uint64_t dynamicQueuePollTime = time(NULL);
    for (;;) {
        if (hfuzz->io.dynamicInputDir && time(NULL) - dynamicQueuePollTime > _HF_SYNC_TIME) {
            LOG_D("Loading files from the dynamic input queue...");
            input_enqueueDynamicInputs(hfuzz);
            dynamicQueuePollTime = time(NULL);
        }

        if (hfuzz->display.useScreen) {
            if (ATOMIC_XCHG(clearWin, false)) {
                display_clear();
            }
            display_display(hfuzz);
        }
        if (ATOMIC_GET(sigReceived) > 0) {
            LOG_I("Signal %d (%s) received, terminating", ATOMIC_GET(sigReceived),
                strsignal(ATOMIC_GET(sigReceived)));
            break;
        }
        if (ATOMIC_GET(hfuzz->threads.threadsFinished) >= hfuzz->threads.threadsMax) {
            break;
        }
        if (hfuzz->timing.runEndTime > 0 && (time(NULL) > hfuzz->timing.runEndTime)) {
            LOG_I("Maximum run time reached, terminating");
            break;
        }
        if (hfuzz->timing.exitOnTime > 0 &&
            time(NULL) - ATOMIC_GET(hfuzz->timing.lastCovUpdate) > hfuzz->timing.exitOnTime) {
            LOG_I("No new coverage was found for the last %" PRIu64 " seconds, terminating",
                (uint64_t)hfuzz->timing.exitOnTime);
            break;
        }
        pingThreads(hfuzz);
        pause();
    }

    fuzz_setTerminating();

    for (;;) {
        if (ATOMIC_GET(hfuzz->threads.threadsFinished) >= hfuzz->threads.threadsMax) {
            break;
        }
        pingThreads(hfuzz);
        util_sleepForMSec(50); /* 50ms */
    }
    if (hfuzz->cfg.exitUponCrash && ATOMIC_GET(hfuzz->cnts.crashesCnt) > 0) {
        return hfuzz->cfg.exitCodeUponCrash;
    } else {
        return EXIT_SUCCESS;
    }
}

static const char* strYesNo(bool yes) {
    return (yes ? "true" : "false");
}

static const char* getGitVersion() {
    static char version[] = "$Id$";
    if (strlen(version) == 47) {
        version[45] = '\0';
        return &version[5];
    }
    return "UNKNOWN";
}

int main(int argc, char** argv) {
    /*
     * Work around CygWin/MinGW
     */
    char** myargs = (char**)util_Calloc(sizeof(char*) * (argc + 1));
    defer {
        free(myargs);
    };

    int i;
    for (i = 0U; i < argc; i++) {
        myargs[i] = argv[i];
    }
    myargs[i] = NULL;

    if (!cmdlineParse(argc, myargs, &hfuzz)) {
        LOG_F("Parsing of the cmd-line arguments failed");
    }
    if (hfuzz.io.inputDir && access(hfuzz.io.inputDir, R_OK) == -1) {
        PLOG_F("Input directory '%s' is not readable", hfuzz.io.inputDir);
    }
    if (hfuzz.io.outputDir && access(hfuzz.io.outputDir, W_OK) == -1) {
        PLOG_F("Output directory '%s' is not writeable", hfuzz.io.outputDir);
    }
    if (hfuzz.cfg.minimize) {
        LOG_I("Minimization mode enabled. Setting number of threads to 1");
        hfuzz.threads.threadsMax = 1;
    }

    char tmstr[64];
    util_getLocalTime("%F.%H.%M.%S", tmstr, sizeof(tmstr), time(NULL));
    LOG_I("Start time:'%s' bin:'%s', input:'%s', output:'%s', persistent:%s, stdin:%s, "
          "mutation_rate:%u, timeout:%ld, max_runs:%zu, threads:%zu, minimize:%s, git_commit:%s",
        tmstr, hfuzz.exe.cmdline[0], hfuzz.io.inputDir,
        hfuzz.io.outputDir ? hfuzz.io.outputDir : hfuzz.io.inputDir, strYesNo(hfuzz.exe.persistent),
        strYesNo(hfuzz.exe.fuzzStdin), hfuzz.mutate.mutationsPerRun, (long)hfuzz.timing.tmOut,
        hfuzz.mutate.mutationsMax, hfuzz.threads.threadsMax, strYesNo(hfuzz.cfg.minimize),
        getGitVersion());

    sigemptyset(&hfuzz.exe.waitSigSet);
    sigaddset(&hfuzz.exe.waitSigSet, SIGIO);   /* Persistent socket data */
    sigaddset(&hfuzz.exe.waitSigSet, SIGCHLD); /* Ping from the signal thread */

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

    if (hfuzz.mutate.dictionaryFile && !input_parseDictionary(&hfuzz)) {
        LOG_F("Couldn't parse dictionary file ('%s')", hfuzz.mutate.dictionaryFile);
    }

    if (hfuzz.feedback.blocklistFile && !input_parseBlacklist(&hfuzz)) {
        LOG_F("Couldn't parse stackhash blocklist file ('%s')", hfuzz.feedback.blocklistFile);
    }
#define hfuzzl hfuzz.arch_linux
    if (hfuzzl.symsBlFile &&
        ((hfuzzl.symsBlCnt = files_parseSymbolFilter(hfuzzl.symsBlFile, &hfuzzl.symsBl)) == 0)) {
        LOG_F("Couldn't parse symbols blocklist file ('%s')", hfuzzl.symsBlFile);
    }

    if (hfuzzl.symsWlFile &&
        ((hfuzzl.symsWlCnt = files_parseSymbolFilter(hfuzzl.symsWlFile, &hfuzzl.symsWl)) == 0)) {
        LOG_F("Couldn't parse symbols allowlist file ('%s')", hfuzzl.symsWlFile);
    }

    if (!(hfuzz.feedback.covFeedbackMap =
                files_mapSharedMem(sizeof(feedback_t), &hfuzz.feedback.covFeedbackFd,
                    "hf-covfeedback", /* nocore= */ true, /* export= */ hfuzz.io.exportFeedback))) {
        LOG_F("files_mapSharedMem(name='hf-covfeddback', sz=%zu, dir='%s') failed",
            sizeof(feedback_t), hfuzz.io.workDir);
    }
    if (hfuzz.feedback.cmpFeedback) {
        if (!(hfuzz.feedback.cmpFeedbackMap = files_mapSharedMem(sizeof(cmpfeedback_t),
                  &hfuzz.feedback.cmpFeedbackFd, "hf-cmpfeedback", /* nocore= */ true,
                  /* export= */ hfuzz.io.exportFeedback))) {
            LOG_F("files_mapSharedMem(name='hf-cmpfeedback', sz=%zu, dir='%s') failed",
                sizeof(cmpfeedback_t), hfuzz.io.workDir);
        }
    }
    /* Stats file. */
    if (hfuzz.io.statsFileName) {
        hfuzz.io.statsFileFd =
            TEMP_FAILURE_RETRY(open(hfuzz.io.statsFileName, O_CREAT | O_RDWR | O_TRUNC, 0640));

        if (hfuzz.io.statsFileFd == -1) {
            PLOG_F("Couldn't open statsfile open('%s')", hfuzz.io.statsFileName);
        } else {
            dprintf(hfuzz.io.statsFileFd,
                "# unix_time, last_cov_update, total_exec, exec_per_sec, "
                "crashes, unique_crashes, hangs, edge_cov, block_cov, corpus_count\n");
        }
    }

    setupRLimits();
    setupSignalsPreThreads();
    fuzz_threadsStart(&hfuzz);

    pthread_t sigthread;
    if (!subproc_runThread(&hfuzz, &sigthread, signalThread, /* joinable= */ false)) {
        LOG_F("Couldn't start the signal thread");
    }

    uint8_t exitcode = mainThreadLoop(&hfuzz);

    /* Clean-up global buffers */
    if (hfuzz.feedback.blocklist) {
        free(hfuzz.feedback.blocklist);
    }
#if defined(_HF_ARCH_LINUX)
    if (hfuzz.arch_linux.symsBl) {
        free(hfuzz.arch_linux.symsBl);
    }
    if (hfuzz.arch_linux.symsWl) {
        free(hfuzz.arch_linux.symsWl);
    }
#elif defined(_HF_ARCH_NETBSD)
    if (hfuzz.arch_netbsd.symsBl) {
        free(hfuzz.arch_netbsd.symsBl);
    }
    if (hfuzz.arch_netbsd.symsWl) {
        free(hfuzz.arch_netbsd.symsWl);
    }
#endif
    if (hfuzz.socketFuzzer.enabled) {
        cleanupSocketFuzzer();
    }
    /* Stats file. */
    if (hfuzz.io.statsFileName) {
        close(hfuzz.io.statsFileFd);
    }

    printSummary(&hfuzz);

    return exitcode;
}
