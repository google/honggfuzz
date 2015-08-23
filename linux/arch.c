/*
 *
 * honggfuzz - architecture dependent code (LINUX)
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
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
#include "arch.h"

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/cdefs.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "linux/perf.h"
#include "linux/ptrace_utils.h"
#include "log.h"
#include "util.h"

bool arch_launchChild(honggfuzz_t * hfuzz, char *fileName)
{
    /*
     * Kill a process which corrupts its own heap (with ABRT)
     */
    if (setenv("MALLOC_CHECK_", "3", 1) == -1) {
        LOGMSG_P(l_ERROR, "setenv(MALLOC_CHECK_=3) failed");
        return false;
    }

    /*
     * Tell asan to ignore SEGVs
     */
    if (setenv
        ("ASAN_OPTIONS",
         "allow_user_segv_handler=1:handle_segv=0:abort_on_error=1:allocator_may_return_null=1",
         1) == -1) {
        LOGMSG_P(l_ERROR, "setenv(ASAN_OPTIONS) failed");
        return false;
    }

    /*
     * Kill the children when fuzzer dies (e.g. due to Ctrl+C)
     */
    if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) == -1) {
        LOGMSG_P(l_ERROR, "prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
        return false;
    }

    /*
     * Disable ASLR
     */
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
        LOGMSG_P(l_ERROR, "personality(ADDR_NO_RANDOMIZE) failed");
        return false;
    }
#define ARGS_MAX 512
    char *args[ARGS_MAX + 2];
    char argData[PATH_MAX] = { 0 };
    int x;

    for (x = 0; x < ARGS_MAX && hfuzz->cmdline[x]; x++) {
        if (!hfuzz->fuzzStdin && strcmp(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER) == 0) {
            args[x] = fileName;
        } else if (!hfuzz->fuzzStdin && strstr(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER)) {
            const char *off = strstr(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER);
            snprintf(argData, PATH_MAX, "%.*s%s", (int)(off - hfuzz->cmdline[x]), hfuzz->cmdline[x],
                     fileName);
            args[x] = argData;
        } else {
            args[x] = hfuzz->cmdline[x];
        }
    }

    args[x++] = NULL;

    LOGMSG(l_DEBUG, "Launching '%s' on file '%s'", args[0], fileName);

    /*
     * Set timeout (prof), real timeout (2*prof), and rlimit_cpu (2*prof)
     */
    if (hfuzz->tmOut) {
        /* 
         * Set the CPU rlimit to twice the value of the time-out
         */
        struct rlimit rl = {
            .rlim_cur = hfuzz->tmOut * 2,
            .rlim_max = hfuzz->tmOut * 2,
        };
        if (setrlimit(RLIMIT_CPU, &rl) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't enforce the RLIMIT_CPU resource limit");
            return false;
        }
    }

    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (hfuzz->asLimit) {
        struct rlimit rl = {
            .rlim_cur = hfuzz->asLimit * 1024UL * 1024UL,
            .rlim_max = hfuzz->asLimit * 1024UL * 1024UL,
        };
        if (setrlimit(RLIMIT_AS, &rl) == -1) {
            LOGMSG_P(l_DEBUG, "Couldn't encforce the RLIMIT_AS resource limit, ignoring");
        }
    }

    for (size_t i = 0; i < ARRAYSIZE(hfuzz->envs) && hfuzz->envs[i]; i++) {
        putenv(hfuzz->envs[i]);
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
    /*
     * Wait for the ptrace to attach
     */
    syscall(__NR_tkill, syscall(__NR_gettid), SIGSTOP);
    execvp(args[0], args);

    util_recoverStdio();
    LOGMSG(l_FATAL, "Failed to create new '%s' process", args[0]);
    return false;
}

static void arch_sigFunc(int signo, siginfo_t * si, void *dummy)
{
    if (signo != SIGALRM) {
        LOGMSG(l_ERROR, "Signal != SIGALRM (%d)", signo);
    }
    return;
    if (si == NULL) {
        return;
    }
    if (dummy == NULL) {
        return;
    }
}

static void arch_removeTimer(timer_t * timerid)
{
    timer_delete(*timerid);
}

static bool arch_setTimer(timer_t * timerid)
{
    struct sigevent sevp = {
        .sigev_value.sival_ptr = timerid,
        .sigev_signo = SIGALRM,
        .sigev_notify = SIGEV_THREAD_ID | SIGEV_SIGNAL,
        ._sigev_un._tid = syscall(__NR_gettid),
    };
    if (timer_create(CLOCK_REALTIME, &sevp, timerid) == -1) {
        LOGMSG_P(l_ERROR, "timer_create(CLOCK_REALTIME) failed");
        return false;
    }
    /* 
     * Kick in every 200ms, starting with the next second
     */
    const struct itimerspec ts = {
        .it_value = {.tv_sec = 1,.tv_nsec = 0},
        .it_interval = {.tv_sec = 0,.tv_nsec = 200000000,},
    };
    if (timer_settime(*timerid, 0, &ts, NULL) == -1) {
        LOGMSG_P(l_ERROR, "timer_settime() failed");
        timer_delete(*timerid);
        return false;
    }
    sigset_t smask;
    sigemptyset(&smask);
    struct sigaction sa = {
        .sa_handler = NULL,
        .sa_sigaction = arch_sigFunc,
        .sa_mask = smask,
        .sa_flags = SA_SIGINFO,
        .sa_restorer = NULL,
    };
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        LOGMSG_P(l_ERROR, "sigaciton(SIGALRM) failed");
        return false;
    }

    return true;
}

static void arch_checkTimeLimit(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - fuzzer->timeStartedMillis;
    if (diffMillis > (hfuzz->tmOut * 1000)) {
        LOGMSG(l_WARN, "PID %d took too much time (limit %ld s). Sending SIGKILL",
               fuzzer->pid, hfuzz->tmOut);
        kill(fuzzer->pid, SIGKILL);
    }
}

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    pid_t ptracePid = (hfuzz->pid > 0) ? hfuzz->pid : fuzzer->pid;
    pid_t childPid = fuzzer->pid;

    timer_t timerid;
    if (arch_setTimer(&timerid) == false) {
        LOGMSG(l_FATAL, "Couldn't set timer");
    }

    int perfFd[3];

    for (;;) {
        int status;
        pid_t pid =
            TEMP_FAILURE_RETRY(wait4(childPid, &status, __WNOTHREAD | __WALL | WUNTRACED, NULL));
        if (pid == -1 && errno == EINTR) {
            continue;
        }
        if (pid != childPid) {
            LOGMSG_P(l_FATAL, "wait4()=%d =! %d", pid, childPid);
        }
        if (WIFSTOPPED(status)) {
            break;
        }
        LOGMSG_P(l_FATAL, "PID '%d' is not in a stopped state", pid);
    }
    if (arch_ptraceAttach(ptracePid) == false) {
        LOGMSG(l_FATAL, "Couldn't attach to pid %d", ptracePid);
    }
    if (arch_perfEnable(ptracePid, hfuzz, perfFd) == false) {
        LOGMSG(l_FATAL, "Couldn't enable perf counters for pid %d", ptracePid);
    }
    kill(childPid, SIGCONT);

    for (;;) {
        int status;

        // wait3 syscall is no longer present in Android
        // wrap syscalls under TEMP_FAILURE_RETRY macro to avoid "Interrupted system call"
#if !defined(__ANDROID__)
        pid_t pid = TEMP_FAILURE_RETRY(wait3(&status, __WNOTHREAD | __WALL, NULL));
#else
        pid_t pid = TEMP_FAILURE_RETRY(wait4(-1, &status, __WNOTHREAD | __WALL, NULL));
#endif

        LOGMSG_P(l_DEBUG, "PID '%d' returned with status '%d'", pid, status);

        if (pid == -1 && errno == EINTR) {
            arch_checkTimeLimit(hfuzz, fuzzer);
            continue;
        }
        if (pid == -1 && errno == ECHILD) {
            LOGMSG(l_DEBUG, "No more processes to track");
            break;
        }
        if (pid == -1) {
#if !defined(__ANDROID__)
            LOGMSG_P(l_FATAL, "wait3() failed");
#else
            LOGMSG_P(l_FATAL, "wait4() failed");
#endif
        }

        uint64_t tmp;
        if ((tmp = arch_ptraceGetCustomPerf(hfuzz, ptracePid)) != 0ULL) {
            fuzzer->branchCnt[3] = tmp;
        }

        if (ptracePid == childPid) {
            arch_ptraceAnalyze(hfuzz, status, pid, fuzzer);
            continue;
        }
        if (pid == childPid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            break;
        }
        if (pid == childPid) {
            continue;
        }

        arch_ptraceAnalyze(hfuzz, status, pid, fuzzer);
    }
    arch_removeTimer(&timerid);
    arch_perfAnalyze(hfuzz, fuzzer, perfFd);
    return;
}

bool arch_archInit(honggfuzz_t * hfuzz)
{
    return true;
    if (hfuzz) {
        return true;
    }
}
