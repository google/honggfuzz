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

#include "../common.h"
#include "../arch.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <setjmp.h>
#include <sys/cdefs.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "../files.h"
#include "../log.h"
#include "../sancov.h"
#include "../subproc.h"
#include "../util.h"
#include "perf.h"
#include "ptrace_utils.h"

/* Common sanitizer flags */
#if _HF_MONITOR_SIGABRT
#define ABORT_FLAG        "abort_on_error=1"
#else
#define ABORT_FLAG        "abort_on_error=0"
#endif

/* Size of remote pid cmdline char buffer */
#define _HF_PROC_CMDLINE_SZ 8192

static inline bool arch_shouldAttach(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->persistent && fuzzer->linux.attachedPid == fuzzer->pid) {
        return false;
    }
    if (hfuzz->linux.pid > 0 && fuzzer->linux.attachedPid == hfuzz->linux.pid) {
        return false;
    }
    return true;
}

static uint8_t arch_clone_stack[PTHREAD_STACK_MIN * 2];

static __thread jmp_buf env;
static int arch_cloneFunc(void *arg UNUSED)
{
    longjmp(env, 1);
    return 0;
}

/* Avoid problem with caching of PID/TID in glibc */
static pid_t arch_clone(uintptr_t flags)
{
    if (flags & CLONE_VM) {
        LOG_E("Cannot use clone(flags & CLONE_VM)");
        return -1;
    }

    if (setjmp(env) == 0) {
        void *stack_mid = &arch_clone_stack[sizeof(arch_clone_stack) / 2];
        /* Parent */
        return clone(arch_cloneFunc, stack_mid, flags, NULL, NULL, NULL);
    }
    /* Child */
    return 0;
}

pid_t arch_fork(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer UNUSED)
{
    return arch_clone(CLONE_UNTRACED | SIGCHLD);
}

bool arch_launchChild(honggfuzz_t * hfuzz, char *fileName)
{
    /*
     * Kill the children when fuzzer dies (e.g. due to Ctrl+C)
     */
    if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) == -1) {
        PLOG_E("prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
        return false;
    }

    /*
     * Kill a process which corrupts its own heap (with ABRT)
     */
    if (setenv("MALLOC_CHECK_", "7", 0) == -1) {
        PLOG_E("setenv(MALLOC_CHECK_=7) failed");
        return false;
    }

    /*
     * Disable ASLR
     */
    if (hfuzz->linux.disableRandomization && personality(ADDR_NO_RANDOMIZE) == -1) {
        PLOG_E("personality(ADDR_NO_RANDOMIZE) failed");
        return false;
    }
#define ARGS_MAX 512
    char *args[ARGS_MAX + 2];
    char argData[PATH_MAX] = { 0 };
    int x = 0;

    for (x = 0; x < ARGS_MAX && hfuzz->cmdline[x]; x++) {
        if (!hfuzz->fuzzStdin && !hfuzz->persistent
            && strcmp(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER) == 0) {
            args[x] = (char *)fileName;
        } else if (!hfuzz->fuzzStdin && !hfuzz->persistent
                   && strstr(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER)) {
            const char *off = strstr(hfuzz->cmdline[x], _HF_FILE_PLACEHOLDER);
            snprintf(argData, PATH_MAX, "%.*s%s", (int)(off - hfuzz->cmdline[x]),
                     hfuzz->cmdline[x], fileName);
            args[x] = argData;
        } else {
            args[x] = hfuzz->cmdline[x];
        }
    }

    args[x++] = NULL;

    LOG_D("Launching '%s' on file '%s'", args[0], hfuzz->persistent ? "PERSISTENT_MODE" : fileName);

    /*
     * Wait for the ptrace to attach
     */
    syscall(__NR_tkill, syscall(__NR_gettid), (uintptr_t) SIGSTOP);

    execvp(args[0], args);

    PLOG_E("execvp('%s')", args[0]);

    return false;
}

static void arch_sigFunc(int signo, siginfo_t * si UNUSED, void *dummy UNUSED)
{
    if (signo != SIGNAL_WAKE) {
        LOG_E("Signal != SIGNAL_WAKE (%d)", signo);
    }
}

static bool arch_setTimer(timer_t * timerid)
{
    /*
     * Kick in every 200ms, starting with the next second
     */
    const struct itimerspec ts = {
        .it_value = {.tv_sec = 0,.tv_nsec = 250000000,},
        .it_interval = {.tv_sec = 0,.tv_nsec = 250000000,},
    };
    if (timer_settime(*timerid, 0, &ts, NULL) == -1) {
        PLOG_E("timer_settime(arm) failed");
        timer_delete(*timerid);
        return false;
    }

    return true;
}

void arch_prepareChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    pid_t ptracePid = (hfuzz->linux.pid > 0) ? hfuzz->linux.pid : fuzzer->pid;
    pid_t childPid = fuzzer->pid;

    if (hfuzz->persistent) {
        struct f_owner_ex fown = {.type = F_OWNER_TID,.pid = syscall(__NR_gettid), };
        if (fcntl(fuzzer->persistentSock, F_SETOWN_EX, &fown)) {
            PLOG_F("fcntl(%d, F_SETOWN_EX)", fuzzer->persistentSock);
        }
        if (fcntl(fuzzer->persistentSock, F_SETSIG, SIGNAL_WAKE) == -1) {
            PLOG_F("fcntl(%d, F_SETSIG, SIGNAL_WAKE)", fuzzer->persistentSock);
        }
        if (fcntl(fuzzer->persistentSock, F_SETFL, O_ASYNC) == -1) {
            PLOG_F("fcntl(%d, F_SETFL, O_ASYNC)", fuzzer->persistentSock);
        }
        int sndbuf = (1024 * 1024 * 2); /* 2MiB */
        if (setsockopt(fuzzer->persistentSock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) ==
            -1) {
            LOG_W("Couldn't set FD send buffer to '%d' bytes", sndbuf);
        }
    }

    if (arch_shouldAttach(hfuzz, fuzzer) == true) {
        if (arch_ptraceAttach(hfuzz, ptracePid) == false) {
            LOG_F("arch_ptraceAttach(pid=%d) failed", ptracePid);
        }
        fuzzer->linux.attachedPid = ptracePid;
    }

    /* A long-lived process could have already exited, and we wouldn't know */
    if (childPid != ptracePid && kill(ptracePid, 0) == -1) {
        if (hfuzz->linux.pidFile) {
            /* If pid from file, check again for cases of auto-restart daemons that update it */
            /*
             * TODO: Investigate if we need to delay here, so that target process has
             * enough time to restart. Tricky to answer since is target dependent.
             */
            if (files_readPidFromFile(hfuzz->linux.pidFile, &hfuzz->linux.pid) == false) {
                LOG_F("Failed to read new PID from file - abort");
            } else {
                if (kill(hfuzz->linux.pid, 0) == -1) {
                    PLOG_F("Liveness of PID %d read from file questioned - abort",
                           hfuzz->linux.pid);
                } else {
                    LOG_D("Monitor PID has been updated (pid=%d)", hfuzz->linux.pid);
                    ptracePid = hfuzz->linux.pid;
                }
            }
        }
    }

    if (arch_perfEnable(ptracePid, hfuzz, fuzzer) == false) {
        LOG_F("Couldn't enable perf counters for pid %d", ptracePid);
    }
    if (childPid != ptracePid) {
        if (arch_ptraceWaitForPidStop(childPid) == false) {
            LOG_F("PID: %d not in a stopped state", childPid);
        }
        if (kill(childPid, SIGCONT) == -1) {
            PLOG_F("Restarting PID: %d failed", childPid);
        }
    }
}

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    pid_t ptracePid = (hfuzz->linux.pid > 0) ? hfuzz->linux.pid : fuzzer->pid;
    pid_t childPid = fuzzer->pid;

    for (;;) {
        if (subproc_persistentModeRoundDone(hfuzz, fuzzer)) {
            break;
        }

        int status;
        pid_t pid = wait4(-1, &status, __WALL | __WNOTHREAD, NULL);
        if (pid == -1 && errno == EINTR) {
            subproc_checkTimeLimit(hfuzz, fuzzer);
            continue;
        }
        if (pid == -1 && errno == ECHILD) {
            LOG_D("No more processes to track");
            break;
        }
        if (pid == -1) {
            PLOG_F("wait4() failed");
        }

        char statusStr[4096];
        LOG_D("PID '%d' returned with status: %s", pid,
              subproc_StatusToStr(status, statusStr, sizeof(statusStr)));

        if (hfuzz->persistent && pid == fuzzer->persistentPid
            && (WIFEXITED(status) || WIFSIGNALED(status))) {
            arch_ptraceAnalyze(hfuzz, status, pid, fuzzer);
            fuzzer->persistentPid = 0;
            LOG_W("Persistent mode: PID %d exited with status: %s", pid,
                  subproc_StatusToStr(status, statusStr, sizeof(statusStr)));
            break;
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

#if !_HF_MONITOR_SIGABRT
    /*
     * There might be cases where ASan instrumented targets crash while generating
     * reports for detected errors (inside __asan_report_error() proc). Under such
     * scenarios target fails to exit or SIGABRT (AsanDie() proc) as defined in
     * ASAN_OPTIONS flags, leaving garbage logs. An attempt is made to parse such
     * logs for cases where enough data are written to identify potentially missed
     * crashes. If ASan internal error results into a SIGSEGV being raised, it
     * will get caught from ptrace API, handling the discovered ASan internal crash.
     */
    char crashReport[PATH_MAX] = { 0 };
    snprintf(crashReport, sizeof(crashReport), "%s/%s.%d", hfuzz->workDir, kLOGPREFIX, ptracePid);
    if (files_exists(crashReport)) {
        LOG_W("Un-handled ASan report due to compiler-rt internal error - retry with '%s' (%s)",
              crashReport, fuzzer->fileName);

        /* Manually set the exitcode to ASan to trigger report parsing */
        arch_ptraceExitAnalyze(hfuzz, ptracePid, fuzzer, HF_ASAN_EXIT_CODE);
    }
#endif

    arch_perfAnalyze(hfuzz, fuzzer);
    sancov_Analyze(hfuzz, fuzzer);
}

bool arch_archInit(honggfuzz_t * hfuzz)
{
    /* Use it to make %'d work */
    setlocale(LC_NUMERIC, "");

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        unsigned long major = 0, minor = 0;
        char *p = NULL;

        /*
         * Check that Linux kernel is compatible
         *
         * Compatibility list:
         *  1) Perf exclude_callchain_kernel requires kernel >= 3.7
         *     TODO: Runtime logic to disable it for unsupported kernels
         *           if it doesn't affect perf counters processing
         *  2) If 'PERF_TYPE_HARDWARE' is not supported by kernel, ENOENT
         *     is returned from perf_event_open(). Unfortunately, no reliable
         *     way to detect it here. libperf exports some list functions,
         *     although small guarantees it's installed. Maybe a more targeted
         *     message at perf_event_open() error handling will help.
         *  3) Intel's PT and new Intel BTS format require kernel >= 4.1
         */
        unsigned long checkMajor = 3, checkMinor = 7;
        if ((hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK) ||
            (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) ||
            (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK)) {
            checkMajor = 4;
            checkMinor = 1;
        }

        struct utsname uts;
        if (uname(&uts) == -1) {
            PLOG_F("uname() failed");
            return false;
        }

        p = uts.release;
        major = strtoul(p, &p, 10);
        if (*p++ != '.') {
            LOG_F("Unsupported kernel version (%s)", uts.release);
            return false;
        }

        minor = strtoul(p, &p, 10);
        if ((major < checkMajor) || ((major == checkMajor) && (minor < checkMinor))) {
            LOG_E("Kernel version '%s' not supporting chosen perf method", uts.release);
            return false;
        }

        if (arch_perfInit(hfuzz) == false) {
            return false;
        }
    }
#if defined(__ANDROID__) && defined(__arm__)
    /*
     * For ARM kernels running Android API <= 21, if fuzzing target links to
     * libcrypto (OpenSSL), OPENSSL_cpuid_setup initialization is triggering a
     * SIGILL/ILLOPC at armv7_tick() due to  "mrrc p15, #1, r0, r1, c14)" instruction.
     * Setups using BoringSSL (API >= 22) are not affected.
     */
    if (setenv("OPENSSL_armcap", OPENSSL_ARMCAP_ABI, 1) == -1) {
        PLOG_E("setenv(OPENSSL_armcap) failed");
        return false;
    }
#endif

    /* If read PID from file enable - read current value */
    if (hfuzz->linux.pidFile) {
        if (files_readPidFromFile(hfuzz->linux.pidFile, &hfuzz->linux.pid) == false) {
            LOG_E("Failed to read PID from file");
            return false;
        }
    }

    /* If remote pid, resolve command using procfs */
    if (hfuzz->linux.pid > 0) {
        char procCmd[PATH_MAX] = { 0 };
        snprintf(procCmd, sizeof(procCmd), "/proc/%d/cmdline", hfuzz->linux.pid);

        hfuzz->linux.pidCmd = malloc(_HF_PROC_CMDLINE_SZ * sizeof(char));
        if (!hfuzz->linux.pidCmd) {
            PLOG_E("malloc(%zu) failed", (size_t) _HF_PROC_CMDLINE_SZ);
            return false;
        }

        ssize_t sz = files_readFileToBufMax(procCmd, (uint8_t *) hfuzz->linux.pidCmd,
                                            _HF_PROC_CMDLINE_SZ - 1);
        if (sz < 1) {
            LOG_E("Couldn't read '%s'", procCmd);
            free(hfuzz->linux.pidCmd);
            return false;
        }

        /* Make human readable */
        for (size_t i = 0; i < ((size_t) sz - 1); i++) {
            if (hfuzz->linux.pidCmd[i] == '\0') {
                hfuzz->linux.pidCmd[i] = ' ';
            }
        }
        hfuzz->linux.pidCmd[sz] = '\0';
    }

    /*
     * If sanitizer fuzzing enabled increase number of major frames, since top 7-9 frames
     * will be occupied with sanitizer symbols if 'abort_on_error' flag is set
     */
#if _HF_MONITOR_SIGABRT
    hfuzz->linux.numMajorFrames = 14;
#endif

    return true;
}

bool arch_archThreadInit(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    struct sigevent sevp = {
        .sigev_value.sival_ptr = &fuzzer->timerId,
        .sigev_signo = SIGNAL_WAKE,
        .sigev_notify = SIGEV_THREAD_ID | SIGEV_SIGNAL,
        ._sigev_un._tid = syscall(__NR_gettid),
    };
    if (timer_create(CLOCK_REALTIME, &sevp, &fuzzer->timerId) == -1) {
        PLOG_E("timer_create(CLOCK_REALTIME) failed");
        return false;
    }

    sigset_t smask;
    sigemptyset(&smask);
    struct sigaction sa = {
        .sa_sigaction = arch_sigFunc,
        .sa_mask = smask,
        .sa_flags = SA_SIGINFO,
        .sa_restorer = NULL,
    };

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGNAL_WAKE);
    if (sigprocmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(%d, SIG_UNBLOCK)", SIGNAL_WAKE);
    }
    if (sigaction(SIGNAL_WAKE, &sa, NULL) == -1) {
        PLOG_E("sigaction(SIGNAL_WAKE (%d)) failed", SIGNAL_WAKE);
        return false;
    }

    if (arch_setTimer(&(fuzzer->timerId)) == false) {
        LOG_F("Couldn't set timer");
    }

    return true;
}
