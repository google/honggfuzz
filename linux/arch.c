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
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "files.h"
#include "linux/perf.h"
#include "linux/ptrace_utils.h"
#include "log.h"
#include "sancov.h"
#include "subproc.h"
#include "util.h"

/* Common sanitizer flags */
#if _HF_MONITOR_SIGABRT
#define ABORT_FLAG        "abort_on_error=1"
#else
#define ABORT_FLAG        "abort_on_error=0"
#endif

#define SIGNAL_TIMER (SIGRTMIN + 1)

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

pid_t arch_fork(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int sv[2];
    if (hfuzz->persistent == true) {
        close(fuzzer->linux.persistentSock);
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            LOG_F("socketpair(AF_UNIX, SOCK_STREAM)");
            return -1;
        }
    }

    /*
     * We need to wait for the child to finish with wait() in case we're fuzzing
     * an external process
     */
    uintptr_t clone_flags = CLONE_UNTRACED;
    if (hfuzz->linux.pid) {
        clone_flags = SIGCHLD;
    }

    pid_t pid = syscall(__NR_clone, (uintptr_t) clone_flags, NULL, NULL, NULL, (uintptr_t) 0);

    if (hfuzz->persistent == true) {
        if (pid == -1) {
            close(sv[0]);
            close(sv[1]);
        }
        if (pid == 0) {
            if (dup2(sv[1], 1023) == -1) {
                LOG_F("dup2('%d', '%d')", sv[1], 1023);
            }
            close(sv[0]);
            close(sv[1]);
        }
        if (pid > 0) {
            fuzzer->linux.persistentSock = sv[0];
            close(sv[1]);
        }
    }
    return pid;
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
    if (setenv("MALLOC_CHECK_", "3", 1) == -1) {
        PLOG_E("setenv(MALLOC_CHECK_=3) failed");
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

#ifdef __NR_execveat
    syscall(__NR_execveat, hfuzz->exeFd, "", args, environ, AT_EMPTY_PATH);
#endif
    execvp(args[0], args);

    PLOG_E("execvp('%s')", args[0]);

    return false;
}

static void arch_sigFunc(int signo, siginfo_t * si UNUSED, void *dummy UNUSED)
{
    if (signo != SIGNAL_TIMER) {
        LOG_E("Signal != SIGNAL_TIMER (%d)", signo);
    }
}

static void arch_removeTimer(timer_t * timerid)
{
    const struct itimerspec ts = {
        .it_value = {.tv_sec = 0,.tv_nsec = 0},
        .it_interval = {.tv_sec = 0,.tv_nsec = 0,},
    };
    if (timer_settime(*timerid, 0, &ts, NULL) == -1) {
        PLOG_E("timer_settime(disarm)");
    }
}

static bool arch_setTimer(timer_t * timerid)
{
    /*
     * Kick in every 200ms, starting with the next second
     */
    const struct itimerspec ts = {
        .it_value = {.tv_sec = 1,.tv_nsec = 0},
        .it_interval = {.tv_sec = 0,.tv_nsec = 200000000,},
    };
    if (timer_settime(*timerid, 0, &ts, NULL) == -1) {
        PLOG_E("timer_settime(arm) failed");
        timer_delete(*timerid);
        return false;
    }

    return true;
}

static void arch_checkTimeLimit(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - fuzzer->timeStartedMillis;
    if (diffMillis > (hfuzz->tmOut * 1000)) {
        LOG_W("PID %d took too much time (limit %ld s). Sending SIGKILL",
              fuzzer->pid, hfuzz->tmOut);
        kill(fuzzer->pid, SIGKILL);
        ATOMIC_POST_INC(hfuzz->timeoutedCnt);
    }
}

static bool arch_persistentModeRoundDone(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->persistent == false) {
        return false;
    }
    char z;
    if (recv(fuzzer->linux.persistentSock, &z, sizeof(z), MSG_DONTWAIT) == sizeof(z)) {
        LOG_D("Persistent mode round finished");
        return true;
    }
    return false;
}

static bool arch_persistentSendFile(fuzzer_t * fuzzer)
{
    uint32_t len = (uint64_t) fuzzer->dynamicFileSz;
    if (files_writeToFd(fuzzer->linux.persistentSock, (uint8_t *) & len, sizeof(len)) == false) {
        return false;
    }
    if (files_writeToFd(fuzzer->linux.persistentSock, fuzzer->dynamicFile, fuzzer->dynamicFileSz) ==
        false) {
        return false;
    }
    return true;
}

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    pid_t ptracePid = (hfuzz->linux.pid > 0) ? hfuzz->linux.pid : fuzzer->pid;
    pid_t childPid = fuzzer->pid;

    if (arch_setTimer(&(fuzzer->linux.timerId)) == false) {
        LOG_F("Couldn't set timer");
    }

    if (hfuzz->persistent == false && arch_ptraceWaitForPidStop(childPid) == false) {
        LOG_F("PID %d not in a stopped state", childPid);
    }

    if (arch_shouldAttach(hfuzz, fuzzer) == true) {
        if (arch_ptraceAttach(ptracePid) == false) {
            LOG_F("arch_ptraceAttach(pid=%d) failed", ptracePid);
        }
        fuzzer->linux.attachedPid = ptracePid;
    }
    /* A long-lived process could have already exited, and we wouldn't know */
    if (kill(ptracePid, 0) == -1) {
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

    perfFd_t perfFds;
    if (arch_perfEnable(ptracePid, hfuzz, fuzzer, &perfFds) == false) {
        LOG_F("Couldn't enable perf counters for pid %d", ptracePid);
    }
    if (kill(childPid, SIGCONT) == -1) {
        PLOG_F("Restarting PID: %d failed", childPid);
    }
    if (hfuzz->persistent == true && arch_persistentSendFile(fuzzer) == false) {
        LOG_W("Could not send file contents to the persistent process");
    }

    for (;;) {
        if (arch_persistentModeRoundDone(hfuzz, fuzzer)) {
            break;
        }

        int status;
        pid_t pid = wait4(-1, &status, __WALL | __WNOTHREAD | WUNTRACED, NULL);
        if (pid == -1 && errno == EINTR) {
            if (hfuzz->tmOut) {
                arch_checkTimeLimit(hfuzz, fuzzer);
            }
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

        arch_ptraceGetCustomPerf(hfuzz, ptracePid, &fuzzer->linux.hwCnts.customCnt);

        if (hfuzz->persistent && pid == fuzzer->persistentPid
            && (WIFEXITED(status) || WIFSIGNALED(status))) {
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

    arch_removeTimer(&fuzzer->linux.timerId);
    arch_perfAnalyze(hfuzz, fuzzer, &perfFds);
    sancov_Analyze(hfuzz, fuzzer);
}

bool arch_archInit(honggfuzz_t * hfuzz)
{
    if (hfuzz->dynFileMethod &
        (_HF_DYNFILE_BTS_BLOCK | _HF_DYNFILE_BTS_EDGE | _HF_DYNFILE_IPT_BLOCK)) {
        hfuzz->bbMap = util_MMap(_HF_PERF_BITMAP_SIZE);
    }

    /* We use execvp() as a fall-back mechanism (using PATH), so it might legitimately fail */
    hfuzz->exeFd = open(hfuzz->cmdline[0], O_RDONLY | O_CLOEXEC);

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
        .sigev_value.sival_ptr = &fuzzer->linux.timerId,
        .sigev_signo = SIGNAL_TIMER,
        .sigev_notify = SIGEV_THREAD_ID | SIGEV_SIGNAL,
        ._sigev_un._tid = syscall(__NR_gettid),
    };
    if (timer_create(CLOCK_REALTIME, &sevp, &fuzzer->linux.timerId) == -1) {
        PLOG_E("timer_create(CLOCK_REALTIME) failed");
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

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGNAL_TIMER);
    if (sigprocmask(SIG_UNBLOCK, &ss, NULL) != 0) {
        PLOG_F("pthread_sigmask(%d, SIG_UNBLOCK)", SIGNAL_TIMER);
    }
    if (sigaction(SIGNAL_TIMER, &sa, NULL) == -1) {
        PLOG_E("sigaction(SIGNAL_TIMER (%d)) failed", SIGNAL_TIMER);
        return false;
    }

    return true;
}
