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
#include <sys/utsname.h>

#include "linux/perf.h"
#include "linux/ptrace_utils.h"
#include "linux/sancov.h"
#include "log.h"
#include "util.h"
#include "files.h"

/* Stringify */
#define XSTR(x)         #x
#define STR(x)          XSTR(x)

/* Common sanitizer flags */
#if _HF_MONITOR_SIGABRT
#define ABORT_FLAG        "abort_on_error=1"
#else
#define ABORT_FLAG        "abort_on_error=0"
#endif

#if defined(__ANDROID__)
/*
 * symbolize: Disable symbolication since it changes logs (which are parsed) format
 * start_deactivated: Enable on Android to reduce memory usage (useful when not all
 *                    target's DSOs are compiled with sanitizer enabled
 * abort_on_error: Disable for platforms where SIGABRT is not monitored
 */
#define kSAN_COMMON_ARCH    "symbolize=0:"ABORT_FLAG":start_deactivated=1"
#else
#define kSAN_COMMON_ARCH    "symbolize=0:"ABORT_FLAG
#endif

/* Sanitizer specific flags (set 'abort_on_error has priority over exitcode') */
#define kASAN_OPTS          "allow_user_segv_handler=1:"\
                            "handle_segv=0:"\
                            "allocator_may_return_null=1:"\
                            kSAN_COMMON_ARCH":exitcode=" STR(HF_ASAN_EXIT_CODE)

#define kUBSAN_OPTS         kSAN_COMMON_ARCH":exitcode=" STR(HF_UBSAN_EXIT_CODE)

#define kMSAN_OPTS          "exit_code=" STR(HF_MSAN_EXIT_CODE) ":"\
                            "wrap_signals=0:print_stats=1"

/* 'log_path' ouput directory for sanitizer reports */
#define kSANLOGDIR          "log_path="

/* 'coverage_dir' output directory for coverage data files is set dynamically */
#define kSANCOVDIR          "coverage_dir="

/*
 * If the program ends with a signal that ASan does not handle (or can not
 * handle at all, like SIGKILL), coverage data will be lost. This is a big
 * problem on Android, where SIGKILL is a normal way of evicting applications
 * from memory. With 'coverage_direct=1' coverage data is written to a
 * memory-mapped file as soon as it collected. Non-Android targets can disable
 * coverage direct when more coverage data collection methods are implemented.
 */
#if defined(__ANDROID__)
#define kSAN_COV_OPTS  "coverage=1:coverage_direct=1"
#else
#define kSAN_COV_OPTS  "coverage=1:coverage_direct=1"
#endif

pid_t arch_fork(honggfuzz_t * hfuzz)
{
    /*
     * We need to wait for the child to finish with wait() in case we're fuzzing
     * an external process
     */
    uintptr_t clone_flags = 0;
    if (hfuzz->pid) {
        clone_flags = SIGCHLD;
    }
    return syscall(__NR_clone, (uintptr_t) clone_flags, NULL, NULL, NULL, (uintptr_t) 0);
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

    /* Address Sanitizer (ASan) */
    if (hfuzz->sanOpts.asanOpts) {
        if (setenv("ASAN_OPTIONS", hfuzz->sanOpts.asanOpts, 1) == -1) {
            PLOG_E("setenv(ASAN_OPTIONS) failed");
            return false;
        }
    }

    /* Memory Sanitizer (MSan) */
    if (hfuzz->sanOpts.msanOpts) {
        if (setenv("MSAN_OPTIONS", hfuzz->sanOpts.msanOpts, 1) == -1) {
            PLOG_E("setenv(MSAN_OPTIONS) failed");
            return false;
        }
    }

    /* Undefined Behavior Sanitizer (UBSan) */
    if (hfuzz->sanOpts.ubsanOpts) {
        if (setenv("UBSAN_OPTIONS", hfuzz->sanOpts.ubsanOpts, 1) == -1) {
            PLOG_E("setenv(UBSAN_OPTIONS) failed");
            return false;
        }
    }

    /*
     * Disable ASLR
     */
    if (hfuzz->disableRandomization && personality(ADDR_NO_RANDOMIZE) == -1) {
        PLOG_E("personality(ADDR_NO_RANDOMIZE) failed");
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

    LOG_D("Launching '%s' on file '%s'", args[0], fileName);

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
            PLOG_E("Couldn't enforce the RLIMIT_CPU resource limit");
            return false;
        }
    }

    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (hfuzz->asLimit) {
        struct rlimit64 rl = {
            .rlim_cur = hfuzz->asLimit * 1024ULL * 1024ULL,
            .rlim_max = hfuzz->asLimit * 1024ULL * 1024ULL,
        };
        if (prlimit64(0, RLIMIT_AS, &rl, NULL) == -1) {
            PLOG_D("Couldn't enforce the RLIMIT_AS resource limit, ignoring");
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
    syscall(__NR_tkill, syscall(__NR_gettid), (uintptr_t) SIGSTOP);
    execvp(args[0], args);

    util_recoverStdio();
    LOG_F("Failed to create new '%s' process", args[0]);
    return false;
}

static void arch_sigFunc(int signo, siginfo_t * si UNUSED, void *dummy UNUSED)
{
    if (signo != SIGALRM) {
        LOG_E("Signal != SIGALRM (%d)", signo);
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
        PLOG_E("timer_create(CLOCK_REALTIME) failed");
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
        PLOG_E("timer_settime() failed");
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
        PLOG_E("sigaction(SIGALRM) failed");
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
        __sync_fetch_and_add(&hfuzz->timeoutedCnt, 1UL);
    }
}

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    pid_t ptracePid = (hfuzz->pid > 0) ? hfuzz->pid : fuzzer->pid;
    pid_t childPid = fuzzer->pid;

    timer_t timerid;
    if (arch_setTimer(&timerid) == false) {
        LOG_F("Couldn't set timer");
    }

    if (arch_ptraceWaitForPidStop(childPid) == false) {
        LOG_F("PID %d not in a stopped state", childPid);
    }
    LOG_D("PID: %d is in a stopped state now", childPid);

    static bool ptraceAttached = false;
    if (ptraceAttached == false) {
        if (arch_ptraceAttach(ptracePid) == false) {
            LOG_F("arch_ptraceAttach(pid=%d) failed", ptracePid);
        }
        /* In case we fuzz a long-lived process (-p pid) we attach to it once only */
        if (ptracePid != childPid) {
            ptraceAttached = true;
        }
    }
    /* A long-lived processed could have already exited, and we wouldn't know */
    if (kill(ptracePid, 0) == -1) {
        if (hfuzz->pidFile) {
            /* If pid from file, check again for cases of auto-restart daemons that update it */
            /* 
             * TODO: Investigate if we need to delay here, so that target process has
             * enough time to restart. Tricky to answer since is target dependant.
             */
            if (files_readPidFromFile(hfuzz->pidFile, &hfuzz->pid) == false) {
                LOG_F("Failed to read new PID from file - abort");
            } else {
                if (kill(hfuzz->pid, 0) == -1) {
                    PLOG_F("Liveness of PID %d read from file questioned - abort", hfuzz->pid);
                } else {
                    LOG_D("Monitor PID has been updated (pid=%d)", hfuzz->pid);
                    ptracePid = hfuzz->pid;
                }
            }
        } else {
            PLOG_F("Liveness of %d questioned - abort", ptracePid);
        }
    }

    perfFd_t perfFds;
    if (arch_perfEnable(ptracePid, hfuzz, &perfFds) == false) {
        LOG_F("Couldn't enable perf counters for pid %d", ptracePid);
    }
    if (kill(childPid, SIGCONT) == -1) {
        PLOG_F("Restarting PID: %d failed", childPid);
    }

    for (;;) {
        int status;
        pid_t pid = wait4(-1, &status, __WALL | __WNOTHREAD, NULL);
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
        LOG_D("PID '%d' returned with status '%d'", pid, status);

        arch_ptraceGetCustomPerf(hfuzz, ptracePid, &fuzzer->hwCnts.customCnt);

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

    arch_removeTimer(&timerid);
    arch_perfAnalyze(hfuzz, fuzzer, &perfFds);
    arch_sanCovAnalyze(hfuzz, fuzzer);
}

bool arch_archInit(honggfuzz_t * hfuzz)
{
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
         *  3) Intel's PT requires kernel >= 4.1
         */
        unsigned long checkMajor = 3, checkMinor = 7;
        if ((hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK)
            || (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_EDGE)) {
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
    if (hfuzz->pidFile) {
        if (files_readPidFromFile(hfuzz->pidFile, &hfuzz->pid) == false) {
            LOG_E("Failed to read PID from file");
            return false;
        }
    }

    /*
     * If sanitizer fuzzing enabled increase number of major frames, since top 7-9 frames
     * will be occupied with sanitizer symbols if 'abort_on_error' flag is set
     */
#if _HF_MONITOR_SIGABRT
    hfuzz->numMajorFrames = 14;
#endif

    /* 
     * If monitoring remote process don't adjust sanitizer flags for spawned workers. It
     * is user's responsibility to spawn remote process with correct flags & path for data
     * files aligned with workspace expected dir.
     */
    if (hfuzz->pid > 0) {
        return true;
    }

    /* If sanitizer coverage enabled init workspace subdir */
    if (hfuzz->useSanCov) {
        char sanCovOutDir[PATH_MAX] = { 0 };
        snprintf(sanCovOutDir, sizeof(sanCovOutDir), "%s/%s", hfuzz->workDir, _HF_SANCOV_DIR);
        if (!files_exists(sanCovOutDir)) {
            if (mkdir(sanCovOutDir, S_IRWXU | S_IXGRP | S_IXOTH) != 0) {
                PLOG_E("mkdir() '%s' failed", sanCovOutDir);
            }
        }
    }

    /* Set sanitizer flags once to avoid performance overhead per worker spawn */
    size_t flagsSz = 0;
    size_t bufSz = sizeof(kASAN_OPTS) + (2 * PATH_MAX); // Larger constant + 2 dynamic paths
    char *san_opts = malloc(bufSz);
    if (san_opts == NULL) {
        PLOG_E("malloc(%zu) failed", bufSz);
        return false;
    }

    /* AddressSanitizer (ASan) */
    memset(san_opts, 0, bufSz);
    if (hfuzz->useSanCov) {
#if !_HF_MONITOR_SIGABRT
        /* Write reports in FS only if abort_on_error is disabled */
        snprintf(san_opts, bufSz, "%s:%s:%s%s/%s:%s%s/%s", kASAN_OPTS, kSAN_COV_OPTS,
                 kSANCOVDIR, hfuzz->workDir, _HF_SANCOV_DIR, kSANLOGDIR, hfuzz->workDir,
                 kLOGPREFIX);
#else
        snprintf(san_opts, bufSz, "%s:%s:%s%s/%s", kASAN_OPTS, kSAN_COV_OPTS,
                 kSANCOVDIR, hfuzz->workDir, _HF_SANCOV_DIR);
#endif
    } else {
        snprintf(san_opts, bufSz, "%s:%s%s/%s", kASAN_OPTS, kSANLOGDIR, hfuzz->workDir, kLOGPREFIX);
    }

    flagsSz = strlen(san_opts) + 1;
    hfuzz->sanOpts.asanOpts = malloc(flagsSz);
    if (hfuzz->sanOpts.asanOpts == NULL) {
        PLOG_E("malloc(%zu) failed", flagsSz);
        free(san_opts);
        return false;
    }
    memset(hfuzz->sanOpts.asanOpts, 0, flagsSz);
    memcpy(hfuzz->sanOpts.asanOpts, san_opts, flagsSz);
    LOG_D("ASAN_OPTIONS=%s", hfuzz->sanOpts.asanOpts);

    /* Undefined Behavior (UBSan) */
    memset(san_opts, 0, bufSz);
    if (hfuzz->useSanCov) {
#if !_HF_MONITOR_SIGABRT
        /* Write reports in FS only if abort_on_error is disabled */
        snprintf(san_opts, bufSz, "%s:%s:%s%s/%s:%s%s/%s", kUBSAN_OPTS, kSAN_COV_OPTS,
                 kSANCOVDIR, hfuzz->workDir, _HF_SANCOV_DIR, kSANLOGDIR, hfuzz->workDir,
                 kLOGPREFIX);
#else
        snprintf(san_opts, bufSz, "%s:%s:%s%s/%s", kUBSAN_OPTS, kSAN_COV_OPTS,
                 kSANCOVDIR, hfuzz->workDir, _HF_SANCOV_DIR);
#endif
    } else {
        snprintf(san_opts, bufSz, "%s:%s%s/%s", kUBSAN_OPTS, kSANLOGDIR, hfuzz->workDir,
                 kLOGPREFIX);
    }

    flagsSz = strlen(san_opts) + 1;
    hfuzz->sanOpts.ubsanOpts = malloc(flagsSz);
    if (hfuzz->sanOpts.ubsanOpts == NULL) {
        PLOG_E("malloc(%zu) failed", flagsSz);
        free(san_opts);
        return false;
    }
    memset(hfuzz->sanOpts.ubsanOpts, 0, flagsSz);
    memcpy(hfuzz->sanOpts.ubsanOpts, san_opts, flagsSz);
    LOG_D("UBSAN_OPTIONS=%s", hfuzz->sanOpts.ubsanOpts);

    /* MemorySanitizer (MSan) */
    memset(san_opts, 0, bufSz);
    const char *msan_reports_flag = "report_umrs=0";
    if (hfuzz->msanReportUMRS) {
        msan_reports_flag = "report_umrs=1";
    }

    if (hfuzz->useSanCov) {
#if !_HF_MONITOR_SIGABRT
        /* Write reports in FS only if abort_on_error is disabled */
        snprintf(san_opts, bufSz, "%s:%s:%s:%s%s/%s:%s%s/%s", kMSAN_OPTS, msan_reports_flag,
                 kSAN_COV_OPTS, kSANCOVDIR, hfuzz->workDir, _HF_SANCOV_DIR, kSANLOGDIR,
                 hfuzz->workDir, kLOGPREFIX);
#else
        snprintf(san_opts, bufSz, "%s:%s:%s:%s%s/%s", kMSAN_OPTS, msan_reports_flag,
                 kSAN_COV_OPTS, kSANCOVDIR, hfuzz->workDir, _HF_SANCOV_DIR);
#endif
    } else {
        snprintf(san_opts, bufSz, "%s:%s:%s%s/%s", kMSAN_OPTS, msan_reports_flag, kSANLOGDIR,
                 hfuzz->workDir, kLOGPREFIX);
    }

    flagsSz = strlen(san_opts) + 1;
    hfuzz->sanOpts.msanOpts = malloc(flagsSz);
    if (hfuzz->sanOpts.msanOpts == NULL) {
        PLOG_E("malloc(%zu) failed", flagsSz);
        free(san_opts);
        return false;
    }
    memset(hfuzz->sanOpts.msanOpts, 0, flagsSz);
    memcpy(hfuzz->sanOpts.msanOpts, san_opts, flagsSz);
    LOG_D("MSAN_OPTIONS=%s", hfuzz->sanOpts.msanOpts);

    free(san_opts);
    return true;
}
