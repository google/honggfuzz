/*
 *
 * honggfuzz - architecture dependent code (LINUX)
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
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

#include "arch.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"
#include "libhfcommon/util.h"
#include "linux/perf.h"
#include "linux/trace.h"
#include "sanitizers.h"
#include "subproc.h"

static uint8_t arch_clone_stack[128 * 1024] __attribute__((aligned(__BIGGEST_ALIGNMENT__)));
static __thread jmp_buf env;

HF_ATTR_NO_SANITIZE_ADDRESS
HF_ATTR_NO_SANITIZE_MEMORY
__attribute__((noreturn)) static int arch_cloneFunc(void* arg HF_ATTR_UNUSED) {
    longjmp(env, 1);
}

/* Avoid problem with caching of PID/TID in glibc */
static pid_t arch_clone(uintptr_t flags) {
    if (flags & CLONE_VM) {
        LOG_E("Cannot use clone(flags & CLONE_VM)");
        return -1;
    }

    if (setjmp(env) == 0) {
        void* stack_mid = &arch_clone_stack[sizeof(arch_clone_stack) / 2];
        /* Parent */
        return clone(arch_cloneFunc, stack_mid, flags, NULL, NULL, NULL);
    }
    /* Child */
    return 0;
}

pid_t arch_fork(run_t* run) {
    pid_t pid = run->global->linux.useClone ? arch_clone(CLONE_UNTRACED | SIGCHLD) : fork();
    if (pid == -1) {
        return pid;
    }
    if (pid == 0) {
        logMutexReset();
        if (prctl(PR_SET_PDEATHSIG, (unsigned long)SIGKILL, 0UL, 0UL, 0UL) == -1) {
            PLOG_W("prctl(PR_SET_PDEATHSIG, SIGKILL)");
        }
        return pid;
    }
    return pid;
}

bool arch_launchChild(run_t* run) {
    if ((run->global->linux.cloneFlags & CLONE_NEWNET) && (nsIfaceUp("lo") == false)) {
        LOG_W("Cannot bring interface 'lo' up");
    }

    /*
     * Make it attach-able by ptrace()
     */
    if (prctl(PR_SET_DUMPABLE, 1UL, 0UL, 0UL, 0UL) == -1) {
        PLOG_E("prctl(PR_SET_DUMPABLE, 1)");
        return false;
    }

    /*
     * Kill a process which corrupts its own heap (with ABRT)
     */
    if (setenv("MALLOC_CHECK_", "7", 0) == -1) {
        PLOG_E("setenv(MALLOC_CHECK_=7) failed");
        return false;
    }
    if (setenv("MALLOC_PERTURB_", "85", 0) == -1) {
        PLOG_E("setenv(MALLOC_PERTURB_=85) failed");
        return false;
    }

    /*
     * Disable ASLR:
     * This might fail in Docker, as Docker blocks __NR_personality. Consequently
     * it's just a debug warning
     */
    if (run->global->linux.disableRandomization &&
        syscall(__NR_personality, ADDR_NO_RANDOMIZE) == -1) {
        PLOG_D("personality(ADDR_NO_RANDOMIZE) failed");
    }

#define ARGS_MAX 512
    const char* args[ARGS_MAX + 2];
    char argData[PATH_MAX];

    char inputFile[PATH_MAX];
    snprintf(inputFile, sizeof(inputFile), "/dev/fd/%d", run->dynamicFileCopyFd);

    int x = 0;
    for (x = 0; x < ARGS_MAX && x < run->global->exe.argc; x++) {
        if (run->global->exe.persistent || run->global->exe.fuzzStdin) {
            args[x] = run->global->exe.cmdline[x];
        } else if (!strcmp(run->global->exe.cmdline[x], _HF_FILE_PLACEHOLDER)) {
            args[x] = inputFile;
        } else if (strstr(run->global->exe.cmdline[x], _HF_FILE_PLACEHOLDER)) {
            const char* off = strstr(run->global->exe.cmdline[x], _HF_FILE_PLACEHOLDER);
            snprintf(argData, sizeof(argData), "%.*s%s", (int)(off - run->global->exe.cmdline[x]),
                run->global->exe.cmdline[x], inputFile);
            args[x] = argData;
        } else {
            args[x] = run->global->exe.cmdline[x];
        }
    }
    args[x++] = NULL;

    LOG_D("Launching '%s' on file '%s'", args[0],
        run->global->exe.persistent ? "PERSISTENT_MODE" : inputFile);

    /* alarms persist across execve(), so disable it here */
    alarm(0);

    /* Wait for the ptrace to attach now */
    if (kill(syscall(__NR_getpid), SIGSTOP) == -1) {
        LOG_F("Couldn't stop itself");
    }
#if defined(__NR_execveat)
    syscall(__NR_execveat, run->global->linux.exeFd, "", args, environ, AT_EMPTY_PATH);
#endif /* defined__NR_execveat) */
    execve(args[0], (char* const*)args, environ);
    int errno_cpy = errno;
    alarm(1);

    LOG_E("execve('%s', fd=%d): %s", args[0], run->global->linux.exeFd, strerror(errno_cpy));

    return false;
}

static bool arch_attachToNewPid(run_t* run) {
    if (!arch_traceAttach(run)) {
        LOG_W("arch_traceAttach(pid=%d) failed", run->pid);
        return false;
    }

    return true;
}

void arch_prepareParentAfterFork(run_t* run) {
    /* Parent */
    if (run->global->exe.persistent) {
        const struct f_owner_ex fown = {
            .type = F_OWNER_TID,
            .pid = syscall(__NR_gettid),
        };
        if (fcntl(run->persistentSock, F_SETOWN_EX, &fown)) {
            PLOG_F("fcntl(%d, F_SETOWN_EX)", run->persistentSock);
        }
        if (fcntl(run->persistentSock, F_SETSIG, SIGIO) == -1) {
            PLOG_F("fcntl(%d, F_SETSIG, SIGIO)", run->persistentSock);
        }
        if (fcntl(run->persistentSock, F_SETFL, O_ASYNC) == -1) {
            PLOG_F("fcntl(%d, F_SETFL, O_ASYNC)", run->persistentSock);
        }
    }

    arch_perfClose(run);
    if (!arch_perfOpen(run)) {
        LOG_F("Couldn't open perf event for pid=%d", (int)run->pid);
    }
    if (!arch_attachToNewPid(run)) {
        LOG_F("Couldn't attach to pid=%d", (int)run->pid);
    }
}

void arch_prepareParent(run_t* run) {
    if (!arch_perfEnable(run)) {
        LOG_F("Couldn't enable perf counters for pid=%d", (int)run->pid);
    }
}

static bool arch_checkWait(run_t* run) {
    /* All queued wait events must be tested when SIGCHLD was delivered */
    for (;;) {
        int status;
        pid_t pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, __WALL | __WNOTHREAD | WNOHANG));
        if (pid == 0) {
            return false;
        }
        if (pid == -1 && errno == ECHILD) {
            LOG_D("No more processes to track");
            return true;
        }
        if (pid == -1) {
            PLOG_F("waitpid() failed");
        }

        char statusStr[4096];
        LOG_D("pid=%d returned with status: %s", pid,
            subproc_StatusToStr(status, statusStr, sizeof(statusStr)));

        arch_traceAnalyze(run, status, pid);

        if (pid == run->pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            if (run->global->exe.persistent) {
                if (!fuzz_isTerminating()) {
                    LOG_W("Persistent mode: pid=%d exited with status: %s", (int)run->pid,
                        subproc_StatusToStr(status, statusStr, sizeof(statusStr)));
                }
            }
            return true;
        }
    }
}

void arch_reapChild(run_t* run) {
    for (;;) {
        if (subproc_persistentModeStateMachine(run)) {
            break;
        }

        subproc_checkTimeLimit(run);
        subproc_checkTermination(run);

        const struct timespec ts = {
            .tv_sec = 0ULL,
            .tv_nsec = (1000ULL * 1000ULL * 250ULL),
        };
        /* Return with SIGIO, SIGCHLD and with SIGUSR1 */
        int sig = sigtimedwait(&run->global->exe.waitSigSet, NULL, &ts /* 0.25s */);
        if (sig == -1 && (errno != EAGAIN && errno != EINTR)) {
            PLOG_F("sigwaitinfo(SIGIO|SIGCHLD|SIGUSR1)");
        }

        if (arch_checkWait(run)) {
            run->pid = 0;
            break;
        }
        if (run->global->socketFuzzer.enabled) {
            // Do not wait for new events
            break;
        }
    }
    if (run->global->sanitizer.enable) {
        char crashReport[PATH_MAX];
        snprintf(crashReport, sizeof(crashReport), "%s/%s.%d", run->global->io.workDir, kLOGPREFIX,
            run->pid);
        if (files_exists(crashReport)) {
            if (run->backtrace) {
                unlink(crashReport);
            } else {
                LOG_W("Un-handled ASan report due to compiler-rt internal error - retry with '%s'",
                    crashReport);
                /* Try to parse report file */
                arch_traceExitAnalyze(run, run->pid);
            }
        }
    }

    arch_perfAnalyze(run);
}

bool arch_archInit(honggfuzz_t* hfuzz) {
    /* Make %'d work */
    setlocale(LC_NUMERIC, "en_US.UTF-8");

    if (access(hfuzz->exe.cmdline[0], X_OK) == -1) {
        PLOG_E("File '%s' doesn't seem to be executable", hfuzz->exe.cmdline[0]);
        return false;
    }
    if ((hfuzz->linux.exeFd =
                TEMP_FAILURE_RETRY(open(hfuzz->exe.cmdline[0], O_RDONLY | O_CLOEXEC))) == -1) {
        PLOG_E("Cannot open the executable binary: %s)", hfuzz->exe.cmdline[0]);
        return false;
    }

    for (;;) {
        __attribute__((weak)) const char* gnu_get_libc_version(void);
        if (!gnu_get_libc_version) {
            LOG_W("Unknown libc implementation. Using clone() instead of fork()");
            break;
        }
        const char* gversion = gnu_get_libc_version();
        int major, minor;
        if (sscanf(gversion, "%d.%d", &major, &minor) != 2) {
            LOG_W("Unknown glibc version:'%s'. Using clone() instead of fork()", gversion);
            break;
        }
        if ((major < 2) || (major == 2 && minor < 23)) {
            LOG_W("Your glibc version:'%s' will most likely result in malloc()-related "
                  "deadlocks. Min. version 2.24 (Or, Ubuntu's 2.23-0ubuntu6) suggested. "
                  "See https://sourceware.org/bugzilla/show_bug.cgi?id=19431 for explanation. "
                  "Using clone() instead of fork()",
                gversion);
            break;
        }
        LOG_D("Glibc version:'%s', OK", gversion);
        hfuzz->linux.useClone = false;
        break;
    }

    if (hfuzz->feedback.dynFileMethod != _HF_DYNFILE_NONE) {
        unsigned long major = 0, minor = 0;
        char* p = NULL;

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
        if ((hfuzz->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) ||
            (hfuzz->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK)) {
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

        if (!arch_perfInit(hfuzz)) {
            return false;
        }
    }
#if defined(__ANDROID__) && defined(__arm__) && defined(OPENSSL_ARMCAP_ABI)
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

    /* Updates the important signal array based on input args */
    arch_traceSignalsInit(hfuzz);

    /*
     * If sanitizer fuzzing enabled and SIGABRT is monitored (abort_on_error=1),
     * increase number of major frames, since top 7-9 frames will be occupied
     * with sanitizer runtime library & libc symbols
     */
    if (hfuzz->sanitizer.enable && hfuzz->cfg.monitorSIGABRT) {
        hfuzz->linux.numMajorFrames = 14;
    }

    if (hfuzz->linux.cloneFlags && unshare(hfuzz->linux.cloneFlags) == -1) {
        LOG_E("unshare(%tx)", hfuzz->linux.cloneFlags);
        return false;
    }

    return true;
}

bool arch_archThreadInit(run_t* run) {
    run->linux.perfMmapBuf = NULL;
    run->linux.perfMmapAux = NULL;
    run->linux.cpuInstrFd = -1;
    run->linux.cpuBranchFd = -1;
    run->linux.cpuIptBtsFd = -1;

    if (prctl(PR_SET_CHILD_SUBREAPER, 1UL, 0UL, 0UL, 0UL) == -1) {
        PLOG_W("prctl(PR_SET_CHILD_SUBREAPER, 1)");
    }

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &ss, NULL) != 0) {
        PLOG_W("Couldn't block SIGUSR1");
        return false;
    }

    return true;
}
