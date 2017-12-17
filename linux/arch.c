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
#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/ns.h"
#include "libcommon/util.h"
#include "linux/perf.h"
#include "linux/trace.h"
#include "sancov.h"
#include "sanitizers.h"
#include "subproc.h"

static inline bool arch_shouldAttach(run_t* run) {
    if (run->global->persistent && run->linux.attachedPid == run->pid) {
        return false;
    }
    if (run->global->linux.pid > 0 && run->linux.attachedPid == run->global->linux.pid) {
        return false;
    }
    return true;
}

static uint8_t arch_clone_stack[128 * 1024];
static __thread jmp_buf env;

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
__attribute__((no_sanitize("address"))) __attribute__((no_sanitize("memory")))
#endif /* if __has_feature(address_sanitizer) */
#endif /* if defined(__has_feature) */
static int
arch_cloneFunc(void* arg UNUSED) {
    longjmp(env, 1);
    abort();
    return 0;
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
    run->global->linux.useClone = true;

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
    char argData[PATH_MAX] = {0};
    int x = 0;

    for (x = 0; x < ARGS_MAX && run->global->exe.cmdline[x]; x++) {
        if (!run->global->exe.fuzzStdin && !run->global->persistent &&
            strcmp(run->global->exe.cmdline[x], _HF_FILE_PLACEHOLDER) == 0) {
            args[x] = (char*)run->fileName;
        } else if (!run->global->exe.fuzzStdin && !run->global->persistent &&
                   strstr(run->global->exe.cmdline[x], _HF_FILE_PLACEHOLDER)) {
            const char* off = strstr(run->global->exe.cmdline[x], _HF_FILE_PLACEHOLDER);
            snprintf(argData, PATH_MAX, "%.*s%s", (int)(off - run->global->exe.cmdline[x]),
                run->global->exe.cmdline[x], run->fileName);
            args[x] = argData;
        } else {
            args[x] = run->global->exe.cmdline[x];
        }
    }

    args[x++] = NULL;

    LOG_D("Launching '%s' on file '%s'", args[0],
        run->global->persistent ? "PERSISTENT_MODE" : run->fileName);

    /* alarm persists across forks, so disable it here */
    alarm(0);

    /*
     * Wait for the ptrace to attach
     */
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

void arch_prepareParentAfterFork(run_t* run) {
    /* Parent */
    if (run->global->persistent) {
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
}

static bool arch_attachToNewPid(run_t* run, pid_t pid) {
    if (!arch_shouldAttach(run)) {
        return true;
    }
    run->linux.attachedPid = pid;
    if (!arch_traceAttach(run, pid)) {
        LOG_W("arch_traceAttach(pid=%d) failed", pid);
        kill(pid, SIGKILL);
        return false;
    }

    arch_perfClose(run);
    if (arch_perfOpen(pid, run) == false) {
        kill(pid, SIGKILL);
        return false;
    }

    return true;
}

void arch_prepareParent(run_t* run) {
    pid_t ptracePid = (run->global->linux.pid > 0) ? run->global->linux.pid : run->pid;
    pid_t childPid = run->pid;

    if (!arch_attachToNewPid(run, ptracePid)) {
        LOG_E("Couldn't attach to PID=%d", (int)ptracePid);
    }

    /* A long-lived process could have already exited, and we wouldn't know */
    if (childPid != ptracePid && kill(ptracePid, 0) == -1) {
        if (run->global->linux.pidFile) {
            /* If pid from file, check again for cases of auto-restart daemons that update it */
            /*
             * TODO: Investigate if we need to delay here, so that target process has
             * enough time to restart. Tricky to answer since is target dependent.
             */
            if (files_readPidFromFile(run->global->linux.pidFile, &run->global->linux.pid) ==
                false) {
                LOG_F("Failed to read new PID from file - abort");
            } else {
                if (kill(run->global->linux.pid, 0) == -1) {
                    PLOG_F("Liveness of PID %d read from file questioned - abort",
                        run->global->linux.pid);
                } else {
                    LOG_D("Monitor PID has been updated (pid=%d)", run->global->linux.pid);
                    ptracePid = run->global->linux.pid;
                }
            }
        }
    }

    if (arch_perfEnable(run) == false) {
        LOG_E("Couldn't enable perf counters for pid %d", ptracePid);
    }
    if (childPid != ptracePid) {
        if (arch_traceWaitForPidStop(childPid) == false) {
            LOG_F("PID: %d not in a stopped state", childPid);
        }
        if (kill(childPid, SIGCONT) == -1) {
            PLOG_F("Restarting PID: %d failed", childPid);
        }
    }
}

static bool arch_checkWait(run_t* run) {
    pid_t ptracePid = (run->global->linux.pid > 0) ? run->global->linux.pid : run->pid;
    pid_t childPid = run->pid;

    /* All queued wait events must be tested */
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, __WALL | __WNOTHREAD | WNOHANG);
        if (pid == 0) {
            return false;
        }
        if (pid == -1 && errno == EINTR) {
            continue;
        }
        if (pid == -1 && errno == ECHILD) {
            LOG_D("No more processes to track");
            return true;
        }
        if (pid == -1) {
            PLOG_F("wait4() failed");
        }

        char statusStr[4096];
        LOG_D("PID '%d' returned with status: %s", pid,
            subproc_StatusToStr(status, statusStr, sizeof(statusStr)));

        if (run->global->persistent && pid == run->persistentPid &&
            (WIFEXITED(status) || WIFSIGNALED(status))) {
            arch_traceAnalyze(run, status, pid);
            run->persistentPid = 0;
            if (fuzz_isTerminating() == false) {
                LOG_W("Persistent mode: PID %d exited with status: %s", pid,
                    subproc_StatusToStr(status, statusStr, sizeof(statusStr)));
            }
            return true;
        }
        if (ptracePid == childPid) {
            arch_traceAnalyze(run, status, pid);
            continue;
        }
        if (pid == childPid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            return true;
        }
        if (pid == childPid) {
            continue;
        }

        arch_traceAnalyze(run, status, pid);
    }
}

__thread sigset_t sset_io_chld;
void arch_reapChild(run_t* run) {
    static const struct timespec ts = {
        .tv_sec = 0L,
        .tv_nsec = 250000000L,
    };
    for (;;) {
        int sig = sigtimedwait(&sset_io_chld, NULL, &ts);
        if (sig == -1 && (errno != EAGAIN && errno != EINTR)) {
            PLOG_F("sigtimedwait(SIGIO|SIGCHLD, 0.25s)");
        }
        if (sig == -1) {
            subproc_checkTimeLimit(run);
            subproc_checkTermination(run);
        }
        if (subproc_persistentModeRoundDone(run)) {
            break;
        }
        if (arch_checkWait(run)) {
            break;
        }
    }

    if (run->global->enableSanitizers) {
        pid_t ptracePid = (run->global->linux.pid > 0) ? run->global->linux.pid : run->pid;
        char crashReport[PATH_MAX];
        snprintf(crashReport, sizeof(crashReport), "%s/%s.%d", run->global->io.workDir, kLOGPREFIX,
            ptracePid);
        if (files_exists(crashReport)) {
            if (run->backtrace) {
                unlink(crashReport);
            } else {
                LOG_W(
                    "Un-handled ASan report due to compiler-rt internal error - retry with '%s' "
                    "(%s)",
                    crashReport, run->fileName);

                /* Try to parse report file */
                arch_traceExitAnalyze(run, ptracePid);
            }
        }
    }

    arch_perfAnalyze(run);
    sancov_Analyze(run);
}

bool arch_archInit(honggfuzz_t* hfuzz) {
    /* Make %'d work */
    setlocale(LC_NUMERIC, "en_US");

    if (access(hfuzz->exe.cmdline[0], X_OK) == -1) {
        PLOG_E("File '%s' doesn't seem to be executable", hfuzz->exe.cmdline[0]);
        return false;
    }
    if ((hfuzz->linux.exeFd = open(hfuzz->exe.cmdline[0], O_RDONLY | O_CLOEXEC)) == -1) {
        PLOG_E("Cannot open the executable binary: %s)", hfuzz->exe.cmdline[0]);
        return false;
    }

    const char* (*gvs)(void) = dlsym(RTLD_DEFAULT, "gnu_get_libc_version");
    for (;;) {
        if (!gvs) {
            LOG_W("Unknown libc implementation. Using clone() instead of fork()");
            break;
        }
        const char* gversion = gvs();
        int major, minor;
        if (sscanf(gversion, "%d.%d", &major, &minor) != 2) {
            LOG_W("Unknown glibc version:'%s'. Using clone() instead of fork()", gversion);
            break;
        }
        if ((major < 2) || (major == 2 && minor < 23)) {
            LOG_W(
                "Your glibc version:'%s' will most likely result in malloc()-related "
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

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
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
        if ((hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) ||
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

    /* If read PID from file enable - read current value */
    if (hfuzz->linux.pidFile) {
        if (files_readPidFromFile(hfuzz->linux.pidFile, &hfuzz->linux.pid) == false) {
            LOG_E("Failed to read PID from file");
            return false;
        }
    }

    /* If remote pid, resolve command using procfs */
    if (hfuzz->linux.pid > 0) {
        char procCmd[PATH_MAX] = {0};
        snprintf(procCmd, sizeof(procCmd), "/proc/%d/cmdline", hfuzz->linux.pid);

        ssize_t sz = files_readFileToBufMax(
            procCmd, (uint8_t*)hfuzz->linux.pidCmd, sizeof(hfuzz->linux.pidCmd) - 1);
        if (sz < 1) {
            LOG_E("Couldn't read '%s'", procCmd);
            return false;
        }

        /* Make human readable */
        for (size_t i = 0; i < ((size_t)sz - 1); i++) {
            if (hfuzz->linux.pidCmd[i] == '\0') {
                hfuzz->linux.pidCmd[i] = ' ';
            }
        }
        hfuzz->linux.pidCmd[sz] = '\0';
    }

    /* Updates the important signal array based on input args */
    arch_traceSignalsInit(hfuzz);

    /*
     * If sanitizer fuzzing enabled and SIGABRT is monitored (abort_on_error=1),
     * increase number of major frames, since top 7-9 frames will be occupied
     * with sanitizer runtime library & libc symbols
     */
    if (hfuzz->enableSanitizers && hfuzz->monitorSIGABRT) {
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

    sigemptyset(&sset_io_chld);
    sigaddset(&sset_io_chld, SIGIO);
    sigaddset(&sset_io_chld, SIGCHLD);

    return true;
}
