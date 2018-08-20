/*
 *
 * honggfuzz - architecture dependent code (NETBSD)
 * -----------------------------------------
 *
 * Author: Kamil Rytarowski <n54@gmx.com>
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

// clang-format off
#include <sys/param.h>
#include <sys/types.h>
// clang-format on

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"
#include "libhfcommon/util.h"
#include "netbsd/trace.h"
#include "sancov.h"
#include "sanitizers.h"
#include "subproc.h"

extern char** environ;

static inline bool arch_shouldAttach(run_t* run) {
    if (run->global->exe.persistent && run->netbsd.attachedPid == run->pid) {
        return false;
    }
    if (run->global->netbsd.pid > 0 && run->netbsd.attachedPid == run->global->netbsd.pid) {
        return false;
    }
    if (run->global->socketFuzzer.enabled && run->netbsd.attachedPid == run->pid) {
        return false;
    }
    return true;
}

pid_t arch_fork(run_t* run HF_ATTR_UNUSED) {
    pid_t pid = fork();
    if (pid == -1) {
        return pid;
    }
    if (pid == 0) {
        logMutexReset();
        return pid;
    }
    return pid;
}

bool arch_launchChild(run_t* run) {
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
    if (raise(SIGSTOP) == -1) {
        LOG_F("Couldn't stop itself");
    }

    execve(args[0], (char* const*)args, environ);
    int errno_cpy = errno;
    alarm(1);

    LOG_E("execve('%s'): %s", args[0], strerror(errno_cpy));

    return false;
}

void arch_prepareParentAfterFork(run_t* run) {
    /* Parent */
    if (run->global->exe.persistent) {
        if (fcntl(run->persistentSock, F_SETFL, O_ASYNC) == -1) {
            PLOG_F("fcntl(%d, F_SETFL, O_ASYNC)", run->persistentSock);
        }
    }
}

static bool arch_attachToNewPid(run_t* run, pid_t pid) {
    if (!arch_shouldAttach(run)) {
        return true;
    }
    run->netbsd.attachedPid = pid;
    if (!arch_traceAttach(run, pid)) {
        LOG_W("arch_traceAttach(pid=%d) failed", pid);
        kill(pid, SIGKILL);
        /* TODO: missing wait(2)? */
        return false;
    }

    return true;
}

void arch_prepareParent(run_t* run) {
    pid_t ptracePid = (run->global->netbsd.pid > 0) ? run->global->netbsd.pid : run->pid;
    pid_t childPid = run->pid;

    if (!arch_attachToNewPid(run, ptracePid)) {
        LOG_E("Couldn't attach to PID=%d", (int)ptracePid);
    }

    /* A long-lived process could have already exited, and we wouldn't know */
    if (childPid != ptracePid && kill(ptracePid, 0) == -1) {
        if (run->global->netbsd.pidFile) {
            /* If pid from file, check again for cases of auto-restart daemons that update it */
            /*
             * TODO: Investigate if we need to delay here, so that target process has
             * enough time to restart. Tricky to answer since is target dependent.
             */
            if (files_readPidFromFile(run->global->netbsd.pidFile, &run->global->netbsd.pid) ==
                false) {
                LOG_F("Failed to read new PID from file - abort");
            } else {
                if (kill(run->global->netbsd.pid, 0) == -1) {
                    PLOG_F("Liveness of PID %d read from file questioned - abort",
                        run->global->netbsd.pid);
                } else {
                    LOG_D("Monitor PID has been updated (pid=%d)", run->global->netbsd.pid);
                    ptracePid = run->global->netbsd.pid;
                }
            }
        }
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
    pid_t ptracePid = (run->global->netbsd.pid > 0) ? run->global->netbsd.pid : run->pid;
    pid_t childPid = run->pid;

    /* All queued wait events must be tested when SIGCHLD was delivered */
    for (;;) {
        int status;
        pid_t pid = TEMP_FAILURE_RETRY(waitpid(ptracePid, &status, WALLSIG | WNOHANG));
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
        LOG_D("PID '%d' returned with status: %s", pid,
            subproc_StatusToStr(status, statusStr, sizeof(statusStr)));

        if (run->global->exe.persistent && pid == run->persistentPid &&
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

void arch_reapChild(run_t* run) {
    for (;;) {
        if (run->global->exe.persistent) {
            struct pollfd pfd = {
                .fd = run->persistentSock,
                .events = POLLIN,
            };
            int r = poll(&pfd, 1, 250 /* 0.25s */);
            if (r == 0 || (r == -1 && errno == EINTR)) {
                subproc_checkTimeLimit(run);
                subproc_checkTermination(run);
            }
            if (r == -1 && errno != EINTR) {
                PLOG_F("poll(fd=%d)", run->persistentSock);
            }
        }

        if (subproc_persistentModeRoundDone(run)) {
            break;
        }
        if (arch_checkWait(run)) {
            LOG_D("SocketFuzzer: arch: Crash Identified");
            run->hasCrashed = true;
            break;
        }
        if (run->global->socketFuzzer.enabled) {
            // Do not wait for new events
            break;
        }
    }

    if (run->global->sanitizer.enable) {
        pid_t ptracePid = (run->global->netbsd.pid > 0) ? run->global->netbsd.pid : run->pid;
        char crashReport[PATH_MAX];
        snprintf(crashReport, sizeof(crashReport), "%s/%s.%d", run->global->io.workDir, kLOGPREFIX,
            ptracePid);
        if (files_exists(crashReport)) {
            if (run->backtrace) {
                unlink(crashReport);
            } else {
                LOG_W("Un-handled ASan report due to compiler-rt internal error - retry with '%s'",
                    crashReport);
                /* Try to parse report file */
                arch_traceExitAnalyze(run, ptracePid);
            }
        }
    }

    sancov_Analyze(run);
}

bool arch_archInit(honggfuzz_t* hfuzz) {
    /* Make %'d work */
    setlocale(LC_NUMERIC, "en_US.UTF-8");

    if (access(hfuzz->exe.cmdline[0], X_OK) == -1) {
        PLOG_E("File '%s' doesn't seem to be executable", hfuzz->exe.cmdline[0]);
        return false;
    }

    /*
     * Set the bitmask (once) of interesting signals, that this thread will be waiting for
     * (with sigsuspend). Do it once here, to save precious CPU cycles, as this cannot be
     * a statically initialized const variable
     */
    sigemptyset(&hfuzz->netbsd.waitSigSet);
    sigaddset(&hfuzz->netbsd.waitSigSet, SIGIO);
    sigaddset(&hfuzz->netbsd.waitSigSet, SIGCHLD);

    /* If remote pid, resolve command using procfs */
    if (hfuzz->netbsd.pid > 0) {
        char procCmd[PATH_MAX] = {0};
        snprintf(procCmd, sizeof(procCmd), "/proc/%d/cmdline", hfuzz->netbsd.pid);

        ssize_t sz = files_readFileToBufMax(
            procCmd, (uint8_t*)hfuzz->netbsd.pidCmd, sizeof(hfuzz->netbsd.pidCmd) - 1);
        if (sz < 1) {
            LOG_E("Couldn't read '%s'", procCmd);
            return false;
        }

        /* Make human readable */
        for (size_t i = 0; i < ((size_t)sz - 1); i++) {
            if (hfuzz->netbsd.pidCmd[i] == '\0') {
                hfuzz->netbsd.pidCmd[i] = ' ';
            }
        }
        hfuzz->netbsd.pidCmd[sz] = '\0';
    }

    /* Updates the important signal array based on input args */
    arch_traceSignalsInit(hfuzz);

    /*
     * If sanitizer fuzzing enabled and SIGABRT is monitored (abort_on_error=1),
     * increase number of major frames, since top 7-9 frames will be occupied
     * with sanitizer runtime library & libc symbols
     */
    if (hfuzz->sanitizer.enable && hfuzz->cfg.monitorSIGABRT) {
        hfuzz->netbsd.numMajorFrames = 14;
    }

    return true;
}

bool arch_archThreadInit(run_t* run) {
    run->netbsd.perfMmapBuf = NULL;
    run->netbsd.perfMmapAux = NULL;
    run->netbsd.cpuInstrFd = -1;
    run->netbsd.cpuBranchFd = -1;
    run->netbsd.cpuIptBtsFd = -1;

    return true;
}
