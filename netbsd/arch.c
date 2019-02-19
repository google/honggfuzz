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
#include "subproc.h"

extern char** environ;

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
    if (!arch_traceAttach(run)) {
        LOG_F("Couldn't attach to pid=%d", (int)run->pid);
    }
}

void arch_prepareParent(run_t* run HF_ATTR_UNUSED) {
}

static bool arch_checkWait(run_t* run) {
    /* All queued wait events must be tested when SIGCHLD was delivered */
    for (;;) {
        int status;
        /* Wait for the whole process group of run->pid */
        pid_t pid = TEMP_FAILURE_RETRY(wait6(P_SID, run->pid, &status,
            WALLSIG | WALTSIG | WTRAPPED | WEXITED | WUNTRACED | WCONTINUED | WSTOPPED | WNOHANG,
            NULL, NULL));
        if (pid == 0) {
            return false;
        }
        if (pid == -1 && errno == ECHILD) {
            LOG_D("No more processes to track");
            return true;
        }
        if (pid == -1) {
            PLOG_F("wait6(pid/session=%d) failed", (int)run->pid);
        }

        arch_traceAnalyze(run, status, pid);

        char statusStr[4096];
        LOG_D("pid=%d returned with status: %s", pid,
            subproc_StatusToStr(status, statusStr, sizeof(statusStr)));

        if (pid == run->pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            if (run->global->exe.persistent) {
                if (!fuzz_isTerminating()) {
                    LOG_W("Persistent mode: PID %d exited with status: %s", pid,
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

        if (run->global->exe.persistent) {
            struct pollfd pfd = {
                .fd = run->persistentSock,
                .events = POLLIN,
            };
            int r = poll(&pfd, 1, 250 /* 0.25s */);
            if (r == -1 && errno != EINTR) {
                PLOG_F("poll(fd=%d)", run->persistentSock);
            }
        } else {
            /* Return with SIGIO, SIGCHLD and with SIGUSR1 */
            const struct timespec ts = {
                .tv_sec = 0ULL,
                .tv_nsec = (1000ULL * 1000ULL * 250ULL),
            };
            int sig = sigtimedwait(&run->global->exe.waitSigSet, NULL, &ts /* 0.25s */);
            if (sig == -1 && (errno != EAGAIN && errno != EINTR)) {
                PLOG_F("sigtimedwait(SIGIO|SIGCHLD|SIGUSR1)");
            }
        }

        if (arch_checkWait(run)) {
            run->pid = 0;
            break;
        }
    }
}

bool arch_archInit(honggfuzz_t* hfuzz) {
    /* Make %'d work */
    setlocale(LC_NUMERIC, "en_US.UTF-8");

    if (access(hfuzz->exe.cmdline[0], X_OK) == -1) {
        PLOG_E("File '%s' doesn't seem to be executable", hfuzz->exe.cmdline[0]);
        return false;
    }

    /* Updates the important signal array based on input args */
    arch_traceSignalsInit(hfuzz);

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
