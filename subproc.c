/*
 *
 * honggfuzz - routines dealing with subprocesses
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
 * Felix Gröbert <groebert@google.com>
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

#include "subproc.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arch.h"
#include "fuzz.h"
#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/util.h"
#include "sanitizers.h"

extern char** environ;

const char* subproc_StatusToStr(int status, char* str, size_t len) {
    if (WIFEXITED(status)) {
        snprintf(str, len, "EXITED, exit code: %d", WEXITSTATUS(status));
        return str;
    }

    if (WIFSIGNALED(status)) {
        snprintf(
            str, len, "SIGNALED, signal: %d (%s)", WTERMSIG(status), strsignal(WTERMSIG(status)));
        return str;
    }
    if (WIFCONTINUED(status)) {
        snprintf(str, len, "CONTINUED");
        return str;
    }

    if (!WIFSTOPPED(status)) {
        snprintf(str, len, "UNKNOWN STATUS: %d", status);
        return str;
    }

    /* Must be in a stopped state */
    if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        snprintf(str, len, "STOPPED (linux syscall): %d (%s)", WSTOPSIG(status),
            strsignal(WSTOPSIG(status)));
        return str;
    }
#if defined(PTRACE_EVENT_STOP)
#define __LINUX_WPTRACEEVENT(x) ((x & 0xff0000) >> 16)
    if (WSTOPSIG(status) == SIGTRAP && __LINUX_WPTRACEEVENT(status) != 0) {
        switch (__LINUX_WPTRACEEVENT(status)) {
            case PTRACE_EVENT_FORK:
                snprintf(str, len, "EVENT (Linux) - fork - with signal: %d (%s)", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_VFORK:
                snprintf(str, len, "EVENT (Linux) - vfork - with signal: %d (%s)", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_CLONE:
                snprintf(str, len, "EVENT (Linux) - clone - with signal: %d (%s)", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_EXEC:
                snprintf(str, len, "EVENT (Linux) - exec - with signal: %d (%s)", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_VFORK_DONE:
                snprintf(str, len, "EVENT (Linux) - vfork_done - with signal: %d (%s)",
                    WSTOPSIG(status), strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_EXIT:
                snprintf(str, len, "EVENT (Linux) - exit - with signal: %d (%s)", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_SECCOMP:
                snprintf(str, len, "EVENT (Linux) - seccomp - with signal: %d (%s)",
                    WSTOPSIG(status), strsignal(WSTOPSIG(status)));
                return str;
            case PTRACE_EVENT_STOP:
                snprintf(str, len, "EVENT (Linux) - stop - with signal: %d (%s)", WSTOPSIG(status),
                    strsignal(WSTOPSIG(status)));
                return str;
            default:
                snprintf(str, len, "EVENT (Linux) UNKNOWN (%d): with signal: %d (%s)",
                    __LINUX_WPTRACEEVENT(status), WSTOPSIG(status), strsignal(WSTOPSIG(status)));
                return str;
        }
    }
#endif /*  defined(PTRACE_EVENT_STOP)  */

    snprintf(
        str, len, "STOPPED with signal: %d (%s)", WSTOPSIG(status), strsignal(WSTOPSIG(status)));
    return str;
}

bool subproc_persistentModeRoundDone(run_t* run) {
    if (!run->global->persistent) {
        return false;
    }
    char z;
    if (recv(run->persistentSock, &z, sizeof(z), MSG_DONTWAIT) == sizeof(z)) {
        LOG_D("Persistent mode round finished");
        return true;
    }
    return false;
}

static bool subproc_persistentSendFile(run_t* run) {
    uint32_t len = (uint64_t)run->dynamicFileSz;
    if (!files_sendToSocketNB(run->persistentSock, (uint8_t*)&len, sizeof(len))) {
        PLOG_W("files_sendToSocketNB(len=%zu)", sizeof(len));
        return false;
    }
    if (!files_sendToSocketNB(run->persistentSock, run->dynamicFile, run->dynamicFileSz)) {
        PLOG_W("files_sendToSocketNB(len=%zu)", run->dynamicFileSz);
        return false;
    }
    return true;
}

bool subproc_PrepareExecv(run_t* run, const char* fileName) {
    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (run->global->exe.asLimit) {
        struct rlimit rl = {
            .rlim_cur = run->global->exe.asLimit * 1024ULL * 1024ULL,
            .rlim_max = run->global->exe.asLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_AS, &rl) == -1) {
            PLOG_W("Couldn't enforce the RLIMIT_AS resource limit, ignoring");
        }
    }
#if defined(RLIMIT_RSS)
    if (run->global->exe.rssLimit) {
        struct rlimit rl = {
            .rlim_cur = run->global->exe.rssLimit * 1024ULL * 1024ULL,
            .rlim_max = run->global->exe.rssLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_RSS, &rl) == -1) {
            PLOG_W("Couldn't enforce the RLIMIT_RSS resource limit, ignoring");
        }
    }
#endif /* defined(RLIMIT_RSS) */
    if (run->global->exe.dataLimit) {
        struct rlimit rl = {
            .rlim_cur = run->global->exe.dataLimit * 1024ULL * 1024ULL,
            .rlim_max = run->global->exe.dataLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_DATA, &rl) == -1) {
            PLOG_W("Couldn't enforce the RLIMIT_DATA resource limit, ignoring");
        }
    }

    if (run->global->exe.nullifyStdio) {
        util_nullifyStdio();
    }

    if (run->global->exe.fuzzStdin) {
        /*
         * Uglyyyyyy ;)
         */
        if (!util_redirectStdin(fileName)) {
            return false;
        }
    }

    if (run->global->exe.clearEnv) {
        environ = NULL;
    }
    if (!sanitizers_prepareExecve(run)) {
        LOG_E("sanitizers_prepareExecve() failed");
        return false;
    }
    for (size_t i = 0; i < ARRAYSIZE(run->global->exe.envs) && run->global->exe.envs[i]; i++) {
        putenv(run->global->exe.envs[i]);
    }
    char fuzzNo[128];
    snprintf(fuzzNo, sizeof(fuzzNo), "%" PRId32, run->fuzzNo);
    setenv(_HF_THREAD_NO_ENV, fuzzNo, 1);

    setsid();

    if (run->global->bbFd != -1) {
        if (dup2(run->global->bbFd, _HF_BITMAP_FD) == -1) {
            PLOG_F("dup2('%d', %d)", run->global->bbFd, _HF_BITMAP_FD);
        }
        close(run->global->bbFd);
    }

    sigset_t sset;
    sigemptyset(&sset);
    if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
        PLOG_W("sigprocmask(empty_set)");
    }

    return true;
}

static bool subproc_New(run_t* run) {
    run->pid = run->persistentPid;
    if (run->pid != 0) {
        return true;
    }
    run->tmOutSignaled = false;

    int sv[2];
    if (run->global->persistent) {
        if (run->persistentSock != -1) {
            close(run->persistentSock);
        }

        int sock_type = SOCK_STREAM;
#if defined(SOCK_CLOEXEC)
        sock_type |= SOCK_CLOEXEC;
#endif
        if (socketpair(AF_UNIX, sock_type, 0, sv) == -1) {
            PLOG_W("socketpair(AF_UNIX, SOCK_STREAM, 0, sv)");
            return false;
        }
        run->persistentSock = sv[0];
    }

    run->pid = arch_fork(run);
    if (run->pid == -1) {
        PLOG_E("Couldn't fork");
        return false;
    }
    /* The child process */
    if (!run->pid) {
        logMutexReset();
        /*
         * Reset sighandlers, and set alarm(1). It's a guarantee against dead-locks
         * in the child, where we ensure here that the child process will either
         * execve or get signaled by SIGALRM within 1 second.
         *
         * Those deadlocks typically stem from the fact, that malloc() can behave weirdly
         * when fork()-ing a single thread of a process: e.g. with glibc < 2.24
         * (or, Ubuntu's 2.23-0ubuntu6). For more see
         * http://changelogs.ubuntu.com/changelogs/pool/main/g/glibc/glibc_2.23-0ubuntu7/changelog
         */
        alarm(1);
        signal(SIGALRM, SIG_DFL);

        if (run->global->persistent) {
            if (dup2(sv[1], _HF_PERSISTENT_FD) == -1) {
                PLOG_F("dup2('%d', '%d')", sv[1], _HF_PERSISTENT_FD);
            }
            close(sv[0]);
            close(sv[1]);
        }

        if (!subproc_PrepareExecv(run, run->fileName)) {
            LOG_E("subproc_PrepareExecv() failed");
            exit(EXIT_FAILURE);
        }
        if (!arch_launchChild(run)) {
            LOG_E("Error launching child process");
            kill(run->global->threads.mainPid, SIGTERM);
            _exit(1);
        }
        abort();
    }

    /* Parent */
    LOG_D("Launched new process, pid: %d, (concurrency: %zd)", run->pid,
        run->global->threads.threadsMax);

    if (run->global->persistent) {
        close(sv[1]);
        LOG_I("Persistent mode: Launched new persistent PID: %d", (int)run->pid);
        run->persistentPid = run->pid;

        int sndbuf = run->global->maxFileSz + 256;
        if (setsockopt(run->persistentSock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
            LOG_W("Couldn't set FD send buffer to '%d' bytes", sndbuf);
        }
    }

    arch_prepareParentAfterFork(run);

    return true;
}

bool subproc_Run(run_t* run) {
    if (!subproc_New(run)) {
        LOG_E("subproc_New()");
        return false;
    }

    arch_prepareParent(run);
    if (run->global->persistent && !subproc_persistentSendFile(run)) {
        LOG_W("Could not send file contents to the persistent process");
        kill(run->persistentPid, SIGKILL);
    }
    arch_reapChild(run);

    return true;
}

uint8_t subproc_System(run_t* run, const char* const argv[]) {
    pid_t pid = arch_fork(run);
    if (pid == -1) {
        PLOG_E("Couldn't fork");
        return 255;
    }
    if (!pid) {
        logMutexReset();

        sigset_t sset;
        sigemptyset(&sset);
        if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
            PLOG_W("sigprocmask(empty_set)");
        }

        execv(argv[0], (char* const*)&argv[0]);
        PLOG_F("Couldn't execute '%s'", argv[0]);
        return 255;
    }

    int status;
    int flags = 0;
#if defined(__WNOTHREAD)
    flags |= __WNOTHREAD;
#endif /* defined(__WNOTHREAD) */

    for (;;) {
        int ret = wait4(pid, &status, flags, NULL);
        if (ret == -1 && errno == EINTR) {
            continue;
        }
        if (ret == -1) {
            PLOG_E("wait4() for process PID: %d", (int)pid);
            return 255;
        }
        if (ret != pid) {
            LOG_E("wait4() returned %d, but waited for %d", ret, (int)pid);
            return 255;
        }
        if (WIFSIGNALED(status)) {
            LOG_E("Command '%s' terminated with signal: %d", argv[0], WTERMSIG(status));
            return (100 + WTERMSIG(status));
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0) {
                return 0U;
            }
            LOG_E("Command '%s' returned with exit code %d", argv[0], WEXITSTATUS(status));
            return 1U;
        }

        LOG_D("wait4() returned with status: %d", status);
    }
}

void subproc_checkTimeLimit(run_t* run) {
    if (run->global->timing.tmOut == 0) {
        return;
    }

    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - run->timeStartedMillis;

    if (run->tmOutSignaled && (diffMillis > ((run->global->timing.tmOut + 1) * 1000))) {
        /* Has this instance been already signaled due to timeout? Just, SIGKILL it */
        LOG_W("PID %d has already been signaled due to timeout. Killing it with SIGKILL", run->pid);
        kill(run->pid, SIGKILL);
        return;
    }

    if ((diffMillis > (run->global->timing.tmOut * 1000)) && !run->tmOutSignaled) {
        run->tmOutSignaled = true;
        LOG_W("PID %d took too much time (limit %ld s). Killing it with %s", run->pid,
            run->global->timing.tmOut, run->global->timing.tmoutVTALRM ? "SIGVTALRM" : "SIGKILL");
        if (run->global->timing.tmoutVTALRM) {
            kill(run->pid, SIGVTALRM);
        } else {
            kill(run->pid, SIGKILL);
        }
        ATOMIC_POST_INC(run->global->cnts.timeoutedCnt);
    }
}

void subproc_checkTermination(run_t* run) {
    if (fuzz_isTerminating()) {
        LOG_D("Killing PID: %d", (int)run->pid);
        kill(run->pid, SIGKILL);
    }
}
