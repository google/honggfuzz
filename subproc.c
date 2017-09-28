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
#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/util.h"
#include "sanitizers.h"

extern char **environ;

const char *subproc_StatusToStr(int status, char *str, size_t len)
{
    if (WIFEXITED(status)) {
        snprintf(str, len, "EXITED, exit code: %d", WEXITSTATUS(status));
        return str;
    }

    if (WIFSIGNALED(status)) {
        snprintf(str, len, "SIGNALED, signal: %d (%s)", WTERMSIG(status),
                 strsignal(WTERMSIG(status)));
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
            snprintf(str, len, "EVENT (Linux) - seccomp - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
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
#endif                          /*  defined(PTRACE_EVENT_STOP)  */

    snprintf(str, len, "STOPPED with signal: %d (%s)", WSTOPSIG(status),
             strsignal(WSTOPSIG(status)));
    return str;
}

bool subproc_persistentModeRoundDone(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->persistent == false) {
        return false;
    }
    char z;
    if (recv(fuzzer->persistentSock, &z, sizeof(z), MSG_DONTWAIT) == sizeof(z)) {
        LOG_D("Persistent mode round finished");
        return true;
    }
    return false;
}

static bool subproc_persistentSendFile(fuzzer_t * fuzzer)
{
    uint32_t len = (uint64_t) fuzzer->dynamicFileSz;
    if (files_sendToSocketNB(fuzzer->persistentSock, (uint8_t *) & len, sizeof(len)) == false) {
        PLOG_W("files_sendToSocketNB(len=%zu)", sizeof(len));
        return false;
    }
    if (files_sendToSocketNB(fuzzer->persistentSock, fuzzer->dynamicFile, fuzzer->dynamicFileSz) ==
        false) {
        PLOG_W("files_sendToSocketNB(len=%zu)", fuzzer->dynamicFileSz);
        return false;
    }
    return true;
}

bool subproc_PrepareExecv(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, const char *fileName)
{
    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (hfuzz->asLimit) {
        struct rlimit rl = {
            .rlim_cur = hfuzz->asLimit * 1024ULL * 1024ULL,
            .rlim_max = hfuzz->asLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_AS, &rl) == -1) {
            PLOG_D("Couldn't enforce the RLIMIT_AS resource limit, ignoring");
        }
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

    if (hfuzz->clearEnv) {
        environ = NULL;
    }
    if (sanitizers_prepareExecve(hfuzz) == false) {
        LOG_E("sanitizers_prepareExecve() failed");
        return false;
    }
    for (size_t i = 0; i < ARRAYSIZE(hfuzz->envs) && hfuzz->envs[i]; i++) {
        putenv(hfuzz->envs[i]);
    }
    char fuzzNo[128];
    snprintf(fuzzNo, sizeof(fuzzNo), "%" PRId32, fuzzer->fuzzNo);
    setenv(_HF_THREAD_NO_ENV, fuzzNo, 1);

    setsid();

    if (hfuzz->bbFd != -1) {
        if (dup2(hfuzz->bbFd, _HF_BITMAP_FD) == -1) {
            PLOG_F("dup2('%d', %d)", hfuzz->bbFd, _HF_BITMAP_FD);
        }
        close(hfuzz->bbFd);
    }

    sigset_t sset;
    sigemptyset(&sset);
    if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
        PLOG_W("sigprocmask(empty_set)");
    }

    return true;
}

static bool subproc_New(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    fuzzer->pid = fuzzer->persistentPid;
    if (fuzzer->pid != 0) {
        return true;
    }
    fuzzer->tmOutSignaled = false;

    int sv[2];
    if (hfuzz->persistent) {
        if (fuzzer->persistentSock != -1) {
            close(fuzzer->persistentSock);
        }

        int sock_type = SOCK_STREAM;
#if defined(SOCK_CLOEXEC)
        sock_type |= SOCK_CLOEXEC;
#endif
        if (socketpair(AF_UNIX, sock_type, 0, sv) == -1) {
            PLOG_W("socketpair(AF_UNIX, SOCK_STREAM, 0, sv)");
            return false;
        }
        fuzzer->persistentSock = sv[0];
    }

    fuzzer->pid = arch_fork(hfuzz, fuzzer);
    if (fuzzer->pid == -1) {
        PLOG_E("Couldn't fork");
        return false;
    }
    /* The child process */
    if (!fuzzer->pid) {
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
        sigset_t sset;
        sigemptyset(&sset);
        if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
            perror("sigprocmask");
            _exit(1);
        }

        if (hfuzz->persistent) {
            if (dup2(sv[1], _HF_PERSISTENT_FD) == -1) {
                PLOG_F("dup2('%d', '%d')", sv[1], _HF_PERSISTENT_FD);
            }
            close(sv[0]);
            close(sv[1]);
        }

        if (!subproc_PrepareExecv(hfuzz, fuzzer, fuzzer->fileName)) {
            LOG_E("subproc_PrepareExecv() failed");
            exit(EXIT_FAILURE);
        }
        if (!arch_launchChild(hfuzz, fuzzer->fileName)) {
            kill(hfuzz->mainPid, SIGTERM);
            LOG_E("Error launching child process");
            _exit(1);
        }
        abort();
    }

    /* Parent */
    LOG_D("Launched new process, pid: %d, (concurrency: %zd)", fuzzer->pid, hfuzz->threadsMax);

    if (hfuzz->persistent) {
        close(sv[1]);
        LOG_I("Persistent mode: Launched new persistent PID: %d", (int)fuzzer->pid);
        fuzzer->persistentPid = fuzzer->pid;

        int sndbuf = hfuzz->maxFileSz + 256;
        if (setsockopt(fuzzer->persistentSock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) ==
            -1) {
            LOG_W("Couldn't set FD send buffer to '%d' bytes", sndbuf);
        }
    }

    arch_prepareParentAfterFork(hfuzz, fuzzer);

    return true;
}

bool subproc_Run(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (subproc_New(hfuzz, fuzzer) == false) {
        LOG_E("subproc_New()");
        return false;
    }

    arch_prepareParent(hfuzz, fuzzer);
    if (hfuzz->persistent == true && subproc_persistentSendFile(fuzzer) == false) {
        LOG_W("Could not send file contents to the persistent process");
        kill(fuzzer->persistentPid, SIGKILL);
    }
    arch_reapChild(hfuzz, fuzzer);

    return true;
}

uint8_t subproc_System(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, const char *const argv[])
{
    pid_t pid = arch_fork(hfuzz, fuzzer);
    if (pid == -1) {
        PLOG_E("Couldn't fork");
        return 255;
    }
    if (!pid) {
        logMutexReset();
        execv(argv[0], (char *const *)&argv[0]);
        PLOG_F("Couldn't execute '%s'", argv[0]);
        return 255;
    }

    int status;
    int flags = 0;
#if defined(__WNOTHREAD)
    flags |= __WNOTHREAD;
#endif                          /* defined(__WNOTHREAD) */

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

void subproc_checkTimeLimit(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->tmOut == 0) {
        return;
    }

    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - fuzzer->timeStartedMillis;

    if (fuzzer->tmOutSignaled && (diffMillis > ((hfuzz->tmOut + 1) * 1000))) {
        /* Has this instance been already signaled due to timeout? Just, SIGKILL it */
        LOG_W("PID %d has already been signaled due to timeout. Killing it with SIGKILL",
              fuzzer->pid);
        kill(fuzzer->pid, SIGKILL);
        return;
    }

    if ((diffMillis > (hfuzz->tmOut * 1000)) && fuzzer->tmOutSignaled == false) {
        fuzzer->tmOutSignaled = true;
        LOG_W("PID %d took too much time (limit %ld s). Killing it with %s", fuzzer->pid,
              hfuzz->tmOut, hfuzz->tmout_vtalrm ? "SIGVTALRM" : "SIGKILL");
        if (hfuzz->tmout_vtalrm) {
            kill(fuzzer->pid, SIGVTALRM);
        } else {
            kill(fuzzer->pid, SIGKILL);
        }
        ATOMIC_POST_INC(hfuzz->timeoutedCnt);
    }
}

void subproc_checkTermination(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (ATOMIC_GET(hfuzz->terminating)) {
        LOG_D("Killing PID: %d", (int)fuzzer->pid);
        kill(fuzzer->pid, SIGKILL);
    }
}
