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

#include "common.h"
#include "subproc.h"

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
#include "files.h"
#include "log.h"
#include "sancov.h"
#include "util.h"

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
    if (files_writeToFd(fuzzer->persistentSock, (uint8_t *) & len, sizeof(len)) == false) {
        return false;
    }
    if (files_writeToFd(fuzzer->persistentSock, fuzzer->dynamicFile, fuzzer->dynamicFileSz) ==
        false) {
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
    if (sancov_prepareExecve(hfuzz) == false) {
        LOG_E("sancov_prepareExecve() failed");
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

    return true;
}

static bool subproc_New(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    fuzzer->pid = fuzzer->persistentPid;
    if (fuzzer->pid != 0) {
        return true;
    }

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
        PLOG_F("Couldn't fork");
    }
    // Child
    if (!fuzzer->pid) {
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
            LOG_E("Error launching child process");
            exit(EXIT_FAILURE);
        }

        abort();
    }
    // Parent
    LOG_D("Launched new process, pid: %d, (concurrency: %zd)", fuzzer->pid, hfuzz->threadsMax);

    if (hfuzz->persistent) {
        close(sv[1]);
        LOG_I("Persistent mode: Launched new persistent PID: %d", (int)fuzzer->pid);
        fuzzer->persistentPid = fuzzer->pid;
    }

    return true;
}

bool subproc_Run(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (subproc_New(hfuzz, fuzzer) == false) {
        LOG_E("subproc_New()");
        return false;
    }

    arch_prepareChild(hfuzz, fuzzer);
    if (hfuzz->persistent == true && subproc_persistentSendFile(fuzzer) == false) {
        LOG_W("Could not send file contents to the persistent process");
    }
    arch_reapChild(hfuzz, fuzzer);

    return true;
}

uint8_t subproc_System(const char *const argv[])
{
    pid_t pid = fork();
    if (pid == -1) {
        PLOG_E("Couldn't fork");
        return 255;
    }

    if (!pid) {
        execv(argv[0], (char *const *)&argv[0]);
        PLOG_F("Couldn't execute '%s'", argv[0]);
        return 255;
    }

    int status;
    int flags = 0;
#if defined(__WNOTHREAD)
    flags |= __WNOTHREAD;
#endif                          /* defined(__WNOTHREAD) */
    while (wait4(pid, &status, flags, NULL) != pid) ;
    if (WIFSIGNALED(status)) {
        LOG_E("Command '%s' terminated with signal: %d", argv[0], WTERMSIG(status));
        return (100 + WTERMSIG(status));
    }
    if (!WIFEXITED(status)) {
        LOG_F("Command '%s' terminated abnormally, status: %d", argv[0], status);
        return 100;
    }

    LOG_D("Command '%s' exited with: %d", argv[0], WEXITSTATUS(status));

    if (WEXITSTATUS(status)) {
        LOG_W("Command '%s' exited with code: %d", argv[0], WEXITSTATUS(status));
        return 1U;
    }

    return 0U;
}

void subproc_checkTimeLimit(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->tmOut == 0) {
        return;
    }

    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - fuzzer->timeStartedMillis;
    if (diffMillis > (hfuzz->tmOut * 1000)) {
        LOG_W("PID %d took too much time (limit %ld s). Sending SIGKILL",
              fuzzer->pid, hfuzz->tmOut);
        kill(fuzzer->pid, SIGKILL);
        ATOMIC_POST_INC(hfuzz->timeoutedCnt);
    }
}
