/*
 *
 * honggfuzz - routines dealing with subprocesses
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *         Felix Gröbert <groebert@google.com>
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
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

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

static bool subproc_persistentSendFileIndicator(run_t* run) {
    uint64_t len = (uint64_t)run->dynamicFileSz;
    if (!files_sendToSocketNB(run->persistentSock, (uint8_t*)&len, sizeof(len))) {
        PLOG_W("files_sendToSocketNB(len=%zu)", sizeof(len));
        return false;
    }
    return true;
}

static bool subproc_persistentGetReady(run_t* run) {
    uint8_t rcv;
    if (recv(run->persistentSock, &rcv, sizeof(rcv), MSG_DONTWAIT) != sizeof(rcv)) {
        return false;
    }
    if (rcv != HFReadyTag) {
        LOG_E("Received invalid message from the persistent process: '%c' (0x%" PRIx8
              ") , expected '%c' (0x%" PRIx8 ")",
            rcv, rcv, HFReadyTag, HFReadyTag);
        return false;
    }
    return true;
}

bool subproc_persistentModeStateMachine(run_t* run) {
    if (!run->global->exe.persistent) {
        return false;
    }

    for (;;) {
        switch (run->runState) {
            case _HF_RS_WAITING_FOR_INITIAL_READY: {
                if (!subproc_persistentGetReady(run)) {
                    return false;
                }
                run->runState = _HF_RS_SEND_DATA;
            }; break;
            case _HF_RS_SEND_DATA: {
                if (!subproc_persistentSendFileIndicator(run)) {
                    LOG_E("Could not send the file size indicator to the persistent process. "
                          "Killing the process pid=%d",
                        (int)run->pid);
                    kill(run->pid, SIGKILL);
                    return false;
                }
                run->runState = _HF_RS_WAITING_FOR_READY;
            }; break;
            case _HF_RS_WAITING_FOR_READY: {
                if (!subproc_persistentGetReady(run)) {
                    return false;
                }
                run->runState = _HF_RS_SEND_DATA;
                /* The current persistent round is done */
                return true;
            }; break;
            default:
                LOG_F("Unknown runState: %d", run->runState);
        }
    }
}

static bool subproc_PrepareExecv(run_t* run) {
    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
#ifdef RLIMIT_AS
    if (run->global->exe.asLimit) {
        const struct rlimit rl = {
            .rlim_cur = run->global->exe.asLimit * 1024ULL * 1024ULL,
            .rlim_max = run->global->exe.asLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_AS, &rl) == -1) {
            PLOG_W("Couldn't enforce the RLIMIT_AS resource limit, ignoring");
        }
    }
#endif /* ifdef RLIMIT_AS */
#ifdef RLIMIT_RSS
    if (run->global->exe.rssLimit) {
        const struct rlimit rl = {
            .rlim_cur = run->global->exe.rssLimit * 1024ULL * 1024ULL,
            .rlim_max = run->global->exe.rssLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_RSS, &rl) == -1) {
            PLOG_W("Couldn't enforce the RLIMIT_RSS resource limit, ignoring");
        }
    }
#endif /* ifdef RLIMIT_RSS */
#ifdef RLIMIT_DATA
    if (run->global->exe.dataLimit) {
        const struct rlimit rl = {
            .rlim_cur = run->global->exe.dataLimit * 1024ULL * 1024ULL,
            .rlim_max = run->global->exe.dataLimit * 1024ULL * 1024ULL,
        };
        if (setrlimit(RLIMIT_DATA, &rl) == -1) {
            PLOG_W("Couldn't enforce the RLIMIT_DATA resource limit, ignoring");
        }
    }
#endif /* ifdef RLIMIT_DATA */
#ifdef RLIMIT_CORE
    const struct rlimit rl = {
        .rlim_cur = run->global->exe.coreLimit * 1024ULL * 1024ULL,
        .rlim_max = run->global->exe.coreLimit * 1024ULL * 1024ULL,
    };
    if (setrlimit(RLIMIT_CORE, &rl) == -1) {
        PLOG_W("Couldn't enforce the RLIMIT_CORE resource limit, ignoring");
    }
#endif /* ifdef RLIMIT_CORE */

    if (run->global->exe.clearEnv) {
        environ = NULL;
    }
    for (size_t i = 0; i < ARRAYSIZE(run->global->exe.envs) && run->global->exe.envs[i]; i++) {
        putenv(run->global->exe.envs[i]);
    }
    char fuzzNo[128];
    snprintf(fuzzNo, sizeof(fuzzNo), "%" PRId32, run->fuzzNo);
    setenv(_HF_THREAD_NO_ENV, fuzzNo, 1);
    if (run->global->exe.netDriver) {
        setenv(_HF_THREAD_NETDRIVER_ENV, "1", 1);
    }

    /* Make sure it's a new process group / session, so waitpid can wait for -(run->pid) */
    setsid();

    util_closeStdio(/* close_stdin= */ run->global->exe.nullifyStdio,
        /* close_stdout= */ run->global->exe.nullifyStdio,
        /* close_stderr= */ run->global->exe.nullifyStdio);

    /* The bitmap structure */
    if (run->global->feedback.bbFd != -1 &&
        TEMP_FAILURE_RETRY(dup2(run->global->feedback.bbFd, _HF_BITMAP_FD)) == -1) {
        PLOG_E("dup2(%d, _HF_BITMAP_FD=%d)", run->global->feedback.bbFd, _HF_BITMAP_FD);
        return false;
    }

    /* The input file to _HF_INPUT_FD */
    if (run->global->exe.persistent &&
        TEMP_FAILURE_RETRY(dup2(run->dynamicFileFd, _HF_INPUT_FD)) == -1) {
        PLOG_E("dup2('%d', _HF_INPUT_FD='%d')", run->dynamicFileFd, _HF_INPUT_FD);
        return false;
    }

    /* The log FD */
    if ((run->global->exe.netDriver || run->global->exe.persistent)) {
        if (TEMP_FAILURE_RETRY(dup2(logFd(), _HF_LOG_FD)) == -1) {
            PLOG_E("dup2(%d, _HF_LOG_FD=%d)", logFd(), _HF_LOG_FD);
            return false;
        }
        char llstr[32];
        snprintf(llstr, sizeof(llstr), "%d", logGetLevel());
        setenv(_HF_LOG_LEVEL_ENV, llstr, 1);
    }

    sigset_t sset;
    sigemptyset(&sset);
    if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
        PLOG_W("sigprocmask(empty_set)");
    }

    if (!run->global->exe.persistent) {
        if ((run->dynamicFileCopyFd = files_writeBufToTmpFile(
                 run->global->io.workDir, run->dynamicFile, run->dynamicFileSz, 0)) == -1) {
            LOG_E("Couldn't save data to a temporary file");
            return false;
        }
        if (run->global->exe.fuzzStdin &&
            TEMP_FAILURE_RETRY(dup2(run->dynamicFileCopyFd, STDIN_FILENO)) == -1) {
            PLOG_E("dup2(_HF_INPUT_FD=%d, STDIN_FILENO=%d)", run->dynamicFileCopyFd, STDIN_FILENO);
            return false;
        }
    }

    return true;
}

static bool subproc_New(run_t* run) {
    if (run->pid) {
        return true;
    }

    int sv[2];
    if (run->global->exe.persistent) {
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

    LOG_D("Forking new process for thread: %" PRId32, run->fuzzNo);

    run->pid = arch_fork(run);
    if (run->pid == -1) {
        PLOG_E("Couldn't fork");
        run->pid = 0;
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

        if (run->global->exe.persistent) {
            if (TEMP_FAILURE_RETRY(dup2(sv[1], _HF_PERSISTENT_FD)) == -1) {
                PLOG_F("dup2('%d', '%d')", sv[1], _HF_PERSISTENT_FD);
            }
            close(sv[0]);
            close(sv[1]);
        }

        if (!subproc_PrepareExecv(run)) {
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
    LOG_D("Launched new process, pid=%d, thread: %" PRId32 " (concurrency: %zd)", (int)run->pid,
        run->fuzzNo, run->global->threads.threadsMax);

    arch_prepareParentAfterFork(run);

    if (run->global->exe.persistent) {
        close(sv[1]);
        run->runState = _HF_RS_WAITING_FOR_INITIAL_READY;
        LOG_I("Persistent mode: Launched new persistent pid=%d", (int)run->pid);
    }

    return true;
}

bool subproc_Run(run_t* run) {
    run->timeStartedMillis = util_timeNowMillis();

    if (!subproc_New(run)) {
        LOG_E("subproc_New()");
        return false;
    }

    arch_prepareParent(run);
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

        setsid();
        util_closeStdio(
            /* close_stdin= */ true, /* close_stdout= */ false, /* close_stderr= */ false);

        sigset_t sset;
        sigemptyset(&sset);
        if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1) {
            PLOG_W("sigprocmask(empty_set)");
        }

        execv(argv[0], (char* const*)&argv[0]);
        PLOG_F("Couldn't execute '%s'", argv[0]);
        return 255;
    }

    int flags = 0;
#if defined(__WNOTHREAD)
    flags |= __WNOTHREAD;
#endif /* defined(__WNOTHREAD) */
#if defined(__WALL)
    flags |= __WALL;
#endif /* defined(__WALL) */

    for (;;) {
        int status;
        int ret = TEMP_FAILURE_RETRY(wait4(pid, &status, flags, NULL));
        if (ret == -1) {
            PLOG_E("wait4() for process pid=%d", (int)pid);
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
    if (!run->global->timing.tmOut) {
        return;
    }

    int64_t curMillis = util_timeNowMillis();
    int64_t diffMillis = curMillis - run->timeStartedMillis;

    if (run->tmOutSignaled && (diffMillis > ((run->global->timing.tmOut + 1) * 1000))) {
        /* Has this instance been already signaled due to timeout? Just, SIGKILL it */
        LOG_W("pid=%d has already been signaled due to timeout. Killing it with SIGKILL", run->pid);
        kill(run->pid, SIGKILL);
        return;
    }

    if ((diffMillis > (run->global->timing.tmOut * 1000)) && !run->tmOutSignaled) {
        run->tmOutSignaled = true;
        LOG_W("pid=%d took too much time (limit %ld s). Killing it with %s", (int)run->pid,
            (long)run->global->timing.tmOut,
            run->global->timing.tmoutVTALRM ? "SIGVTALRM" : "SIGKILL");
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
        LOG_D("Killing pid=%d", (int)run->pid);
        kill(run->pid, SIGKILL);
    }
}

bool subproc_runThread(
    honggfuzz_t* hfuzz, pthread_t* thread, void* (*thread_func)(void*), bool joinable) {
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(
        &attr, joinable ? PTHREAD_CREATE_JOINABLE : PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, _HF_PTHREAD_STACKSIZE);
    pthread_attr_setguardsize(&attr, (size_t)sysconf(_SC_PAGESIZE));

    if (pthread_create(thread, &attr, thread_func, (void*)hfuzz) < 0) {
        PLOG_W("Couldn't create a new thread");
        return false;
    }

    pthread_attr_destroy(&attr);

    return true;
}
