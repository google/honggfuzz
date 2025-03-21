/*
 *
 * honggfuzz - architecture dependent code (POSIX / SIGNAL)
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
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(__sun)
#include <sys/cdefs.h>
#else
#include <kvm.h>
#include <sys/proc.h>
#endif
#if defined(__FreeBSD__)
#include <sys/procctl.h>
#endif
#if defined(__APPLE__)
#include <spawn.h>
extern char** environ;
#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "report.h"
#include "sanitizers.h"
#include "subproc.h"

struct {
    bool        important;
    const char* descr;
} arch_sigs[NSIG] = {
    [0 ...(NSIG - 1)].important = false,
    [0 ...(NSIG - 1)].descr     = "UNKNOWN",

    [SIGILL].important = true,
    [SIGILL].descr     = "SIGILL",

    [SIGFPE].important = true,
    [SIGFPE].descr     = "SIGFPE",

    [SIGSEGV].important = true,
    [SIGSEGV].descr     = "SIGSEGV",

    [SIGBUS].important = true,
    [SIGBUS].descr     = "SIGBUS",

    [SIGABRT].important = true,
    [SIGABRT].descr     = "SIGABRT",

    /* Is affected from tmout_vtalrm flag */
    [SIGVTALRM].important = false,
    [SIGVTALRM].descr     = "SIGVTALRM-TMOUT",
};

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static void arch_analyzeSignal(run_t* run, pid_t pid, int status) {
    /*
     * Resumed by delivery of SIGCONT
     */
    if (WIFCONTINUED(status)) {
        return;
    }

    /*
     * Boring, the process just exited
     */
    if (WIFEXITED(status)) {
        LOG_D("Process (pid %d) exited normally with status %d", (int)pid, WEXITSTATUS(status));
        return;
    }

    /*
     * Shouldn't really happen, but, well..
     */
    if (!WIFSIGNALED(status)) {
        LOG_E("Process (pid %d) exited with the following status %d, please report that as a bug",
            (int)pid, status);
        return;
    }

    int termsig = WTERMSIG(status);
    LOG_D("Process (pid %d) killed by signal %d '%s'", (int)pid, termsig, strsignal(termsig));
    if (!arch_sigs[termsig].important) {
        LOG_D("It's not that important signal, skipping");
        return;
    }

    funcs_t* funcs = util_Calloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };
    uint64_t pc                      = 0;
    uint64_t crashAddr               = 0;
    char     description[HF_STR_LEN] = {};
    size_t   funcCnt = sanitizers_parseReport(run, pid, funcs, &pc, &crashAddr, description);

    /*
     * Calculate backtrace callstack hash signature
     */
    run->backtrace = sanitizers_hashCallstack(run, funcs, funcCnt, false);

    /*
     * If unique flag is set and single frame crash, disable uniqueness for this crash
     * to always save (timestamp will be added to the filename)
     */
    bool saveUnique = run->global->io.saveUnique;
    if (saveUnique && (funcCnt == 0)) {
        saveUnique = false;
    }

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->dynfile->path);
    } else if (saveUnique) {
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIx64 ".STACK.%" PRIx64 ".ADDR.%" PRIx64 ".%s", run->global->io.crashDir,
            util_sigName(termsig), pc, run->backtrace, crashAddr, run->global->io.fileExtn);
    } else {
        char localtmstr[HF_STR_LEN];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIx64 ".STACK.%" PRIx64 ".ADDR.%" PRIx64 ".%s.%d.%s",
            run->global->io.crashDir, util_sigName(termsig), pc, run->backtrace, crashAddr,
            localtmstr, (int)pid, run->global->io.fileExtn);
    }

    ATOMIC_POST_INC(run->global->cnts.crashesCnt);

    if (files_exists(run->crashFileName)) {
        LOG_I("Crash (dup): '%s' already exists, skipping", run->crashFileName);
        /* Clear filename so that verifier can understand we hit a duplicate */
        memset(run->crashFileName, 0, sizeof(run->crashFileName));
        return;
    }

    LOG_I("Ok, that's interesting, saving input '%s'", run->crashFileName);

    ATOMIC_POST_INC(run->global->cnts.uniqueCrashesCnt);
    /* If unique crash found, reset dynFile counter */
    ATOMIC_CLEAR(run->global->cfg.dynFileIterExpire);

    if (!files_writeBufToFile(run->crashFileName, run->dynfile->data, run->dynfile->size,
            O_CREAT | O_EXCL | O_WRONLY)) {
        LOG_E("Couldn't save crash to '%s'", run->crashFileName);
    }

    report_appendReport(pid, run, funcs, funcCnt, pc, crashAddr, termsig, "", description);
}

pid_t arch_fork(run_t* fuzzer HF_ATTR_UNUSED) {
#if defined(__FreeBSD__)
    const int flags = RFPROC | RFCFDG;
    return rfork(flags);
#else
    return fork();
#endif
}

bool arch_launchChild(run_t* run) {
#if defined(__APPLE__)
    posix_spawnattr_t attrs;
    posix_spawnattr_init(&attrs);

    short ps_flags = POSIX_SPAWN_SETEXEC;
    if (run->global->arch_linux.disableRandomization) {
        ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
    }

    int ret = posix_spawnattr_setflags(&attrs, ps_flags);
    if (ret != 0) {
        LOG_W("cannot set posix_spawn flags");
    }

    int status = posix_spawn(NULL, run->args[0], NULL, &attrs, (char* const*)run->args, environ);

    posix_spawnattr_destroy(&attrs);

    if (status != 0) {
        PLOG_E("posix_spawnp failed for '%s'", run->args[0]);
        return false;
    }
#elif defined(__FreeBSD__)
    int enableTrace          = PROC_TRACE_CTL_ENABLE;
    int disableRandomization = PROC_ASLR_FORCE_DISABLE;
    if (procctl(P_PID, 0, PROC_TRACE_CTL, &enableTrace) == -1) {
        PLOG_E("procctl(PROC_TRACE_CTL, PROC_TRACE_CTL_ENABLE)");
        return false;
    }

    if (run->global->arch_linux.disableRandomization &&
        procctl(P_PID, 0, PROC_ASLR_CTL, &disableRandomization) == -1) {
        PLOG_D("procctl(PROC_ASLR_CTL, PROC_ASLR_FORCE_DISABLE) failed");
    }
#elif defined(__sun)
    if (run->global->arch_linux.disableRandomization) {
        kvm_t*  hd          = NULL;
        proc_t* cur         = NULL;
        int     enableTrace = PROC_SEC_ASLR;
        if ((hd = kvm_open(NULL, NULL, NULL, O_RDWR, NULL)) == NULL) {
            PLOG_E("kvm_open() failed");
            return false;
        }

        // unlikely but who knows
        if ((cur = kvm_getproc(hd, getpid())) == NULL) {
            PLOG_E("kvm_getproc() failed");
            kvm_close(hd);
            return false;
        }
        if (secflag_isset(cur->p_secflags.psf_effective, enableTrace)) {
            secflag_clear(&cur->p_secflags.psf_effective, enableTrace);
        }
        kvm_close(hd);
    }

#endif
    /* alarm persists across forks, so disable it here */
    alarm(0);
    execvp(run->args[0], (char* const*)run->args);
    alarm(1);

    return false;
}

void arch_prepareParent(run_t* fuzzer HF_ATTR_UNUSED) {
}

void arch_prepareParentAfterFork(run_t* fuzzer HF_ATTR_UNUSED) {
}

static bool arch_checkWait(run_t* run) {
    /* All queued wait events must be tested when SIGCHLD was delivered */
    for (;;) {
        int   status;
        pid_t pid = TEMP_FAILURE_RETRY(waitpid(run->pid, &status, WNOHANG));
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

        LOG_D("pid=%d returned with status: %s", (int)pid, subproc_StatusToStr(status));

        arch_analyzeSignal(run, pid, status);

        if (pid == run->pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
            if (run->global->exe.persistent) {
                if (!fuzz_isTerminating()) {
                    LOG_W("Persistent mode: pid=%d exited with status: %s", (int)run->pid,
                        subproc_StatusToStr(status));
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
                .fd     = run->persistentSock,
                .events = POLLIN,
            };
            int r = poll(&pfd, 1, 250 /* 0.25s */);
            if (r == -1 && errno != EINTR) {
                PLOG_F("poll(fd=%d)", run->persistentSock);
            }
        } else {
            /* Return with SIGIO, SIGCHLD */
            errno = 0;
            int sig;
            int ret = sigwait(&run->global->exe.waitSigSet, &sig);
            if (ret != 0 && ret != EINTR) {
                PLOG_F("sigwait(SIGIO|SIGCHLD)");
            }
        }

        if (arch_checkWait(run)) {
            run->pid = 0;
            break;
        }
    }
}

void arch_reapKill(void) {
#if defined(__FreeBSD__)
    struct procctl_reaper_kill lst;
    lst.rk_flags = 0;
    lst.rk_sig   = SIGTERM;
    if (procctl(P_PID, getpid(), PROC_REAP_KILL, &lst) == -1) {
        PLOG_W("procctl(PROC_REAP_KILL)");
    }
#endif
}

bool arch_archInit(honggfuzz_t* hfuzz HF_ATTR_UNUSED) {
    /* Make %'d work */
    setlocale(LC_NUMERIC, "en_US.UTF-8");

    return true;
}

bool arch_archThreadInit(run_t* fuzzer HF_ATTR_UNUSED) {
#if defined(__FreeBSD_)
    if (procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL) == -1) {
        PLOG_W("procctl(PROC_REAP_ACQUIRE)");
    }
#endif
    return true;
}
