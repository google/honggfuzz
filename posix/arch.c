/*
 *
 * honggfuzz - architecture dependent code (POSIX / SIGNAL)
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "files.h"

#ifdef __ANDROID__
#ifndef WIFCONTINUED
#define WIFCONTINUED(x) WEXITSTATUS(0)
#endif
#endif

/*  *INDENT-OFF* */
struct {
    bool important;
    const char *descr;
} arch_sigs[NSIG] = {
    [0 ... (NSIG - 1)].important = false,
    [0 ... (NSIG - 1)].descr = "UNKNOWN",

    [SIGILL].important = true,
    [SIGILL].descr = "SIGILL",
    [SIGFPE].important = true,
    [SIGFPE].descr = "SIGFPE",
    [SIGSEGV].important = true,
    [SIGSEGV].descr = "SIGSEGV",
    [SIGBUS].important = true,
    [SIGBUS].descr = "SIGBUS",
    [SIGABRT].important = true,
    [SIGABRT].descr = "SIGABRT"
};
/*  *INDENT-ON* */

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static bool arch_analyzeSignal(honggfuzz_t * hfuzz, int status, fuzzer_t * fuzzer)
{
    /*
     * Resumed by delivery of SIGCONT
     */
    if (WIFCONTINUED(status)) {
        return false;
    }

    /*
     * Boring, the process just exited
     */
    if (WIFEXITED(status)) {
        LOGMSG(l_DEBUG, "Process (pid %d) exited normally with status %d", fuzzer->pid,
               WEXITSTATUS(status));
        return true;
    }

    /*
     * Shouldn't really happen, but, well..
     */
    if (!WIFSIGNALED(status)) {
        LOGMSG(l_ERROR,
               "Process (pid %d) exited with the following status %d, please report that as a bug",
               fuzzer->pid, status);
        return true;
    }

    int termsig = WTERMSIG(status);
    LOGMSG(l_DEBUG, "Process (pid %d) killed by signal %d '%s'", fuzzer->pid, termsig,
           strsignal(termsig));
    if (!arch_sigs[termsig].important) {
        LOGMSG(l_DEBUG, "It's not that important signal, skipping");
        return true;
    }

    char localtmstr[PATH_MAX];
    util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));

    char newname[PATH_MAX];
    snprintf(newname, sizeof(newname), "%s/%s.%d.%s.%s.%s",
             hfuzz->workDir, arch_sigs[termsig].descr, fuzzer->pid, localtmstr,
             fuzzer->origFileName, hfuzz->fileExtn);

    LOGMSG(l_INFO, "Ok, that's interesting, saving the '%s' as '%s'", fuzzer->fileName, newname);

    /*
     * All crashes are marked as unique due to lack of information in POSIX arch
     */
    __sync_fetch_and_add(&hfuzz->crashesCnt, 1UL);
    __sync_fetch_and_add(&hfuzz->uniqueCrashesCnt, 1UL);

    if (files_copyFile(fuzzer->fileName, newname, NULL) == false) {
        LOGMSG(l_ERROR, "Couldn't save '%s' as '%s'", fuzzer->fileName, newname);
    }
    return true;
}

bool arch_launchChild(honggfuzz_t * hfuzz, char *fileName)
{
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

    LOGMSG(l_DEBUG, "Launching '%s' on file '%s'", args[0], fileName);

    /*
     * Set timeout (prof), real timeout (2*prof), and rlimit_cpu (2*prof)
     */
    if (hfuzz->tmOut) {
        struct itimerval it;

        /*
         * The hfuzz->tmOut is real CPU usage time...
         */
        it.it_value.tv_sec = hfuzz->tmOut;
        it.it_value.tv_usec = 0;
        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = 0;
        if (setitimer(ITIMER_PROF, &it, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't set the ITIMER_PROF timer");
            return false;
        }

        /*
         * ...so, if a process sleeps, this one should
         * trigger a signal...
         */
        it.it_value.tv_sec = hfuzz->tmOut * 2UL;
        it.it_value.tv_usec = 0;
        it.it_interval.tv_sec = 0;
        it.it_interval.tv_usec = 0;
        if (setitimer(ITIMER_REAL, &it, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't set the ITIMER_REAL timer");
            return false;
        }

        /*
         * ..if a process sleeps and catches SIGPROF/SIGALRM
         * rlimits won't help either
         */
        struct rlimit rl;

        rl.rlim_cur = hfuzz->tmOut * 2;
        rl.rlim_max = hfuzz->tmOut * 2;
        if (setrlimit(RLIMIT_CPU, &rl) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't enforce the RLIMIT_CPU resource limit");
            return false;
        }
    }

    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (hfuzz->asLimit) {
        struct rlimit rl;

        rl.rlim_cur = hfuzz->asLimit * 1024UL * 1024UL;
        rl.rlim_max = hfuzz->asLimit * 1024UL * 1024UL;
        if (setrlimit(RLIMIT_AS, &rl) == -1) {
            LOGMSG_P(l_DEBUG, "Couldn't enforce the RLIMIT_AS resource limit, ignoring");
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

    for (size_t i = 0; i < ARRAYSIZE(hfuzz->envs) && hfuzz->envs[i]; i++) {
        putenv(hfuzz->envs[i]);
    }

    execvp(args[0], args);

    util_recoverStdio();
    LOGMSG(l_FATAL, "Failed to create new '%s' process", args[0]);
    return false;
}

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int status;

    for (;;) {
#ifndef __WALL
#define __WALL 0
#endif
        while (wait4(fuzzer->pid, &status, __WALL, NULL) != fuzzer->pid) ;
        LOGMSG(l_DEBUG, "Process (pid %d) came back with status %d", fuzzer->pid, status);

        if (arch_analyzeSignal(hfuzz, status, fuzzer)) {
            return;
        }
    }
}

bool arch_archInit(honggfuzz_t * hfuzz)
{
    if (hfuzz) {
        return true;
    }
    return true;
}
