/*

   honggfuzz - architecture dependent code (POSIX / SIGNAL)
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>

   Copyright 2010 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

#include "common.h"
#include "log.h"
#include "arch.h"
#include "util.h"

struct {
    bool important;
    const char *descr;
} arch_sigs[NSIG];

__attribute__ ((constructor))
void arch_initSigs(void
    )
{
    for (int x = 0; x < NSIG; x++)
        arch_sigs[x].important = false;

    arch_sigs[SIGILL].important = true;
    arch_sigs[SIGILL].descr = "SIGILL";
    arch_sigs[SIGFPE].important = true;
    arch_sigs[SIGFPE].descr = "SIGFPE";
    arch_sigs[SIGSEGV].important = true;
    arch_sigs[SIGSEGV].descr = "SIGSEGV";
    arch_sigs[SIGBUS].important = true;
    arch_sigs[SIGBUS].descr = "SIGBUS";
    arch_sigs[SIGABRT].important = true;
    arch_sigs[SIGABRT].descr = "SIGABRT";
}

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static bool arch_analyzeSignal(honggfuzz_t * hfuzz, pid_t pid, int status)
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
        LOGMSG(l_DEBUG, "Process (pid %d) exited normally with status %d", pid,
               WEXITSTATUS(status));
        return true;
    }

    /*
     * Shouldn't really happen, but, well..
     */
    if (!WIFSIGNALED(status)) {
        LOGMSG(l_ERROR,
               "Process (pid %d) exited with the following status %d, please report that as a bug",
               pid, status);
        return true;
    }

    int termsig = WTERMSIG(status);
    LOGMSG(l_DEBUG, "Process (pid %d) killed by signal %d '%s'", pid, termsig, strsignal(termsig));
    if (!arch_sigs[termsig].important) {
        LOGMSG(l_DEBUG, "It's not that important signal, skipping");
        return true;
    }

    char localtmstr[PATH_MAX];
    util_getLocalTime("%F.%H.%M.%S", localtmstr, sizeof(localtmstr));

    char newname[PATH_MAX];
    snprintf(newname, sizeof(newname), "%s.%d.%s.%s", arch_sigs[termsig].descr, pid,
             localtmstr, hfuzz->fileExtn);

    int idx = HF_SLOT(hfuzz, pid);
    LOGMSG(l_INFO, "Ok, that's interesting, saving the '%s' as '%s'",
           hfuzz->fuzzers[idx].fileName, newname);

    if (link(hfuzz->fuzzers[idx].fileName, newname) == -1) {
        LOGMSG_P(l_ERROR, "Couldn't save '%s' as '%s'", hfuzz->fuzzers[idx].fileName, newname);
    }
    return true;
}

bool arch_launchChild(honggfuzz_t * hfuzz, char *fileName)
{
#define ARGS_MAX 512
    char *args[ARGS_MAX + 2];

    int x;

    for (x = 0; x < ARGS_MAX && hfuzz->cmdline[x]; x++) {
        if (!hfuzz->fuzzStdin && strcmp(hfuzz->cmdline[x], FILE_PLACEHOLDER) == 0) {
            args[x] = fileName;
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
            LOGMSG_P(l_DEBUG, "Couldn't encforce the RLIMIT_AS resource limit, ignoring");
        }
    }

    if (hfuzz->nullifyStdio) {
        util_nullifyStdio();
    }

    if (hfuzz->fuzzStdin) {
        /* Uglyyyyyy ;) */
        if (!util_redirectStdin(fileName)) {
            return false;
        }
    }

    execvp(args[0], args);

    util_recoverStdio();
    LOGMSG(l_FATAL, "Failed to create new '%s' process", args[0]);
    return false;
}

pid_t arch_reapChild(honggfuzz_t * hfuzz)
{
    int status;
    struct rusage ru;

    pid_t pid = wait3(&status, 0, &ru);
    if (pid <= 0) {
        return pid;
    }
    LOGMSG(l_DEBUG, "Process (pid %d) came back with status %d", pid, status);

    int ret = arch_analyzeSignal(hfuzz, pid, status);

    if (ret) {
        return pid;
    } else {
        return (-1);
    }
}

bool arch_prepareParent(honggfuzz_t * hfuzz)
{
    return true;
}
