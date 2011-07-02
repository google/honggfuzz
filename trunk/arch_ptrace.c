/*

   honggfuzz - architecture dependent code (PTRACE)
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
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#if defined(__i386__) || defined(__x86_64__)
#include <udis86.h>
#endif

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

static bool arch_enablePtrace(honggfuzz_t * hfuzz)
{
    // We're fuzzing an external process, so just return true
    if (hfuzz->pid) {
        return true;
    }

    if (ptrace(PT_TRACE_ME, 0, 0, 0) == -1) {
        LOGMSG_P(l_FATAL, "Couldn't attach ptrace to pid %d", getpid());
        return false;
    }

    return true;
}

static size_t arch_getProcMem(pid_t pid, uint8_t * buf, size_t len, void *pc)
{
    /*
     * len must be aligned to the sizeof(long)
     */
    int cnt = len / sizeof(long);
    size_t memsz = 0;

    for (int x = 0; x < cnt; x++) {
        uint8_t *addr = (uint8_t *) pc + (int)(x * sizeof(long));
        long ret = ptrace(PT_READ_D, pid, addr, NULL);

        if (errno != 0) {
            LOGMSG_P(l_WARN, "Couldn't PT_READ_D on pid %d, addr: %p", pid, addr);
            break;
        }

        memsz += sizeof(long);
        memcpy(&buf[x * sizeof(long)], &ret, sizeof(long));
    }
    return memsz;
}

#if defined(__i386__) || defined(__x86_64__)
#ifndef MAX_OP_STRING
#define MAX_OP_STRING 32
#endif                          /* MAX_OP_STRING */
static void arch_getX86InstrStr(pid_t pid, char *instr, void *pc)
{
    /*
     * MAX_INSN_LENGTH is actually 15, but we need a value aligned to 8
     * which is sizeof(long) on 64bit CPU archs (on most of them, I hope;)
     */
    uint8_t buf[16];
    size_t memsz;

    if ((memsz = arch_getProcMem(pid, buf, sizeof(buf), pc)) == 0) {
        snprintf(instr, MAX_OP_STRING, "%s", "[NOT_MMAPED]");
        return;
    }

    ud_t ud_obj;
    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, 64);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    ud_set_pc(&ud_obj, (uint64_t) (long)pc);
    ud_set_input_buffer(&ud_obj, buf, memsz);
    if (!ud_disassemble(&ud_obj)) {
        LOGMSG(l_WARN, "Couldn't disassemble the x86/x86-64 instruction stream");
        return;
    }

    snprintf(instr, MAX_OP_STRING, "%s", ud_insn_asm(&ud_obj));
    for (int x = 0; instr[x] && x < MAX_OP_STRING; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace(instr[x]) || !isprint(instr[x])) {
            instr[x] = '_';
        }
    }
}

#endif                          /* defined(__i386__) || defined(__x86_64__) */

static void arch_savePtraceData(honggfuzz_t * hfuzz, pid_t pid, int status)
{
    void *pc = NULL;

    char instr[MAX_OP_STRING] = "[UNKNOWN]";
    siginfo_t si;

    if (ptrace(PT_GETSIGINFO, pid, 0, &si) == -1) {
        LOGMSG_P(l_WARN, "Couldn't get siginfo for pid %d", pid);
        return;
    }

    struct user_regs_struct regs;
    if (ptrace(PT_GETREGS, pid, NULL, &regs) == -1) {
        LOGMSG(l_ERROR, "Couldn't get CPU registers");
    }
#ifdef __i386__
    pc = (void *)regs.eip;
    arch_getX86InstrStr(pid, instr, pc);
#endif                          /* __i386__ */
#ifdef __x86_64__
    pc = (void *)regs.rip;
    arch_getX86InstrStr(pid, instr, pc);
#endif                          /* __x86_64__ */

    LOGMSG(l_DEBUG,
           "Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %p, instr: '%s'",
           pid, si.si_signo, si.si_errno, si.si_code, si.si_addr, pc, instr);

    int idx = HF_SLOT(hfuzz, pid);

    // If we're checkign state of an external process, then the idx is 0 (cause
    // there's no concurrency)
    if (hfuzz->pid) {
        idx = 0;
    }

    if (si.si_addr < hfuzz->ignoreAddr) {
        LOGMSG(l_INFO,
               "'%s' is interesting (%s), but the si.si_addr is %p (below %p), skipping",
               hfuzz->fuzzers[idx].fileName, arch_sigs[si.si_signo].descr, si.si_addr,
               hfuzz->ignoreAddr);
        return;
    }

    char newname[PATH_MAX];
    if (hfuzz->saveUnique) {
        snprintf(newname, sizeof(newname),
                 "%s.PC.%p.CODE.%d.ADDR.%p.INSTR.%s.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr, instr, hfuzz->fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H.%M.%S", localtmstr, sizeof(localtmstr));
        snprintf(newname, sizeof(newname), "%s.PC.%p.CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr, instr, localtmstr, pid,
                 hfuzz->fileExtn);
    }

    if (link(hfuzz->fuzzers[idx].fileName, newname) == 0) {
        LOGMSG(l_INFO, "Ok, that's interesting, saved '%s' as '%s'",
               hfuzz->fuzzers[idx].fileName, newname);
    } else {
        if (errno == EEXIST) {
            LOGMSG(l_INFO, "It seems that '%s' already exists, skipping", newname);
        } else {
            LOGMSG_P(l_ERROR, "Couldn't link '%s' to '%s'", hfuzz->fuzzers[idx].fileName, newname);
        }
    }
}

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static bool arch_analyzePtrace(honggfuzz_t * hfuzz, pid_t pid, int status)
{
    /*
     * It's our child which fuzzess our process (that we had attached to) finished
     */
    int idx = HF_SLOT(hfuzz, pid);
    if (hfuzz->pid && idx != -1) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            LOGMSG_P(l_DEBUG, "Process pid: %d finished");
            return true;
        } else {
            return false;
        }
    }

    /*
     * If it's an uninteresting signal (even SIGTRAP), let it run and relay the
     * signal (if not SIGTRAP)
     */
    if (WIFSTOPPED(status) && !arch_sigs[WSTOPSIG(status)].important) {
        int sig = WSTOPSIG(status) == SIGTRAP ? 0 : WSTOPSIG(status);
        ptrace(PT_CONTINUE, pid, 0, sig);
        return false;
    }

    /*
     * If it's an interesting signal, save the testcase, and detach
     * the tracer (relay the signal as well)
     */
    if (WIFSTOPPED(status) && arch_sigs[WSTOPSIG(status)].important) {
        arch_savePtraceData(hfuzz, pid, status);
        ptrace(PT_CONTINUE, pid, 0, WSTOPSIG(status));
        return false;
    }

    /*
     * Resumed by delivery of SIGCONT
     */
    if (WIFCONTINUED(status)) {
        return false;
    }

    /*
     * Process exited
     */
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        if (hfuzz->pid && pid == hfuzz->pid) {
            LOGMSG(l_WARN, "Monitored process PID: %d finished", pid);
            exit(EXIT_SUCCESS);
        }
        return true;
    }

    abort();                    /* NOTREACHED */
    return true;
}

bool arch_launchChild(honggfuzz_t * hfuzz, char *fileName)
{
    if (!arch_enablePtrace(hfuzz)) {
        return false;
    }
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/personality.h>
    /*
     * Kill a process (with ABRT) which corrupts its own heap
     */
    if (setenv("MALLOC_CHECK_", "3", 1) == -1) {
        LOGMSG_P(l_ERROR, "setenv(MALLOC_CHECK_=3) failed");
        return false;
    }

    /*
     * Kill the children when fuzzer dies (e.g. due to Ctrl+C)
     */
    if (prctl(PR_SET_PDEATHSIG, (long)SIGKILL, 0L, 0L, 0L) == -1) {
        LOGMSG_P(l_ERROR, "prctl(PR_SET_PDEATHSIG, SIGKILL) failed");
        return false;
    }

    /*
     * Disable ASLR
     */
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
        LOGMSG_P(l_ERROR, "personality(ADDR_NO_RANDOMIZE) failed");
        return false;
    }
#endif                          /* __linux__ */

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
    pid_t pid = waitpid(-1, &status, __WALL);
    if (pid <= 0) {
        return pid;
    }
    LOGMSG(l_DEBUG, "Process (pid %d) came back with status %d", pid, status);

    int ret = arch_analyzePtrace(hfuzz, pid, status);

    if (ret) {
        return pid;
    } else {
        return (-1);
    }
}

static bool arch_listThreads(int tasks[], size_t thrSz, int pid)
{
    size_t count = 0;
    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (!dir) {
        LOGMSG_P(l_ERROR, "Couldn't open dir '%s'", path);
        return false;
    }

    for (;;) {
        struct dirent de, *res;
        if (readdir_r(dir, &de, &res) > 0) {
            LOGMSG_P(l_ERROR, "Couldn't read contents of '%s'", path);
            closedir(dir);
            return false;
        }

        if (res == NULL) {
            break;
        }

        pid_t pid = (pid_t) strtol(res->d_name, (char **)NULL, 10);
        if (pid == 0) {
            LOGMSG(l_DEBUG, "The following dir entry couldn't be converted to pid_t '%s'",
                   res->d_name);
            continue;
        }

        tasks[count++] = pid;
        LOGMSG(l_DEBUG, "Added pid '%d' from '%s/%s'", pid, path, res->d_name);

        if (count >= thrSz) {
            break;
        }
    }
    closedir(dir);
    LOGMSG_P(l_DEBUG, "Total number of threads in pid '%d': '%d'", pid, count);
    tasks[count + 1] = 0;
    if (count < 1) {
        return false;
    }
    return true;
}

bool arch_prepareParent(honggfuzz_t * hfuzz)
{
    if (!hfuzz->pid) {
        return true;
    }
#define MAX_THREAD_IN_TASK 4096
    int tasks[MAX_THREAD_IN_TASK + 1];
    tasks[MAX_THREAD_IN_TASK] = 0;
    if (!arch_listThreads(tasks, MAX_THREAD_IN_TASK, hfuzz->pid)) {
        LOGMSG(l_ERROR, "Couldn't read thread list for pid '%d'", hfuzz->pid);
        return false;
    }

    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        if (ptrace(PT_ATTACH, tasks[i], NULL, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't ptrace() ATTACH to pid: %d", tasks[i]);
            return false;
        }

        int status;
        while (waitpid(tasks[i], &status, WUNTRACED | __WALL) != tasks[i]) ;

        if (ptrace(PT_CONTINUE, tasks[i], NULL, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't ptrace() CONTINUE pid: %d", tasks[i]);
            ptrace(PT_DETACH, tasks[i], 0, SIGCONT);
            return false;
        }

        LOGMSG(l_INFO, "Successfully attached to pid/tid: %d", tasks[i]);
    }
    return true;
}
