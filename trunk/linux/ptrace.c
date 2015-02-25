/*
 *
 * honggfuzz - architecture dependent code (LINUX/PTRACE)
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
#include "ptrace.h"

#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/cdefs.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "files.h"
#include "linux/bfd.h"
#include "linux/unwind.h"
#include "log.h"
#include "util.h"

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

bool arch_ptraceEnable(honggfuzz_t * hfuzz)
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

static size_t arch_getProcMem(pid_t pid, uint8_t * buf, size_t len, uint64_t pc)
{
    /*
     * Let's try process_vm_readv first
     */
    const struct iovec local_iov = {
        .iov_base = buf,
        .iov_len = len,
    };
    const struct iovec remote_iov = {
        .iov_base = (void *)(uintptr_t) pc,
        .iov_len = len,
    };
    if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) == (ssize_t) len) {
        return len;
    }

    /*
     * Ok, let's do it via ptrace() then.
     * len must be aligned to the sizeof(long)
     */
    int cnt = len / sizeof(long);
    size_t memsz = 0;

    for (int x = 0; x < cnt; x++) {
        uint8_t *addr = (uint8_t *) (uintptr_t) pc + (int)(x * sizeof(long));
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

static bool arch_getPC(pid_t pid, uint64_t * pc)
{
    char buf[1024];
    struct iovec pt_iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov) == -1L) {
        LOGMSG_P(l_WARN, "ptrace(PTRACE_GETREGSET) failed");
        return false;
    }
#if defined(__i386__) || defined(__x86_64__)
    struct user_regs_struct_32 {
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
        uint32_t esi;
        uint32_t edi;
        uint32_t ebp;
        uint32_t eax;
        uint16_t ds, __ds;
        uint16_t es, __es;
        uint16_t fs, __fs;
        uint16_t gs, __gs;
        uint32_t orig_eax;
        uint32_t eip;
        uint16_t cs, __cs;
        uint32_t eflags;
        uint32_t esp;
        uint16_t ss, __ss;
    };

    struct user_regs_struct_64 {
        uint64_t r15;
        uint64_t r14;
        uint64_t r13;
        uint64_t r12;
        uint64_t bp;
        uint64_t bx;
        uint64_t r11;
        uint64_t r10;
        uint64_t r9;
        uint64_t r8;
        uint64_t ax;
        uint64_t cx;
        uint64_t dx;
        uint64_t si;
        uint64_t di;
        uint64_t orig_ax;
        uint64_t ip;
        uint64_t cs;
        uint64_t flags;
        uint64_t sp;
        uint64_t ss;
        uint64_t fs_base;
        uint64_t gs_base;
        uint64_t ds;
        uint64_t es;
        uint64_t fs;
        uint64_t gs;
    };

    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)buf;
        *pc = r32->eip;
        return true;
    }
    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)buf;
        *pc = r64->ip;
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /* defined(__i386__) ||
                                 * defined(__x86_64__) */
#if defined(__arm__)
    struct user_regs_struct_32 {
        uint32_t uregs[18];
    };
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)buf;
#ifndef ARM_pc
#define ARM_pc 15
#endif                          /* ARM_pc */
        *pc = r32->uregs[ARM_pc];
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /* defined(__arm__) */
#if defined(__aarch64__)
    struct user_regs_struct_64 {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    };
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)buf;
        *pc = r64->pc;
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /* defined(__aarch64__) */
#if defined(__powerpc64__) || defined(__powerpc__)
    struct user_regs_struct_32 {
        uint32_t gpr[32];
        uint32_t nip;
        uint32_t msr;
        uint32_t orig_gpr3;
        uint32_t ctr;
        uint32_t link;
        uint32_t xer;
        uint32_t ccr;
        uint32_t mq;
        uint32_t trap;
        uint32_t dar;
        uint32_t dsisr;
        uint32_t result;
        /*
         * elf.h's ELF_NGREG says it's 48 registers, so kernel fills it in
         * with some zeros
         */
        uint32_t zero0;
        uint32_t zero1;
        uint32_t zero2;
        uint32_t zero3;
    };
    struct user_regs_struct_64 {
        uint64_t gpr[32];
        uint64_t nip;
        uint64_t msr;
        uint64_t orig_gpr3;
        uint64_t ctr;
        uint64_t link;
        uint64_t xer;
        uint64_t ccr;
        uint64_t softe;
        uint64_t trap;
        uint64_t dar;
        uint64_t dsisr;
        uint64_t result;
        /*
         * elf.h's ELF_NGREG says it's 48 registers, so kernel fills it in
         * with some zeros
         */
        uint64_t zero0;
        uint64_t zero1;
        uint64_t zero2;
        uint64_t zero3;
    };
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)buf;
        *pc = r32->nip;
        return true;
    }
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)buf;
        *pc = r64->nip;
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /* defined(__powerpc64__) ||
                                 * defined(__powerpc__) */
    LOGMSG(l_DEBUG, "Unknown/unsupported CPU architecture");
    return false;
}

static void arch_getInstrStr(pid_t pid, uint64_t * pc, char *instr)
{
    /*
     * We need a value aligned to 8
     * which is sizeof(long) on 64bit CPU archs (on most of them, I hope;)
     */
    uint8_t buf[16];
    size_t memsz;

    snprintf(instr, _HF_INSTR_SZ, "%s", "[UNKNOWN]");

    if (!arch_getPC(pid, pc)) {
        LOGMSG(l_WARN, "Current architecture not supported for disassembly");
        return;
    }

    if ((memsz = arch_getProcMem(pid, buf, sizeof(buf), *pc)) == 0) {
        snprintf(instr, _HF_INSTR_SZ, "%s", "[NOT_MMAPED]");
        return;
    }

    arch_bfdDisasm(pid, buf, memsz, instr);

    for (int x = 0; instr[x] && x < _HF_INSTR_SZ; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace(instr[x])
            || !isprint(instr[x])) {
            instr[x] = '_';
        }
    }

    return;
}

static void
arch_ptraceGenerateReport(pid_t pid, fuzzer_t * fuzzer, funcs_t * funcs,
                          size_t funcCnt, siginfo_t * si, const char *instr)
{
    fuzzer->report[0] = '\0';
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "ORIG_FNAME: %s\n",
                   fuzzer->origFileName);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "FUZZ_FNAME: %s\n", fuzzer->fileName);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "PID: %d\n", pid);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "SIGNAL: %s (%d)\n",
                   arch_sigs[si->si_signo].descr, si->si_signo);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "FAULT ADDRESS: %p\n", si->si_addr);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "INSTRUCTION: %s\n", instr);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "STACK:\n");
    for (size_t i = 0; i < funcCnt; i++) {
        util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), " <0x%016" PRIx64 "> [%s():%d]\n",
                       (uint64_t) (long)funcs[i].pc, funcs[i].func, funcs[i].line);
    }

    return;
}

static void arch_ptraceSaveData(honggfuzz_t * hfuzz, pid_t pid, fuzzer_t * fuzzer)
{
    uint64_t pc = 0ULL;

    char instr[_HF_INSTR_SZ] = "\x00";
    siginfo_t si;

    if (ptrace(PT_GETSIGINFO, pid, 0, &si) == -1) {
        LOGMSG_P(l_WARN, "Couldn't get siginfo for pid %d", pid);
        return;
    }

    arch_getInstrStr(pid, &pc, instr);

    LOGMSG(l_DEBUG,
           "Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %"
           PRIx64 ", instr: '%s'", pid, si.si_signo, si.si_errno, si.si_code, si.si_addr, pc,
           instr);

    if (si.si_addr < hfuzz->ignoreAddr) {
        LOGMSG(l_INFO,
               "'%s' is interesting (%s), but the si.si_addr is %p (below %p), skipping",
               fuzzer->fileName, arch_sigs[si.si_signo].descr, si.si_addr, hfuzz->ignoreAddr);
        return;
    }

    char newname[PATH_MAX];
    if (hfuzz->saveUnique) {
        snprintf(newname, sizeof(newname),
                 "%s.PC.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr,
                 instr, fuzzer->origFileName, hfuzz->fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr));
        snprintf(newname, sizeof(newname),
                 "%s.PC.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr,
                 instr, localtmstr, pid, fuzzer->origFileName, hfuzz->fileExtn);
    }

    if (link(fuzzer->fileName, newname) == 0) {
        LOGMSG(l_INFO, "Ok, that's interesting, saved '%s' as '%s'", fuzzer->fileName, newname);
    } else {
        if (errno == EEXIST) {
            LOGMSG(l_INFO, "It seems that '%s' already exists, skipping", newname);
        } else {
            LOGMSG_P(l_ERROR, "Couldn't link '%s' to '%s'", fuzzer->fileName, newname);
        }
    }

    funcs_t funcs[_HF_MAX_FUNCS] = {
        [0 ... (_HF_MAX_FUNCS - 1)].pc = NULL,
        [0 ... (_HF_MAX_FUNCS - 1)].line = 0,
        [0 ... (_HF_MAX_FUNCS - 1)].func = {'\0'}
        ,
    };

    size_t funcCnt = arch_unwindStack(pid, funcs);
    arch_bfdResolveSyms(pid, funcs, funcCnt);

    arch_ptraceGenerateReport(pid, fuzzer, funcs, funcCnt, &si, instr);
}

void arch_ptraceAnalyze(honggfuzz_t * hfuzz, int status, pid_t pid, fuzzer_t * fuzzer)
{
    /*
     * If it's an uninteresting signal (even SIGTRAP), let it run and relay the
     * signal (if not SIGTRAP)
     */
    if (WIFSTOPPED(status) && !arch_sigs[WSTOPSIG(status)].important) {
        int sig = WSTOPSIG(status) == SIGTRAP ? 0 : WSTOPSIG(status);
        ptrace(PT_CONTINUE, pid, 0, sig);
        return;
    }

    /*
     * If it's an interesting signal, save the testcase, and detach
     * the tracer (relay the signal as well)
     */
    if (WIFSTOPPED(status) && arch_sigs[WSTOPSIG(status)].important) {
        arch_ptraceSaveData(hfuzz, pid, fuzzer);
        ptrace(PT_CONTINUE, pid, 0, WSTOPSIG(status));
        return;
    }

    /*
     * Resumed by delivery of SIGCONT
     */
    if (WIFCONTINUED(status)) {
        return;
    }

    /*
     * Process exited
     */
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        return;
    }

    abort();                    /* NOTREACHED */
    return;
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

bool arch_ptracePrepare(honggfuzz_t * hfuzz)
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
            LOGMSG_P(l_ERROR, "Couldn't ptrace(PTRACE_ATTACH) to pid: %d", tasks[i]);
            return false;
        }

        int status;
        while (waitpid(tasks[i], &status, WUNTRACED | __WALL) != tasks[i]) ;

        if (ptrace(PTRACE_SETOPTIONS, tasks[i], NULL,
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't ptrace(PTRACE_SETOPTIONS) pid: %d", tasks[i]);
            ptrace(PT_DETACH, tasks[i], 0, SIGCONT);
            return false;
        }

        if (ptrace(PT_CONTINUE, tasks[i], NULL, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't ptrace(PTRACE_CONTINUE) pid: %d", tasks[i]);
            ptrace(PT_DETACH, tasks[i], 0, SIGCONT);
            return false;
        }

        LOGMSG(l_INFO, "Successfully attached to pid/tid: %d", tasks[i]);
    }
    return true;
}
