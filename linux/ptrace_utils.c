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
#include "ptrace_utils.h"

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

#if defined(__ANDROID__)
#include <linux/ptrace.h>
#include <asm/ptrace.h>         /* For pt_regs structs */
#include <sys/syscall.h>
#include "capstone.h"
#endif

#if defined(__i386__) || defined(__arm__) || defined(__powerpc__)
#define REG_TYPE uint32_t
#define REG_PM   PRIx32
#define REG_PD   "0x%08"
#elif defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__)
#define REG_TYPE uint64_t
#define REG_PM   PRIx64
#define REG_PD   "0x%016"
#endif

#if defined(__i386__) || defined(__x86_64__)
#define MAX_INSTR_SZ 16
#elif defined(__arm__) || defined(__powerpc__) || defined(__powerpc64__)
#define MAX_INSTR_SZ 4
#elif defined(__aarch64__)
#define MAX_INSTR_SZ 8
#endif

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
#define HEADERS_STRUCT struct user_regs_struct_64
#endif                          /* defined(__i386__) || defined(__x86_64__) */

#if defined(__arm__) || defined(__aarch64__)
#ifndef ARM_pc
#ifdef __ANDROID__              /* Building with NDK headers */
#define ARM_pc uregs[15]
#else                           /* Building with glibc headers */
#define ARM_pc 15
#endif
#endif                          /* ARM_pc */
#ifndef ARM_cpsr
#ifdef __ANDROID__              /* Building with NDK headers */
#define ARM_cpsr uregs[16]
#else                           /* Building with glibc headers */
#define ARM_cpsr 16
#endif
#endif                          /* ARM_cpsr */
struct user_regs_struct_32 {
    uint32_t uregs[18];
};

struct user_regs_struct_64 {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};
#define HEADERS_STRUCT struct user_regs_struct_64
#endif                          /* defined(__arm__) || defined(__aarch64__) */

#if defined(__powerpc64__) || defined(__powerpc__)
#define HEADERS_STRUCT struct pt_regs
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
#endif                          /* defined(__powerpc64__) || defined(__powerpc__) */

#ifdef __ANDROID__
#ifndef WIFCONTINUED
#define WIFCONTINUED(x) WEXITSTATUS(0)
#endif
#endif

#if defined(__ANDROID__)
#if defined(__NR_process_vm_readv)
static ssize_t honggfuzz_process_vm_readv(pid_t pid,
                                          const struct iovec *lvec,
                                          unsigned long liovcnt,
                                          const struct iovec *rvec,
                                          unsigned long riovcnt, unsigned long flags)
{
    return syscall(__NR_process_vm_readv, (long)pid, lvec, liovcnt, rvec, riovcnt, flags);
}

#define process_vm_readv honggfuzz_process_vm_readv
#else                           /* defined(__NR_process_vm_readv) */
#define process_vm_readv(...) (errno = ENOSYS, -1)
#endif                          /* !defined(__NR_process_vm_readv) */

// Naming compatibilities
#if !defined(PT_TRACE_ME)
#define PT_TRACE_ME PTRACE_TRACEME
#endif

#if !defined(PT_READ_I)
#define PT_READ_I PTRACE_PEEKTEXT
#endif

#if !defined(PT_READ_D)
#define PT_READ_D PTRACE_PEEKDATA
#endif

#if !defined(PT_READ_U)
#define PT_READ_U PTRACE_PEEKUSR
#endif

#if !defined(PT_WRITE_I)
#define PT_WRITE_I PTRACE_POKETEXT
#endif

#if !defined(PT_WRITE_D)
#define PT_WRITE_D PTRACE_POKEDATA
#endif

#if !defined(PT_WRITE_U)
#define PT_WRITE_U PTRACE_POKEUSR
#endif

#if !defined(PT_CONT)
#define PT_CONT PTRACE_CONT
#endif

#if !defined(PT_CONTINUE)
#define PT_CONTINUE PTRACE_CONT
#endif

#if !defined(PT_KILL)
#define PT_KILL PTRACE_KILL
#endif

#if !defined(PT_STEP)
#define PT_STEP PTRACE_SINGLESTEP
#endif

#if !defined(PT_GETFPREGS)
#define PT_GETFPREGS PTRACE_GETFPREGS
#endif

#if !defined(PT_ATTACH)
#define PT_ATTACH PTRACE_ATTACH
#endif

#if !defined(PT_DETACH)
#define PT_DETACH PTRACE_DETACH
#endif

#if !defined(PT_SYSCALL)
#define PT_SYSCALL PTRACE_SYSCALL
#endif

#if !defined(PT_SETOPTIONS)
#define PT_SETOPTIONS PTRACE_SETOPTIONS
#endif

#if !defined(PT_GETEVENTMSG)
#define PT_GETEVENTMSG PTRACE_GETEVENTMSG
#endif

#if !defined(PT_GETSIGINFO)
#define PT_GETSIGINFO PTRACE_GETSIGINFO
#endif

#if !defined(PT_SETSIGINFO)
#define PT_SETSIGINFO PTRACE_SETSIGINFO
#endif

/* 
 * WARNING: NOT TESTED YET
 * If doesn't work, remove PTRACE_GETREGSET failover support via
 * the PTRACE_GETREGS call. Considering recent kernels in arm64, 
 * PTRACE_GETREGSET should be always implemented and be enough for
 * fuzzer to work.
 */
#if defined(__aarch64__) && !defined(PTRACE_GETREGS)
#define PTRACE_GETREGS 12
#endif

#endif                          /* defined(__ANDROID__) */

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

static size_t arch_getProcMem(pid_t pid, uint8_t * buf, size_t len, REG_TYPE pc)
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
    // Debug if failed since it shouldn't happen very often
    LOGMSG_P(l_DEBUG, "process_vm_readv() failed");

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

// Non i386 / x86_64 ISA fail build due to unused pid argument
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
uint64_t arch_ptraceGetCustomPerf(honggfuzz_t * hfuzz, pid_t pid)
{
    if ((hfuzz->dynFileMethod & _HF_DYNFILE_CUSTOM) == 0) {
        return 0ULL;
    }
#if defined(__i386__) || defined(__x86_64__)
    HEADERS_STRUCT regs;
    struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov) == -1L) {
        LOGMSG_P(l_DEBUG, "ptrace(PTRACE_GETREGSET) failed");

        // If PTRACE_GETREGSET fails, try PTRACE_GETREGS
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
            LOGMSG_P(l_DEBUG, "ptrace(PTRACE_GETREGS) failed");
            LOGMSG(l_WARN, "ptrace PTRACE_GETREGSET & PTRACE_GETREGS failed to"
                   " extract target registers");
            return 0ULL;
        }
    }

    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)&regs;
        return (uint64_t) r32->gs;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)&regs;
        return (uint64_t) r64->gs_base;
    }

    LOGMSG(l_WARN, "Unknown registers structure size: '%d'", pt_iov.iov_len);
#endif                          /* defined(__i386__) || defined(__x86_64__) */

    return 0ULL;
}

#pragma GCC diagnostic pop      /* ignored "-Wunused-parameter" */

static size_t arch_getPC(pid_t pid, REG_TYPE * pc, REG_TYPE * status_reg)
{
    HEADERS_STRUCT regs;
    struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov) == -1L) {
        LOGMSG_P(l_DEBUG, "ptrace(PTRACE_GETREGSET) failed");

        // If PTRACE_GETREGSET fails, try PTRACE_GETREGS
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
            LOGMSG_P(l_DEBUG, "ptrace(PTRACE_GETREGS) failed");
            LOGMSG(l_WARN, "ptrace PTRACE_GETREGSET & PTRACE_GETREGS failed to"
                   " extract target registers");
            return 0;
        }
    }
#if defined(__i386__) || defined(__x86_64__)
    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)&regs;
        *pc = r32->eip;
        *status_reg = r32->eflags;
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)&regs;
        *pc = r64->ip;
        *status_reg = r64->flags;
        return pt_iov.iov_len;
    }
    LOGMSG(l_WARN, "Unknown registers structure size: '%d'", pt_iov.iov_len);
    return 0;
#endif                          /* defined(__i386__) || defined(__x86_64__) */

#if defined(__arm__) || defined(__aarch64__)
    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)&regs;
#ifdef __ANDROID__
        *pc = r32->ARM_pc;
        *status_reg = r32->ARM_cpsr;
#else
        *pc = r32->uregs[ARM_pc];
        *status_reg = r32->uregs[ARM_cpsr];
#endif
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)&regs;
        *pc = r64->pc;
        *status_reg = r64->pstate;
        return pt_iov.iov_len;
    }
    LOGMSG(l_WARN, "Unknown registers structure size: '%d'", pt_iov.iov_len);
    return 0;
#endif                          /* defined(__arm__) || defined(__aarch64__) */

#if defined(__powerpc64__) || defined(__powerpc__)
    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)&regs;
        *pc = r32->nip;
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)&regs;
        *pc = r64->nip;
        return pt_iov.iov_len;
    }

    LOGMSG(l_WARN, "Unknown registers structure size: '%d'", pt_iov.iov_len);
    return 0;
#endif                          /* defined(__powerpc64__) || defined(__powerpc__) */

    LOGMSG(l_DEBUG, "Unknown/unsupported CPU architecture");
    return 0;
}

static void arch_getInstrStr(pid_t pid, REG_TYPE * pc, char *instr)
{
    /*
     * We need a value aligned to 8
     * which is sizeof(long) on 64bit CPU archs (on most of them, I hope;)
     */
    uint8_t buf[MAX_INSTR_SZ];
    size_t memsz;
    REG_TYPE status_reg = 0;

    snprintf(instr, _HF_INSTR_SZ, "%s", "[UNKNOWN]");

    size_t pcRegSz = arch_getPC(pid, pc, &status_reg);
    if (!pcRegSz) {
        LOGMSG(l_WARN, "Current architecture not supported for disassembly");
        return;
    }

    if ((memsz = arch_getProcMem(pid, buf, sizeof(buf), *pc)) == 0) {
        snprintf(instr, _HF_INSTR_SZ, "%s", "[NOT_MMAPED]");
        return;
    }
#if !defined(__ANDROID__)
    arch_bfdDisasm(pid, buf, memsz, instr);
#else
    cs_arch arch;
    cs_mode mode;
#if defined(__arm__) || defined(__aarch64__)
    arch = (pcRegSz == sizeof(struct user_regs_struct_64)) ? CS_ARCH_ARM64 : CS_ARCH_ARM;
    if (arch == CS_ARCH_ARM) {
        mode = (status_reg & 0x20) ? CS_MODE_THUMB : CS_MODE_ARM;
    } else {
        mode = CS_MODE_ARM;
    }
#elif defined(__i386__) || defined(__x86_64__)
    arch = CS_ARCH_X86;
    mode = (pcRegSz == sizeof(struct user_regs_struct_64)) ? CS_MODE_64 : CS_MODE_32;
#else
    LOGMSG(l_ERROR, "Unknown/unsupported Android CPU architecture");
#endif

    csh handle;
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        LOGMSG(l_WARN, "Capstone initialization failed: '%s'", cs_strerror(err));
        return;
    }

    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, sizeof(buf), *pc, 0, &insn);

    if (count < 1) {
        LOGMSG(l_WARN, "Couldn't disassemble the assembler instructions' stream: '%s'",
               cs_strerror(cs_errno(handle)));
        cs_close(&handle);
        return;
    }

    snprintf(instr, _HF_INSTR_SZ, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, count);
    cs_close(&handle);
#endif

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
#ifdef __HF_USE_CAPSTONE__
        util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), " <" REG_PD REG_PM "> ",
                       (REG_TYPE) (long)funcs[i].pc, funcs[i].func, funcs[i].line);
        if (funcs[i].func[0] != '\0')
            util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "[%s + 0x%x]\n",
                           funcs[i].func, funcs[i].line);
        else
            util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "[]\n");
#else
        util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), " <" REG_PD REG_PM "> [%s():%u]\n",
                       (REG_TYPE) (long)funcs[i].pc, funcs[i].func, funcs[i].line);
#endif
    }

// libunwind is not working for 32bit targets in 64bit systems
#if defined(__aarch64__)
    if (funcCnt == 0) {
        util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), " !ERROR: If 32bit fuzz target"
                       " in aarch64 system, try ARM 32bit build\n");
    }
#endif

    return;
}

static void arch_ptraceSaveData(honggfuzz_t * hfuzz, pid_t pid, fuzzer_t * fuzzer)
{
    REG_TYPE pc = 0;

    char instr[_HF_INSTR_SZ] = "\x00";
    siginfo_t si;

    if (ptrace(PT_GETSIGINFO, pid, 0, &si) == -1) {
        LOGMSG_P(l_WARN, "Couldn't get siginfo for pid %d", pid);
        return;
    }

    arch_getInstrStr(pid, &pc, instr);

    LOGMSG(l_DEBUG,
           "Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %"
           REG_PM ", instr: '%s'", pid, si.si_signo, si.si_errno, si.si_code, si.si_addr, pc,
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
                 "%s.PC.%" REG_PM ".CODE.%d.ADDR.%p.INSTR.%s.%s.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr,
                 instr, fuzzer->origFileName, hfuzz->fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr));
        snprintf(newname, sizeof(newname),
                 "%s.PC.%" REG_PM ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr,
                 instr, localtmstr, pid, fuzzer->origFileName, hfuzz->fileExtn);
    }

    if (link(fuzzer->fileName, newname) == 0) {
        LOGMSG(l_INFO, "Ok, that's interesting, saved '%s' as '%s'", fuzzer->fileName, newname);
    } else {
        if (errno == EEXIST) {
            LOGMSG(l_INFO, "It seems that '%s' already exists, skipping", newname);
            // Don't bother unwinding & generating reports for duplicate crashes
            return;
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

#if !defined(__ANDROID__)
    size_t funcCnt = arch_unwindStack(pid, funcs);
    arch_bfdResolveSyms(pid, funcs, funcCnt);
#else
    size_t funcCnt = arch_unwindStack(pid, funcs);
#endif

    arch_ptraceGenerateReport(pid, fuzzer, funcs, funcCnt, &si, instr);
}

#define __WEVENT(status) ((status & 0xFF0000) >> 16)
static void arch_ptraceEvent(int status, pid_t pid)
{
    LOGMSG(l_DEBUG, "PID: %d, Ptrace event %d", pid, __WEVENT(status));
    ptrace(PT_CONTINUE, pid, 0, 0);
    return;
}

void arch_ptraceAnalyze(honggfuzz_t * hfuzz, int status, pid_t pid, fuzzer_t * fuzzer)
{
    /*
     * It's a ptrace event, deal with it elsewhere
     */
    if (WIFSTOPPED(status) && __WEVENT(status)) {
        return arch_ptraceEvent(status, pid);
    }

    if (WIFSTOPPED(status)) {
        int curStatus = WSTOPSIG(status);

        /*
         * If it's an interesting signal, save the testcase
         */
        if (arch_sigs[WSTOPSIG(status)].important) {
            arch_ptraceSaveData(hfuzz, pid, fuzzer);

            /* 
             * An kind of ugly (although necessary) hack due to custom signal handlers
             * in Android from debuggerd. If we pass one of the monitored signals, 
             * we'll end-up running the processing routine twice. A cost that we 
             * don't want to pay.
             */
#if defined(__ANDROID__)
            curStatus = SIGINT;
#endif
        }
        ptrace(PT_CONTINUE, pid, 0, curStatus);
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

bool arch_ptraceAttach(pid_t pid)
{
#define MAX_THREAD_IN_TASK 4096
    int tasks[MAX_THREAD_IN_TASK + 1];
    tasks[MAX_THREAD_IN_TASK] = 0;
    if (!arch_listThreads(tasks, MAX_THREAD_IN_TASK, pid)) {
        LOGMSG(l_ERROR, "Couldn't read thread list for pid '%d'", pid);
        return false;
    }

    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        if (ptrace
            (PTRACE_SEIZE, tasks[i], NULL,
             PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT) ==
            -1) {
            LOGMSG_P(l_ERROR, "Couldn't ptrace(PTRACE_SEIZE) to pid: %d", tasks[i]);
            return false;
        }
        LOGMSG(l_DEBUG, "Successfully attached to pid/tid: %d", tasks[i]);
    }
    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        ptrace(PT_CONTINUE, tasks[i], NULL, NULL);
    }
    return true;
}
