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

/*
 * Size in characters required to store a string representation of a
 * register value (0xdeadbeef style))
 */
#define REGSIZEINCHAR   (2 * sizeof(REG_TYPE) + 3)

/*
 * Number of frames to include in backtrace callstack signature
 */
#define NMAJORFRAMES    7

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
    return syscall(__NR_process_vm_readv, (uintptr_t) pid, lvec, (uintptr_t) liovcnt, rvec,
                   (uintptr_t) riovcnt, (uintptr_t) flags);
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
 * Some Android ABIs don't implement PTRACE_GETREGS (e.g. aarch64)
 */
#if defined(PTRACE_GETREGS)
#define PTRACE_GETREGS_AVAILABLE 1
#else
#define PTRACE_GETREGS_AVAILABLE 0
#endif                          /* defined(PTRACE_GETREGS) */
#endif                          /* defined(__ANDROID__) */

/*  *INDENT-OFF* */
struct {
    const char *descr;
    bool important;
} arch_sigs[NSIG] = {
    [0 ... (NSIG - 1)].important = false,
    [0 ... (NSIG - 1)].descr = "UNKNOWN",

    [SIGTRAP].important = false,
    [SIGTRAP].descr = "SIGTRAP",

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

#ifndef SI_FROMUSER
#define SI_FROMUSER(siptr)      ((siptr)->si_code <= 0)
#endif                          /* SI_FROMUSER */

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
    PLOG_D("process_vm_readv() failed");

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
            PLOG_W("Couldn't PT_READ_D on pid %d, addr: %p", pid, addr);
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
void arch_ptraceGetCustomPerf(honggfuzz_t * hfuzz, pid_t pid, uint64_t * cnt)
{
    if ((hfuzz->dynFileMethod & _HF_DYNFILE_CUSTOM) == 0) {
        return;
    }
#if defined(__i386__) || defined(__x86_64__)
    HEADERS_STRUCT regs;
    struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov) == -1L) {
        PLOG_D("ptrace(PTRACE_GETREGSET) failed");

        // If PTRACE_GETREGSET fails, try PTRACE_GETREGS if available
#if PTRACE_GETREGS_AVAILABLE
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
            PLOG_D("ptrace(PTRACE_GETREGS) failed");
            LOG_W("ptrace PTRACE_GETREGSET & PTRACE_GETREGS failed to extract target registers");
            return;
        }
#else
        return;
#endif
    }

    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)&regs;
        *cnt = (uint64_t) r32->gs;
        return;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)&regs;
        *cnt = (uint64_t) r64->gs_base;
        return;
    }

    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
#endif                          /* defined(__i386__) || defined(__x86_64__) */
}

#pragma GCC diagnostic pop      /* ignored "-Wunused-parameter" */

static size_t arch_getPC(pid_t pid, REG_TYPE * pc, REG_TYPE * status_reg)
{
    /* 
     * Some old ARM android kernels are failing with PTRACE_GETREGS to extract
     * the correct register values if struct size is bigger than expected. As such the
     * 32/64-bit multiplexing trick is not working for them in case PTRACE_GETREGSET
     * fails or is not implemented. To cover such cases we explicitly define
     * the struct size to 32bit version for arm CPU.
     */
#if defined(__arm__)
    struct user_regs_struct_32 regs;
#else
    HEADERS_STRUCT regs;
#endif
    struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &pt_iov) == -1L) {
        PLOG_D("ptrace(PTRACE_GETREGSET) failed");

        // If PTRACE_GETREGSET fails, try PTRACE_GETREGS if available
#if PTRACE_GETREGS_AVAILABLE
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
            PLOG_D("ptrace(PTRACE_GETREGS) failed");
            LOG_W("ptrace PTRACE_GETREGSET & PTRACE_GETREGS failed to extract target registers");
            return 0;
        }
#else
        return 0;
#endif
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
    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
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
    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
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

    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
    return 0;
#endif                          /* defined(__powerpc64__) || defined(__powerpc__) */

    LOG_D("Unknown/unsupported CPU architecture");
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
        LOG_W("Current architecture not supported for disassembly");
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
    LOG_E("Unknown/unsupported Android CPU architecture");
#endif

    csh handle;
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        LOG_W("Capstone initialization failed: '%s'", cs_strerror(err));
        return;
    }

    cs_insn *insn;
    size_t count = cs_disasm(handle, buf, sizeof(buf), *pc, 0, &insn);

    if (count < 1) {
        LOG_W("Couldn't disassemble the assembler instructions' stream: '%s'",
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

static void arch_hashCallstack(fuzzer_t * fuzzer, funcs_t * funcs, size_t funcCnt,
                               bool enableMasking)
{
    uint64_t hash = 0;
    for (size_t i = 0; i < funcCnt && i < NMAJORFRAMES; i++) {
        /*
         * Convert PC to char array to be compatible with hash function
         */
        char pcStr[REGSIZEINCHAR] = { 0 };
        snprintf(pcStr, REGSIZEINCHAR, REG_PD REG_PM, (REG_TYPE) (long)funcs[i].pc);

        /*
         * Hash the last three nibbles
         */
        hash ^= util_hash(&pcStr[strlen(pcStr) - 3], 3);
    }

    /*
     * If only one frame, hash is not safe to be used for uniqueness. We mask it
     * here with a constant prefix, so analyzers can pick it up and create filenames
     * accordingly. 'enableMasking' is controlling masking for cases where it should
     * not be enabled (e.g. fuzzer worker is from verifier).
     */
    if (enableMasking && funcCnt == 1) {
        hash |= __HF_SINGLE_FRAME_MASK;
    }
    fuzzer->backtrace = hash;
}

static void
arch_ptraceGenerateReport(pid_t pid, fuzzer_t * fuzzer, funcs_t * funcs, size_t funcCnt,
                          siginfo_t * si, const char *instr)
{
    fuzzer->report[0] = '\0';
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "ORIG_FNAME: %s\n",
                   fuzzer->origFileName);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "FUZZ_FNAME: %s\n",
                   fuzzer->crashFileName);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "PID: %d\n", pid);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "SIGNAL: %s (%d)\n",
                   arch_sigs[si->si_signo].descr, si->si_signo);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "FAULT ADDRESS: %p\n",
                   SI_FROMUSER(si) ? NULL : si->si_addr);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "INSTRUCTION: %s\n", instr);
    util_ssnprintf(fuzzer->report, sizeof(fuzzer->report), "STACK HASH: %016llx\n",
                   fuzzer->backtrace);
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

static void arch_ptraceAnalyzeData(pid_t pid, fuzzer_t * fuzzer)
{
    /*
     * Unwind and resolve symbols
     */
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

    /*
     * Calculate backtrace callstack hash signature
     */
    arch_hashCallstack(fuzzer, funcs, funcCnt, false);
}

static void arch_ptraceSaveData(honggfuzz_t * hfuzz, pid_t pid, fuzzer_t * fuzzer)
{
    REG_TYPE pc = 0;

    /* Local copy since flag is overridden for some crashes */
    bool saveUnique = hfuzz->saveUnique;

    char instr[_HF_INSTR_SZ] = "\x00";
    siginfo_t si;
    bzero(&si, sizeof(si));

    if (ptrace(PT_GETSIGINFO, pid, 0, &si) == -1) {
        PLOG_W("Couldn't get siginfo for pid %d", pid);
    }

    arch_getInstrStr(pid, &pc, instr);

    LOG_D("Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %"
          REG_PM ", instr: '%s'", pid, si.si_signo, si.si_errno, si.si_code, si.si_addr, pc, instr);

    if (!SI_FROMUSER(&si) && si.si_addr < hfuzz->ignoreAddr) {
        LOG_I("'%s' is interesting (%s), but the si.si_addr is %p (below %p), skipping",
              fuzzer->fileName, arch_sigs[si.si_signo].descr, si.si_addr, hfuzz->ignoreAddr);
        return;
    }

    /*
     * Unwind and resolve symbols
     */
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

    /* 
     * Temp local copy of previous backtrace value in case worker hit crashes into multiple
     * tids for same target master thread. Will be 0 for first crash against target.
     */
    uint64_t oldBacktrace = fuzzer->backtrace;

    /*
     * Calculate backtrace callstack hash signature
     */
    arch_hashCallstack(fuzzer, funcs, funcCnt, saveUnique);

    /* 
     * If unique flag is set and single frame crash, disable uniqueness for this crash 
     * to always save (timestamp will be added to the filename)
     */
    if (saveUnique && (funcCnt == 1)) {
        saveUnique = false;
    }

    /* 
     * If worker crashFileName member is set, it means that a tid has already crashed
     * from target master thread.
     */
    if (fuzzer->crashFileName) {
        LOG_D("Multiple crashes detected from worker against attached tids group");

        /*
         * If stackhashes match, don't re-analyze. This will avoid duplicates
         * and prevent verifier from running multiple passes. Depth of check is
         * always 1 (last backtrace saved only per target iteration).
         */
        if (oldBacktrace == fuzzer->backtrace) {
            return;
        }
    }

    /* Increase global crashes counter */
    __sync_fetch_and_add(&hfuzz->crashesCnt, 1UL);

    /* 
     * Check if stackhash is blacklisted
     */
    if (hfuzz->blacklist
        && (fastArray64Search(hfuzz->blacklist, hfuzz->blacklistCnt, fuzzer->backtrace) != -1)) {
        LOG_I("Blacklisted stack hash '%" PRIx64 "', skipping", fuzzer->backtrace);
        __sync_fetch_and_add(&hfuzz->blCrashesCnt, 1UL);
        return;
    }

    void *sig_addr = si.si_addr;
    if (hfuzz->disableRandomization == false) {
        pc = 0UL;
        sig_addr = NULL;
    }

    /* User-induced signals don't set si.si_addr */
    if (SI_FROMUSER(&si)) {
        sig_addr = NULL;
    }

    /* If dry run mode, copy file with same name into workspace */
    if (hfuzz->flipRate == 0.0L && hfuzz->useVerifier) {
        snprintf(fuzzer->crashFileName, sizeof(fuzzer->crashFileName), "%s/%s",
                 hfuzz->workDir, fuzzer->origFileName);
    } else if (saveUnique) {
        snprintf(fuzzer->crashFileName, sizeof(fuzzer->crashFileName),
                 "%s/%s.PC.%" REG_PM ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s",
                 hfuzz->workDir, arch_sigs[si.si_signo].descr, pc, fuzzer->backtrace,
                 si.si_code, sig_addr, instr, hfuzz->fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
        snprintf(fuzzer->crashFileName, sizeof(fuzzer->crashFileName),
                 "%s/%s.PC.%" REG_PM ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s",
                 hfuzz->workDir, arch_sigs[si.si_signo].descr, pc, fuzzer->backtrace,
                 si.si_code, sig_addr, instr, localtmstr, pid, hfuzz->fileExtn);
    }

    bool dstFileExists = false;
    if (files_copyFile(fuzzer->fileName, fuzzer->crashFileName, &dstFileExists)) {
        LOG_I("Ok, that's interesting, saved '%s' as '%s'", fuzzer->fileName,
              fuzzer->crashFileName);
        __sync_fetch_and_add(&hfuzz->uniqueCrashesCnt, 1UL);
    } else {
        if (dstFileExists) {
            LOG_I("It seems that '%s' already exists, skipping", fuzzer->crashFileName);

            // Clear filename so that verifier can understand we hit a duplicate
            memset(fuzzer->crashFileName, 0, sizeof(fuzzer->crashFileName));

            // Don't bother unwinding & generating reports for duplicate crashes
            return;
        } else {
            LOG_E("Couldn't copy '%s' to '%s'", fuzzer->fileName, fuzzer->crashFileName);
        }
    }

    arch_ptraceGenerateReport(pid, fuzzer, funcs, funcCnt, &si, instr);
}

#define __WEVENT(status) ((status & 0xFF0000) >> 16)
static void arch_ptraceEvent(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int status, pid_t pid)
{
    LOG_D("PID: %d, Ptrace event: %d", pid, __WEVENT(status));
    switch (__WEVENT(status)) {
    case PTRACE_EVENT_EXIT:
        {
            unsigned long event_msg;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_msg) == -1) {
                PLOG_E("ptrace(PTRACE_GETEVENTMSG,%d) failed", pid);
                return;
            }

            if (WIFEXITED(event_msg)) {
                LOG_D("PID: %d exited with exit_code: %lu", pid,
                      (unsigned long)WEXITSTATUS(event_msg));
                if (WEXITSTATUS(event_msg) == (unsigned long)HF_MSAN_EXIT_CODE) {
                    arch_ptraceSaveData(hfuzz, pid, fuzzer);
                }
            } else if (WIFSIGNALED(event_msg)) {
                LOG_D("PID: %d terminated with signal: %lu", pid,
                      (unsigned long)WTERMSIG(event_msg));
            } else {
                LOG_D("PID: %d exited with unknown status: %lu", pid, event_msg);
            }
        }
        break;
    default:
        break;
    }

    ptrace(PT_CONTINUE, pid, 0, 0);
    return;
}

void arch_ptraceAnalyze(honggfuzz_t * hfuzz, int status, pid_t pid, fuzzer_t * fuzzer)
{
    /*
     * It's a ptrace event, deal with it elsewhere
     */
    if (WIFSTOPPED(status) && __WEVENT(status)) {
        return arch_ptraceEvent(hfuzz, fuzzer, status, pid);
    }

    if (WIFSTOPPED(status)) {
        /*
         * If it's an interesting signal, save the testcase
         */
        if (arch_sigs[WSTOPSIG(status)].important) {
            /*
             * If fuzzer worker is from core fuzzing process run full
             * analysis. Otherwise just unwind and get stack hash signature.
             */
            if (fuzzer->mainWorker) {
                arch_ptraceSaveData(hfuzz, pid, fuzzer);
            } else {
                arch_ptraceAnalyzeData(pid, fuzzer);
            }
        }
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
    if (WIFEXITED(status)) {
        return;
    }

    if (WIFSIGNALED(status)) {
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
        PLOG_E("Couldn't open dir '%s'", path);
        return false;
    }

    for (;;) {
        struct dirent de, *res;
        if (readdir_r(dir, &de, &res) > 0) {
            PLOG_E("Couldn't read contents of '%s'", path);
            closedir(dir);
            return false;
        }

        if (res == NULL) {
            break;
        }

        pid_t pid = (pid_t) strtol(res->d_name, (char **)NULL, 10);
        if (pid == 0) {
            LOG_D("The following dir entry couldn't be converted to pid_t '%s'", res->d_name);
            continue;
        }

        tasks[count++] = pid;
        LOG_D("Added pid '%d' from '%s/%s'", pid, path, res->d_name);

        if (count >= thrSz) {
            break;
        }
    }
    closedir(dir);
    PLOG_D("Total number of threads in pid '%d': '%zd'", pid, count);
    tasks[count + 1] = 0;
    if (count < 1) {
        return false;
    }
    return true;
}

bool arch_ptraceWaitForPidStop(pid_t pid)
{
    for (;;) {
        int status;
        pid_t ret = wait4(pid, &status, __WALL | WUNTRACED, NULL);
        if (ret == -1 && errno == EINTR) {
            continue;
        }
        if (ret == -1) {
            PLOG_W("wait4(pid=%d) failed", pid);
            return false;
        }
        if (!WIFSTOPPED(status)) {
            LOG_W("PID %d not in a stopped state - status:%d", pid, status);
            return false;
        }
        return true;
    }
}

#define MAX_THREAD_IN_TASK 4096
bool arch_ptraceAttach(pid_t pid)
{
    static const long seize_options =
        PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT;

    if (ptrace(PTRACE_SEIZE, pid, NULL, seize_options) == -1) {
        PLOG_W("Couldn't ptrace(PTRACE_SEIZE) to pid: %d", pid);
        return false;
    }

    LOG_D("Attached to PID: %d", pid);

    int tasks[MAX_THREAD_IN_TASK + 1] = { 0 };
    if (!arch_listThreads(tasks, MAX_THREAD_IN_TASK, pid)) {
        LOG_E("Couldn't read thread list for pid '%d'", pid);
        return false;
    }

    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        if (tasks[i] == pid) {
            continue;
        }
        if (ptrace(PTRACE_SEIZE, tasks[i], NULL, seize_options) == -1) {
            PLOG_W("Couldn't ptrace(PTRACE_SEIZE) to pid: %d", tasks[i]);
            continue;
        }
        LOG_D("Attached to PID: %d (thread_group:%d)", tasks[i], pid);
    }
    return true;
}

void arch_ptraceDetach(pid_t pid)
{
    if (kill(pid, 0) == -1 && errno == ESRCH) {
        LOG_D("PID: %d no longer exists", pid);
        return;
    }

    int tasks[MAX_THREAD_IN_TASK + 1] = { 0 };
    if (!arch_listThreads(tasks, MAX_THREAD_IN_TASK, pid)) {
        LOG_E("Couldn't read thread list for pid '%d'", pid);
        return;
    }

    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        ptrace(PTRACE_INTERRUPT, tasks[i], NULL, NULL);
        arch_ptraceWaitForPidStop(tasks[i]);
        ptrace(PTRACE_DETACH, tasks[i], NULL, NULL);
    }
}
