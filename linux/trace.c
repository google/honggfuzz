/*
 *
 * honggfuzz - architecture dependent code (LINUX/PTRACE)
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

#include "linux/trace.h"

#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "linux/bfd.h"
#include "linux/unwind.h"
#include "report.h"
#include "sanitizers.h"
#include "socketfuzzer.h"
#include "subproc.h"

#if defined(__ANDROID__)
#include "capstone/capstone.h"
#endif

#if defined(__i386__) || defined(__x86_64__)
#define MAX_INSTR_SZ 16
#elif defined(__arm__) || defined(__powerpc__) || defined(__powerpc64__)
#define MAX_INSTR_SZ 4
#elif defined(__aarch64__)
#define MAX_INSTR_SZ 8
#elif defined(__mips__) || defined(__mips64__)
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
#endif /* defined(__i386__) || defined(__x86_64__) */

#if defined(__arm__) || defined(__aarch64__)
#ifndef ARM_pc
#ifdef __ANDROID__ /* Building with NDK headers */
#define ARM_pc uregs[15]
#else /* Building with glibc headers */
#define ARM_pc 15
#endif
#endif /* ARM_pc */
#ifndef ARM_cpsr
#ifdef __ANDROID__ /* Building with NDK headers */
#define ARM_cpsr uregs[16]
#else /* Building with glibc headers */
#define ARM_cpsr 16
#endif
#endif /* ARM_cpsr */
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
#endif /* defined(__arm__) || defined(__aarch64__) */

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
#endif /* defined(__powerpc64__) || defined(__powerpc__) */

#if defined(__mips__) || defined(__mips64__)
struct user_regs_struct {
    uint64_t regs[32];

    uint64_t lo;
    uint64_t hi;
    uint64_t cp0_epc;
    uint64_t cp0_badvaddr;
    uint64_t cp0_status;
    uint64_t cp0_cause;
};
#define HEADERS_STRUCT struct user_regs_struct
#endif /* defined(__mips__) || defined(__mips64__) */

#if defined(__ANDROID__)
/*
 * Some Android ABIs don't implement PTRACE_GETREGS (e.g. aarch64)
 */
#if defined(PTRACE_GETREGS)
#define PTRACE_GETREGS_AVAILABLE 1
#else
#define PTRACE_GETREGS_AVAILABLE 0
#endif /* defined(PTRACE_GETREGS) */
#endif /* defined(__ANDROID__) */

static struct {
    const char* descr;
    bool        important;
} arch_sigs[_NSIG + 1] = {
    [0 ...(_NSIG)].important = false,
    [0 ...(_NSIG)].descr     = "UNKNOWN",

    [SIGTRAP].important = false,
    [SIGTRAP].descr     = "SIGTRAP",

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

    /* Is affected from tmoutVTALRM flag */
    [SIGVTALRM].important = false,
    [SIGVTALRM].descr     = "SIGVTALRM-TMOUT",

    /* seccomp-bpf kill */
    [SIGSYS].important = true,
    [SIGSYS].descr     = "SIGSYS",
};

#ifndef SI_FROMUSER
#define SI_FROMUSER(siptr) ((siptr)->si_code <= 0)
#endif /* SI_FROMUSER */

static size_t arch_getProcMem(pid_t pid, uint8_t* buf, size_t len, uint64_t pc) {
    /*
     * Let's try process_vm_readv first
     */
    const struct iovec local_iov = {
        .iov_base = buf,
        .iov_len  = len,
    };
    const struct iovec remote_iov = {
        .iov_base = (void*)(uintptr_t)pc,
        .iov_len  = len,
    };
    if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) == (ssize_t)len) {
        return len;
    }
    // Debug if failed since it shouldn't happen very often
    PLOG_D("process_vm_readv() failed");

    /*
     * Ok, let's do it via ptrace() then.
     * len must be aligned to the sizeof(long)
     */
    int    cnt   = len / sizeof(long);
    size_t memsz = 0;

    for (int x = 0; x < cnt; x++) {
        uint8_t* addr = (uint8_t*)(uintptr_t)pc + (int)(x * sizeof(long));
        long     ret  = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

        if (errno != 0) {
            PLOG_W("Couldn't PT_READ_D on pid %d, addr: %p", pid, addr);
            break;
        }

        memsz += sizeof(long);
        memcpy(&buf[x * sizeof(long)], &ret, sizeof(long));
    }
    return memsz;
}

static size_t arch_getPC(pid_t pid, uint64_t* pc, uint64_t* status_reg HF_ATTR_UNUSED) {
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
    const struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len  = sizeof(regs),
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
        struct user_regs_struct_32* r32 = (struct user_regs_struct_32*)&regs;
        *pc                             = r32->eip;
        *status_reg                     = r32->eflags;
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64* r64 = (struct user_regs_struct_64*)&regs;
        *pc                             = r64->ip;
        *status_reg                     = r64->flags;
        return pt_iov.iov_len;
    }
    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
    return 0;
#endif /* defined(__i386__) || defined(__x86_64__) */

#if defined(__arm__) || defined(__aarch64__)
    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32* r32 = (struct user_regs_struct_32*)&regs;
#ifdef __ANDROID__
        *pc         = r32->ARM_pc;
        *status_reg = r32->ARM_cpsr;
#else
        *pc         = r32->uregs[ARM_pc];
        *status_reg = r32->uregs[ARM_cpsr];
#endif
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64* r64 = (struct user_regs_struct_64*)&regs;
        *pc                             = r64->pc;
        *status_reg                     = r64->pstate;
        return pt_iov.iov_len;
    }
    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
    return 0;
#endif /* defined(__arm__) || defined(__aarch64__) */

#if defined(__powerpc64__) || defined(__powerpc__)
    /*
     * 32-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32* r32 = (struct user_regs_struct_32*)&regs;
        *pc                             = r32->nip;
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64* r64 = (struct user_regs_struct_64*)&regs;
        *pc                             = r64->nip;
        return pt_iov.iov_len;
    }

    LOG_W("Unknown registers structure size: '%zd'", pt_iov.iov_len);
    return 0;
#endif /* defined(__powerpc64__) || defined(__powerpc__) */

#if defined(__mips__) || defined(__mips64__)
    *pc = regs.cp0_epc;
    return pt_iov.iov_len;
#endif /* defined(__mips__) || defined(__mips64__) */

    LOG_D("Unknown/unsupported CPU architecture");
    return 0;
}

static void arch_getInstrStr(pid_t pid, uint64_t pc, uint64_t status_reg HF_ATTR_UNUSED,
    size_t pcRegSz HF_ATTR_UNUSED, char* instr) {
    /*
     * We need a value aligned to 8
     * which is sizeof(long) on 64bit CPU archs (on most of them, I hope;)
     */
    uint8_t buf[MAX_INSTR_SZ];
    size_t  memsz;

    snprintf(instr, _HF_INSTR_SZ, "%s", "[UNKNOWN]");

    if ((memsz = arch_getProcMem(pid, buf, sizeof(buf), pc)) == 0) {
        snprintf(instr, _HF_INSTR_SZ, "%s", "[NOT_MMAPED]");
        return;
    }
#if !defined(__ANDROID__)
#if !defined(_HF_LINUX_NO_BFD)
    arch_bfdDisasm(pid, buf, memsz, instr);
#endif /* !defined(_HF_LINUX_NO_BFD) */
#else  /* !defined(__ANDROID__) */
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
    LOG_E("Unknown/Unsupported Android CPU architecture");
#endif

    csh    handle;
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        LOG_W("Capstone initialization failed: '%s'", cs_strerror(err));
        return;
    }

    cs_insn* insn;
    size_t   count = cs_disasm(handle, buf, sizeof(buf), pc, 0, &insn);

    if (count < 1) {
        LOG_W("Couldn't disassemble the assembler instructions' stream: '%s'",
            cs_strerror(cs_errno(handle)));
        cs_close(&handle);
        return;
    }

    snprintf(instr, _HF_INSTR_SZ, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, count);
    cs_close(&handle);
#endif /* defined(__ANDROID__) */

    for (int x = 0; instr[x] && x < _HF_INSTR_SZ; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace(instr[x]) || !isprint(instr[x])) {
            instr[x] = '_';
        }
    }

    return;
}

static void arch_traceAnalyzeData(run_t* run, pid_t pid) {
    funcs_t* funcs = util_Calloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };

    uint64_t pc         = 0;
    uint64_t status_reg = 0;
    size_t   pcRegSz    = arch_getPC(pid, &pc, &status_reg);
    if (!pcRegSz) {
        LOG_W("ptrace arch_getPC failed");
        return;
    }

    uint64_t crashAddr               = 0;
    char     description[HF_STR_LEN] = {};
    size_t   funcCnt = sanitizers_parseReport(run, pid, funcs, &pc, &crashAddr, description);
    if (funcCnt <= 0) {
        funcCnt = arch_unwindStack(pid, funcs);
#if !defined(__ANDROID__)
#if !defined(_HF_LINUX_NO_BFD)
        arch_bfdResolveSyms(pid, funcs, funcCnt);
#endif /* !defined(_HF_LINUX_NO_BFD) */
#endif /* !defined(__ANDROID__) */
    }

#if !defined(__ANDROID__)
#if !defined(_HF_LINUX_NO_BFD)
    arch_bfdDemangle(funcs, funcCnt);
#endif /* !defined(_HF_LINUX_NO_BFD) */
#endif /* !defined(__ANDROID__) */

    /*
     * Calculate backtrace callstack hash signature
     */
    run->backtrace = sanitizers_hashCallstack(run, funcs, funcCnt, false);
}

static void arch_traceSaveData(run_t* run, pid_t pid) {
    char      instr[_HF_INSTR_SZ] = "\x00";
    siginfo_t si                  = {};

    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == -1) {
        PLOG_W("Couldn't get siginfo for pid %d", pid);
    }

    uint64_t crashAddr = (uint64_t)(uintptr_t)si.si_addr;
    /* User-induced signals don't set si.si_addr */
    if (SI_FROMUSER(&si)) {
        crashAddr = 0UL;
    }

    uint64_t pc         = 0;
    uint64_t status_reg = 0;
    size_t   pcRegSz    = arch_getPC(pid, &pc, &status_reg);
    if (!pcRegSz) {
        LOG_W("ptrace arch_getPC failed");
        return;
    }

    /*
     * Unwind and resolve symbols
     */
    funcs_t* funcs = util_Calloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };

    char   description[HF_STR_LEN] = {};
    size_t funcCnt = sanitizers_parseReport(run, pid, funcs, &pc, &crashAddr, description);
    if (funcCnt == 0) {
        funcCnt = arch_unwindStack(pid, funcs);
#if !defined(__ANDROID__)
#if !defined(_HF_LINUX_NO_BFD)
        arch_bfdResolveSyms(pid, funcs, funcCnt);
#endif /* !defined(_HF_LINUX_NO_BFD) */
#endif /* !defined(__ANDROID__) */
    }

#if !defined(__ANDROID__)
#if !defined(_HF_LINUX_NO_BFD)
    arch_bfdDemangle(funcs, funcCnt);
#endif /* !defined(_HF_LINUX_NO_BFD) */
#endif /* !defined(__ANDROID__) */
    arch_getInstrStr(pid, pc, status_reg, pcRegSz, instr);

    LOG_D("Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %" PRIx64 ", crashAddr: %" PRIx64
          " instr: '%s'",
        pid, si.si_signo, si.si_errno, si.si_code, si.si_addr, pc, crashAddr, instr);

    if (!SI_FROMUSER(&si) && pc &&
        crashAddr < (uint64_t)(uintptr_t)run->global->arch_linux.ignoreAddr) {
        LOG_I("Input is interesting (%s), but the si.si_addr is %p (below %p), skipping",
            util_sigName(si.si_signo), si.si_addr, run->global->arch_linux.ignoreAddr);
        return;
    }

    /*
     * Temp local copy of previous backtrace value in case worker hit crashes into multiple
     * tids for same target master thread. Will be 0 for first crash against target.
     */
    uint64_t oldBacktrace = run->backtrace;

    /* Local copy since flag is overridden for some crashes */
    bool saveUnique = run->global->io.saveUnique;

    /*
     * Calculate backtrace callstack hash signature
     */
    run->backtrace = sanitizers_hashCallstack(run, funcs, funcCnt, saveUnique);

    /*
     * If unique flag is set and single frame crash, disable uniqueness for this crash
     * to always save (timestamp will be added to the filename)
     */
    if (saveUnique && (funcCnt == 0)) {
        saveUnique = false;
    }

    /*
     * If worker crashFileName member is set, it means that a tid has already crashed
     * from target master thread.
     */
    if (run->crashFileName[0] != '\0') {
        LOG_D("Multiple crashes detected from worker against attached tids group");

        /*
         * If stackhashes match, don't re-analyze. This will avoid duplicates
         * and prevent verifier from running multiple passes. Depth of check is
         * always 1 (last backtrace saved only per target iteration).
         */
        if (oldBacktrace == run->backtrace) {
            return;
        }
    }

    /* Increase global crashes counter */
    ATOMIC_POST_INC(run->global->cnts.crashesCnt);

    /*
     * Check if backtrace contains whitelisted symbol. Whitelist overrides
     * both stackhash and symbol blacklist. Crash is always kept regardless
     * of the status of uniqueness flag.
     */
    if (run->global->arch_linux.symsWl) {
        char* wlSymbol = arch_btContainsSymbol(
            run->global->arch_linux.symsWlCnt, run->global->arch_linux.symsWl, funcCnt, funcs);
        if (wlSymbol != NULL) {
            saveUnique = false;
            LOG_D("Whitelisted symbol '%s' found, skipping blacklist checks", wlSymbol);
        }
    } else {
        /*
         * Check if stackhash is blacklisted
         */
        if (run->global->feedback.blacklist &&
            (fastArray64Search(run->global->feedback.blacklist, run->global->feedback.blacklistCnt,
                 run->backtrace) != -1)) {
            LOG_I("Blacklisted stack hash '%" PRIx64 "', skipping", run->backtrace);
            ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
            return;
        }

        /*
         * Check if backtrace contains blacklisted symbol
         */
        char* blSymbol = arch_btContainsSymbol(
            run->global->arch_linux.symsBlCnt, run->global->arch_linux.symsBl, funcCnt, funcs);
        if (blSymbol != NULL) {
            LOG_I("Blacklisted symbol '%s' found, skipping", blSymbol);
            ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
            return;
        }
    }

    /* If non-blacklisted crash detected, zero set two MSB */
    ATOMIC_POST_ADD(run->global->cfg.dynFileIterExpire, _HF_DYNFILE_SUB_MASK);

    /* Those addresses will be random, so depend on stack-traces for uniqueness */
    if (!run->global->arch_linux.disableRandomization) {
        pc        = 0UL;
        crashAddr = 0UL;
    }
    /* crashAddr (si.si_addr) never makes sense for SIGABRT */
    if (si.si_signo == SIGABRT) {
        crashAddr = 0UL;
    }

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->dynfile->path);
    } else if (saveUnique) {
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIx64 ".STACK.%" PRIx64 ".CODE.%d.ADDR.%" PRIx64 ".INSTR.%s.%s",
            run->global->io.crashDir, util_sigName(si.si_signo), pc, run->backtrace, si.si_code,
            crashAddr, instr, run->global->io.fileExtn);
    } else {
        char localtmstr[HF_STR_LEN];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIx64 ".STACK.%" PRIx64 ".CODE.%d.ADDR.%" PRIx64 ".INSTR.%s.%s.%d.%s",
            run->global->io.crashDir, util_sigName(si.si_signo), pc, run->backtrace, si.si_code,
            crashAddr, instr, localtmstr, pid, run->global->io.fileExtn);
    }

    /* Target crashed (no duplicate detection yet) */
    if (run->global->socketFuzzer.enabled) {
        LOG_D("SocketFuzzer: trace: Crash Identified");
    }

    if (files_exists(run->crashFileName)) {
        LOG_I("Crash (dup): '%s' already exists, skipping", run->crashFileName);
        /* Clear filename so that verifier can understand we hit a duplicate */
        memset(run->crashFileName, 0, sizeof(run->crashFileName));
        return;
    }

    if (!files_writeBufToFile(run->crashFileName, run->dynfile->data, run->dynfile->size,
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC)) {
        LOG_E("Couldn't write to '%s'", run->crashFileName);
        return;
    }

    /* Unique new crash, notify fuzzer */
    if (run->global->socketFuzzer.enabled) {
        LOG_D("SocketFuzzer: trace: New Uniqu Crash");
        fuzz_notifySocketFuzzerCrash(run);
    }
    LOG_I("Crash: saved as '%s'", run->crashFileName);

    ATOMIC_POST_INC(run->global->cnts.uniqueCrashesCnt);
    /* If unique crash found, reset dynFile counter */
    ATOMIC_CLEAR(run->global->cfg.dynFileIterExpire);

    report_appendReport(pid, run, funcs, funcCnt, pc, crashAddr, si.si_signo, instr, description);
}

#define __WEVENT(status) ((status & 0xFF0000) >> 16)
static void arch_traceEvent(int status, pid_t pid) {
    LOG_D("PID: %d, Ptrace event: %d", pid, __WEVENT(status));
    switch (__WEVENT(status)) {
        case PTRACE_EVENT_EXIT: {
            unsigned long event_msg;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_msg) == -1) {
                PLOG_E("ptrace(PTRACE_GETEVENTMSG,%d) failed", pid);
                return;
            }

            if (WIFEXITED(event_msg)) {
                LOG_D("PID: %d exited with exit_code: %lu", pid,
                    (unsigned long)WEXITSTATUS(event_msg));
            } else if (WIFSIGNALED(event_msg)) {
                LOG_D(
                    "PID: %d terminated with signal: %lu", pid, (unsigned long)WTERMSIG(event_msg));
            } else {
                LOG_D("PID: %d exited with unknown status: %lu (%s)", pid, event_msg,
                    subproc_StatusToStr(event_msg));
            }
        } break;
        default:
            break;
    }

    ptrace(PTRACE_CONT, pid, 0, 0);
}

void arch_traceAnalyze(run_t* run, int status, pid_t pid) {
    /*
     * It's a ptrace event, deal with it elsewhere
     */
    if (WIFSTOPPED(status) && __WEVENT(status)) {
        return arch_traceEvent(status, pid);
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
            if (run->mainWorker) {
                arch_traceSaveData(run, pid);
            } else {
                arch_traceAnalyzeData(run, pid);
            }
        }
        /* Do not deliver SIGSTOP, as we don't support PTRACE_LISTEN anyway */
        int sig = (WSTOPSIG(status) != SIGSTOP) ? WSTOPSIG(status) : 0;
        ptrace(PTRACE_CONT, pid, 0, sig);
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

    abort(); /* NOTREACHED */
}

static bool arch_listThreads(int tasks[], size_t thrSz, int pid) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    /* An optimization, the number of threads is st.st_nlink - 2 (. and ..) */
    struct stat st;
    if (stat(path, &st) != -1) {
        if (st.st_nlink == 3) {
            tasks[0] = pid;
            tasks[1] = 0;
            return true;
        }
    }

    size_t count = 0;
    DIR*   dir   = opendir(path);
    if (!dir) {
        PLOG_E("Couldn't open dir '%s'", path);
        return false;
    }
    defer {
        closedir(dir);
    };

    for (;;) {
        errno                    = 0;
        const struct dirent* res = readdir(dir);
        if (res == NULL && errno != 0) {
            PLOG_E("Couldn't read contents of '%s'", path);
            return false;
        }

        if (res == NULL) {
            break;
        }

        pid_t pid = (pid_t)strtol(res->d_name, (char**)NULL, 10);
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
    PLOG_D("Total number of threads in pid '%d': '%zd'", pid, count);
    tasks[count + 1] = 0;
    if (count < 1) {
        return false;
    }
    return true;
}

bool arch_traceWaitForPidStop(pid_t pid) {
    for (;;) {
        int   status;
        pid_t ret = wait4(pid, &status, __WALL | WUNTRACED, NULL);
        if (ret == -1 && errno == EINTR) {
            continue;
        }
        if (ret == -1) {
            PLOG_W("wait4(pid=%d) failed", pid);
            return false;
        }
        if (!WIFSTOPPED(status)) {
            LOG_W("PID %d not in a stopped state - status:%d (%s)", pid, status,
                subproc_StatusToStr(status));
            return false;
        }
        return true;
    }
}

#define MAX_THREAD_IN_TASK 4096
bool arch_traceAttach(run_t* run) {
/*
 * It should be present since, at least, Linux kernel 3.8, but
 * not always defined in kernel-headers
 */
#if !defined(PTRACE_O_EXITKILL)
#define PTRACE_O_EXITKILL (1 << 20)
#endif /* !defined(PTRACE_O_EXITKILL) */
    long seize_options =
        PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL;
    /* The event is only used with sanitizers */
    if (run->global->sanitizer.enable) {
        seize_options |= PTRACE_O_TRACEEXIT;
    }

    if (!arch_traceWaitForPidStop(run->pid)) {
        return false;
    }

    if (ptrace(PTRACE_SEIZE, run->pid, NULL, seize_options) == -1) {
        PLOG_W("Couldn't ptrace(PTRACE_SEIZE) to pid: %d", (int)run->pid);
        return false;
    }

    LOG_D("Attached to PID: %d", (int)run->pid);

    int tasks[MAX_THREAD_IN_TASK + 1] = {0};
    if (!arch_listThreads(tasks, MAX_THREAD_IN_TASK, run->pid)) {
        LOG_E("Couldn't read thread list for pid '%d'", run->pid);
        return false;
    }

    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        if (tasks[i] == run->pid) {
            continue;
        }
        if (ptrace(PTRACE_SEIZE, tasks[i], NULL, seize_options) == -1) {
            PLOG_W("Couldn't ptrace(PTRACE_SEIZE) to pid: %d", tasks[i]);
            continue;
        }
        LOG_D("Attached to PID: %d (thread_group:%d)", tasks[i], run->pid);
    }

    if (ptrace(PTRACE_CONT, run->pid, NULL, NULL) == -1) {
        PLOG_W("ptrace(PTRACE_CONT) to pid: %d", (int)run->pid);
    }

    return true;
}

void arch_traceDetach(pid_t pid) {
    if (syscall(__NR_kill, pid, 0) == -1 && errno == ESRCH) {
        LOG_D("PID: %d no longer exists", pid);
        return;
    }

    int tasks[MAX_THREAD_IN_TASK + 1] = {0};
    if (!arch_listThreads(tasks, MAX_THREAD_IN_TASK, pid)) {
        LOG_E("Couldn't read thread list for pid '%d'", pid);
        return;
    }

    for (int i = 0; i < MAX_THREAD_IN_TASK && tasks[i]; i++) {
        ptrace(PTRACE_INTERRUPT, tasks[i], NULL, NULL);
        arch_traceWaitForPidStop(tasks[i]);
        ptrace(PTRACE_DETACH, tasks[i], NULL, NULL);
    }
}

void arch_traceSignalsInit(honggfuzz_t* hfuzz) {
    /* Default is false */
    arch_sigs[SIGVTALRM].important = hfuzz->timing.tmoutVTALRM;

    /* Let *SAN handle it, if it's enabled */
    if (hfuzz->sanitizer.enable) {
        LOG_I("Sanitizer support enabled. SIGSEGV/SIGBUS/SIGILL/SIGFPE will not be reported, and "
              "should be handled by *SAN code internally");
        arch_sigs[SIGSEGV].important = false;
        arch_sigs[SIGBUS].important  = false;
        arch_sigs[SIGILL].important  = false;
        arch_sigs[SIGFPE].important  = false;
    }
}
