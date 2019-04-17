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
#include "sanitizers.h"
#include "socketfuzzer.h"
#include "subproc.h"

#if defined(__ANDROID__)
#include "capstone.h"
#endif

#if defined(__i386__) || defined(__arm__) || defined(__powerpc__)
#define REG_TYPE uint32_t
#define REG_PM PRIx32
#define REG_PD "0x%08"
#elif defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__) || \
    defined(__mips__) || defined(__mips64__)
#define REG_TYPE uint64_t
#define REG_PM PRIx64
#define REG_PD "0x%016"
#endif

/*
 * Size in characters required to store a string representation of a
 * register value (0xdeadbeef style))
 */
#define REGSIZEINCHAR (2 * sizeof(REG_TYPE) + 3)

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
    bool important;
} arch_sigs[_NSIG + 1] = {
    [0 ...(_NSIG)].important = false,
    [0 ...(_NSIG)].descr = "UNKNOWN",

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

    /* Is affected from monitorSIGABRT flag */
    [SIGABRT].important = false,
    [SIGABRT].descr = "SIGABRT",

    /* Is affected from tmoutVTALRM flag */
    [SIGVTALRM].important = false,
    [SIGVTALRM].descr = "SIGVTALRM-TMOUT",

    /* seccomp-bpf kill */
    [SIGSYS].important = true,
    [SIGSYS].descr = "SIGSYS",
};

#ifndef SI_FROMUSER
#define SI_FROMUSER(siptr) ((siptr)->si_code <= 0)
#endif /* SI_FROMUSER */

extern const char* sys_sigabbrev[];

static __thread char arch_signame[32];
static const char* arch_sigName(int signo) {
    if (signo < 0 || signo > _NSIG) {
        snprintf(arch_signame, sizeof(arch_signame), "UNKNOWN-%d", signo);
        return arch_signame;
    }
    if (signo > __SIGRTMIN) {
        snprintf(arch_signame, sizeof(arch_signame), "SIG%d-RTMIN+%d", signo, signo - __SIGRTMIN);
        return arch_signame;
    }
#ifdef __ANDROID__
    return arch_sigs[signo].descr;
#else
    if (sys_sigabbrev[signo] == NULL) {
        snprintf(arch_signame, sizeof(arch_signame), "SIG%d", signo);
    } else {
        snprintf(arch_signame, sizeof(arch_signame), "SIG%s", sys_sigabbrev[signo]);
    }
    return arch_signame;
#endif /* __ANDROID__ */
}

static size_t arch_getProcMem(pid_t pid, uint8_t* buf, size_t len, REG_TYPE pc) {
    /*
     * Let's try process_vm_readv first
     */
    const struct iovec local_iov = {
        .iov_base = buf,
        .iov_len = len,
    };
    const struct iovec remote_iov = {
        .iov_base = (void*)(uintptr_t)pc,
        .iov_len = len,
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
    int cnt = len / sizeof(long);
    size_t memsz = 0;

    for (int x = 0; x < cnt; x++) {
        uint8_t* addr = (uint8_t*)(uintptr_t)pc + (int)(x * sizeof(long));
        long ret = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

        if (errno != 0) {
            PLOG_W("Couldn't PT_READ_D on pid %d, addr: %p", pid, addr);
            break;
        }

        memsz += sizeof(long);
        memcpy(&buf[x * sizeof(long)], &ret, sizeof(long));
    }
    return memsz;
}

static size_t arch_getPC(pid_t pid, REG_TYPE* pc, REG_TYPE* status_reg HF_ATTR_UNUSED) {
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
        struct user_regs_struct_32* r32 = (struct user_regs_struct_32*)&regs;
        *pc = r32->eip;
        *status_reg = r32->eflags;
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64* r64 = (struct user_regs_struct_64*)&regs;
        *pc = r64->ip;
        *status_reg = r64->flags;
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
        struct user_regs_struct_64* r64 = (struct user_regs_struct_64*)&regs;
        *pc = r64->pc;
        *status_reg = r64->pstate;
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
        *pc = r32->nip;
        return pt_iov.iov_len;
    }

    /*
     * 64-bit
     */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64* r64 = (struct user_regs_struct_64*)&regs;
        *pc = r64->nip;
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

static void arch_getInstrStr(pid_t pid, REG_TYPE* pc, char* instr) {
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
    LOG_E("Unknown/Unsupported Android CPU architecture");
#endif

    csh handle;
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        LOG_W("Capstone initialization failed: '%s'", cs_strerror(err));
        return;
    }

    cs_insn* insn;
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
#endif /* defined(__ANDROID__) */

    for (int x = 0; instr[x] && x < _HF_INSTR_SZ; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace(instr[x]) || !isprint(instr[x])) {
            instr[x] = '_';
        }
    }

    return;
}

static void arch_hashCallstack(run_t* run, funcs_t* funcs, size_t funcCnt, bool enableMasking) {
    uint64_t hash = 0;
    for (size_t i = 0; i < funcCnt && i < run->global->linux.numMajorFrames; i++) {
        /*
         * Convert PC to char array to be compatible with hash function
         */
        char pcStr[REGSIZEINCHAR] = {0};
        snprintf(pcStr, REGSIZEINCHAR, REG_PD REG_PM, (REG_TYPE)(long)funcs[i].pc);

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
        hash |= _HF_SINGLE_FRAME_MASK;
    }
    run->backtrace = hash;
}

static void arch_traceGenerateReport(
    pid_t pid, run_t* run, funcs_t* funcs, size_t funcCnt, siginfo_t* si, const char* instr) {
    run->report[0] = '\0';
    util_ssnprintf(run->report, sizeof(run->report), "ORIG_FNAME: %s\n", run->origFileName);
    util_ssnprintf(run->report, sizeof(run->report), "FUZZ_FNAME: %s\n", run->crashFileName);
    util_ssnprintf(run->report, sizeof(run->report), "PID: %d\n", pid);
    util_ssnprintf(run->report, sizeof(run->report), "SIGNAL: %s (%d)\n",
        arch_sigName(si->si_signo), si->si_signo);
    util_ssnprintf(run->report, sizeof(run->report), "FAULT ADDRESS: %p\n",
        SI_FROMUSER(si) ? NULL : si->si_addr);
    util_ssnprintf(run->report, sizeof(run->report), "INSTRUCTION: %s\n", instr);
    util_ssnprintf(
        run->report, sizeof(run->report), "STACK HASH: %016" PRIx64 "\n", run->backtrace);
    util_ssnprintf(run->report, sizeof(run->report), "STACK:\n");
    for (size_t i = 0; i < funcCnt; i++) {
#ifdef __HF_USE_CAPSTONE__
        util_ssnprintf(
            run->report, sizeof(run->report), " <" REG_PD REG_PM "> ", (REG_TYPE)(long)funcs[i].pc);
        if (funcs[i].func[0] != '\0')
            util_ssnprintf(run->report, sizeof(run->report), "[%s() + 0x%x at %s]\n", funcs[i].func,
                funcs[i].line, funcs[i].mapName);
        else
            util_ssnprintf(run->report, sizeof(run->report), "[]\n");
#else
        util_ssnprintf(run->report, sizeof(run->report), " <" REG_PD REG_PM "> [%s():%zu at %s]\n",
            (REG_TYPE)(long)funcs[i].pc, funcs[i].func, funcs[i].line, funcs[i].mapName);
#endif
    }

// libunwind is not working for 32bit targets in 64bit systems
#if defined(__aarch64__)
    if (funcCnt == 0) {
        util_ssnprintf(run->report, sizeof(run->report),
            " !ERROR: If 32bit fuzz target"
            " in aarch64 system, try ARM 32bit build\n");
    }
#endif

    return;
}

static void arch_traceAnalyzeData(run_t* run, pid_t pid) {
    REG_TYPE pc = 0, status_reg = 0;
    size_t pcRegSz = arch_getPC(pid, &pc, &status_reg);
    if (!pcRegSz) {
        LOG_W("ptrace arch_getPC failed");
        return;
    }

    /*
     * Unwind and resolve symbols
     */
    funcs_t* funcs = util_Malloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };
    memset(funcs, 0, _HF_MAX_FUNCS * sizeof(funcs_t));

#if !defined(__ANDROID__)
    size_t funcCnt = arch_unwindStack(pid, funcs);
    arch_bfdResolveSyms(pid, funcs, funcCnt);
#else
    size_t funcCnt = arch_unwindStack(pid, funcs);
#endif

    /*
     * If unwinder failed (zero frames), use PC from ptrace GETREGS if not zero.
     * If PC reg zero return and callers should handle zero hash case.
     */
    if (funcCnt == 0) {
        if (pc) {
            /* Manually update major frame PC & frames counter */
            funcs[0].pc = (void*)(uintptr_t)pc;
            funcCnt = 1;
        } else {
            return;
        }
    }

    /*
     * Calculate backtrace callstack hash signature
     */
    arch_hashCallstack(run, funcs, funcCnt, false);
}

static void arch_traceSaveData(run_t* run, pid_t pid) {
    REG_TYPE pc = 0;

    /* Local copy since flag is overridden for some crashes */
    bool saveUnique = run->global->io.saveUnique;

    char instr[_HF_INSTR_SZ] = "\x00";
    siginfo_t si;
    bzero(&si, sizeof(si));

    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == -1) {
        PLOG_W("Couldn't get siginfo for pid %d", pid);
    }

    arch_getInstrStr(pid, &pc, instr);

    LOG_D("Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %" REG_PM ", instr: '%s'", pid,
        si.si_signo, si.si_errno, si.si_code, si.si_addr, pc, instr);

    if (!SI_FROMUSER(&si) && pc && si.si_addr < run->global->linux.ignoreAddr) {
        LOG_I("Input is interesting (%s), but the si.si_addr is %p (below %p), skipping",
            arch_sigName(si.si_signo), si.si_addr, run->global->linux.ignoreAddr);
        return;
    }

    /*
     * Unwind and resolve symbols
     */
    funcs_t* funcs = util_Malloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };
    memset(funcs, 0, _HF_MAX_FUNCS * sizeof(funcs_t));

#if !defined(__ANDROID__)
    size_t funcCnt = arch_unwindStack(pid, funcs);
    arch_bfdResolveSyms(pid, funcs, funcCnt);
#else
    size_t funcCnt = arch_unwindStack(pid, funcs);
#endif

    /*
     * If unwinder failed (zero frames), use PC from ptrace GETREGS if not zero.
     * If PC reg zero, temporarily disable uniqueness flag since callstack
     * hash will be also zero, thus not safe for unique decisions.
     */
    if (funcCnt == 0) {
        if (pc) {
            /* Manually update major frame PC & frames counter */
            funcs[0].pc = (void*)(uintptr_t)pc;
            funcCnt = 1;
        } else {
            saveUnique = false;
        }
    }

    /*
     * Temp local copy of previous backtrace value in case worker hit crashes into multiple
     * tids for same target master thread. Will be 0 for first crash against target.
     */
    uint64_t oldBacktrace = run->backtrace;

    /*
     * Calculate backtrace callstack hash signature
     */
    arch_hashCallstack(run, funcs, funcCnt, saveUnique);

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
    if (run->global->linux.symsWl) {
        char* wlSymbol = arch_btContainsSymbol(
            run->global->linux.symsWlCnt, run->global->linux.symsWl, funcCnt, funcs);
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
            run->global->linux.symsBlCnt, run->global->linux.symsBl, funcCnt, funcs);
        if (blSymbol != NULL) {
            LOG_I("Blacklisted symbol '%s' found, skipping", blSymbol);
            ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
            return;
        }
    }

    /* If non-blacklisted crash detected, zero set two MSB */
    ATOMIC_POST_ADD(run->global->cfg.dynFileIterExpire, _HF_DYNFILE_SUB_MASK);

    void* sig_addr = si.si_addr;
    if (!run->global->linux.disableRandomization) {
        pc = 0UL;
        sig_addr = NULL;
    }

    /* User-induced signals don't set si.si_addr */
    if (SI_FROMUSER(&si)) {
        sig_addr = NULL;
    }

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->origFileName);
    } else if (saveUnique) {
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" REG_PM ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s",
            run->global->io.crashDir, arch_sigName(si.si_signo), pc, run->backtrace, si.si_code,
            sig_addr, instr, run->global->io.fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" REG_PM ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s",
            run->global->io.crashDir, arch_sigName(si.si_signo), pc, run->backtrace, si.si_code,
            sig_addr, instr, localtmstr, pid, run->global->io.fileExtn);
    }

    /* Target crashed (no duplicate detection yet) */
    if (run->global->socketFuzzer.enabled) {
        LOG_D("SocketFuzzer: trace: Crash Identified");
    }

    if (files_exists(run->crashFileName)) {
        LOG_I("Crash (dup): '%s' already exists, skipping", run->crashFileName);
        // Clear filename so that verifier can understand we hit a duplicate
        memset(run->crashFileName, 0, sizeof(run->crashFileName));
        return;
    }

    if (!files_writeBufToFile(run->crashFileName, run->dynamicFile, run->dynamicFileSz,
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

    arch_traceGenerateReport(pid, run, funcs, funcCnt, &si, instr);
}

/* TODO: Add report parsing support for other sanitizers too */
static int arch_parseAsanReport(
    run_t* run, pid_t pid, funcs_t* funcs, void** crashAddr, char** op) {
    char crashReport[PATH_MAX] = {0};
    const char* const crashReportCpy = crashReport;
    snprintf(
        crashReport, sizeof(crashReport), "%s/%s.%d", run->global->io.workDir, kLOGPREFIX, pid);

    FILE* fReport = fopen(crashReport, "rb");
    if (fReport == NULL) {
        PLOG_D("Couldn't open '%s' - R/O mode", crashReport);
        return -1;
    }
    defer {
        fclose(fReport);
    };
    defer {
        unlink(crashReportCpy);
    };

    char header[35] = {0};
    snprintf(header, sizeof(header), "==%d==ERROR: AddressSanitizer:", pid);
    size_t headerSz = strlen(header);
    bool headerFound = false;

    uint8_t frameIdx = 0;
    char framePrefix[5] = {0};
    snprintf(framePrefix, sizeof(framePrefix), "#%" PRIu8, frameIdx);

    char *lineptr = NULL, *cAddr = NULL;
    size_t n = 0;
    defer {
        free(lineptr);
    };
    for (;;) {
        if (getline(&lineptr, &n, fReport) == -1) {
            break;
        }

        /* First step is to identify header */
        if (!headerFound) {
            if ((strlen(lineptr) > headerSz) && (strncmp(header, lineptr, headerSz) == 0)) {
                headerFound = true;

                /* Parse crash address */
                cAddr = strstr(lineptr, "address 0x");
                if (cAddr) {
                    cAddr = cAddr + strlen("address ");
                    char* endOff = strchr(cAddr, ' ');
                    cAddr[endOff - cAddr] = '\0';
                    *crashAddr = (void*)((size_t)strtoull(cAddr, NULL, 16));
                } else {
                    *crashAddr = 0x0;
                }
            }
            continue;
        } else {
            char* pLineLC = lineptr;
            /* Trim leading spaces */
            while (*pLineLC != '\0' && isspace(*pLineLC)) {
                ++pLineLC;
            }

            /* End separator for crash thread stack trace is an empty line */
            if ((*pLineLC == '\0') && (frameIdx != 0)) {
                break;
            }

            /* Basic length checks */
            if (strlen(pLineLC) < 10) {
                continue;
            }

            /* If available parse the type of error (READ/WRITE) */
            if (cAddr && strstr(pLineLC, cAddr)) {
                if (strncmp(pLineLC, "READ", 4) == 0) {
                    *op = "READ";
                } else if (strncmp(pLineLC, "WRITE", 5) == 0) {
                    *op = "WRITE";
                }
                cAddr = NULL;
            }

            /* Check for crash thread frames */
            if (strncmp(pLineLC, framePrefix, strlen(framePrefix)) == 0) {
                /* Abort if max depth */
                if (frameIdx >= _HF_MAX_FUNCS) {
                    break;
                }

                /*
                 * Frames have following format:
                 #0 0xaa860177  (/system/lib/libc.so+0x196177)
                 */
                char* savePtr = NULL;
                strtok_r(pLineLC, " ", &savePtr);
                funcs[frameIdx].pc =
                    (void*)((size_t)strtoull(strtok_r(NULL, " ", &savePtr), NULL, 16));

                /* DSO & code offset parsing */
                char* targetStr = strtok_r(NULL, " ", &savePtr);
                char* startOff = strchr(targetStr, '(') + 1;
                char* plusOff = strchr(targetStr, '+');
                char* endOff = strrchr(targetStr, ')');
                targetStr[endOff - startOff] = '\0';
                if ((startOff == NULL) || (endOff == NULL) || (plusOff == NULL)) {
                    LOG_D("Invalid ASan report entry (%s)", lineptr);
                } else {
                    size_t dsoSz =
                        MIN(sizeof(funcs[frameIdx].mapName), (size_t)(plusOff - startOff));
                    memcpy(funcs[frameIdx].mapName, startOff, dsoSz);
                    char* codeOff = targetStr + (plusOff - startOff) + 1;
                    funcs[frameIdx].line = strtoull(codeOff, NULL, 16);
                }

                frameIdx++;
                snprintf(framePrefix, sizeof(framePrefix), "#%" PRIu8, frameIdx);
            }
        }
    }

    return frameIdx;
}

/*
 * Special book keeping for cases where crashes are detected based on exitcode and not
 * a raised signal. Such case is the ASan fuzzing for Android. Crash file name maintains
 * the same format for compatibility with post campaign tools.
 */
static void arch_traceExitSaveData(run_t* run, pid_t pid) {
    REG_TYPE pc = 0;
    void* crashAddr = 0;
    char* op = "UNKNOWN";

    /* Save only the first hit for each worker */
    if (run->crashFileName[0] != '\0') {
        return;
    }

    /* Increase global crashes counter */
    ATOMIC_POST_INC(run->global->cnts.crashesCnt);
    ATOMIC_POST_AND(run->global->cfg.dynFileIterExpire, _HF_DYNFILE_SUB_MASK);

    /* If sanitizer produces reports with stack traces (e.g. ASan), they're parsed manually */
    int funcCnt = 0;
    funcs_t* funcs = util_Malloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };
    memset(funcs, 0, _HF_MAX_FUNCS * sizeof(funcs_t));

    /* Sanitizers save reports against parent PID */
    if (run->pid != pid) {
        return;
    }
    funcCnt = arch_parseAsanReport(run, pid, funcs, &crashAddr, &op);

    /*
     * -1 error indicates a file not found for report. This is expected to happen often since
     * ASan report is generated once for crashing TID. Ptrace arch is not guaranteed to parse
     * that TID first. Not setting the 'crashFileName' variable will ensure that this branch
     * is executed again for all TIDs until the matching report is found
     */
    if (funcCnt == -1) {
        return;
    }

    /* Since crash address is available, apply ignoreAddr filters */
    if (crashAddr < run->global->linux.ignoreAddr) {
        LOG_I("Input is interesting, but the crash addr is %p (below %p), skipping", crashAddr,
            run->global->linux.ignoreAddr);
        return;
    }

    /* If frames successfully recovered, calculate stack hash & populate crash PC */
    arch_hashCallstack(run, funcs, funcCnt, false);
    pc = (uintptr_t)funcs[0].pc;

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

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->origFileName);
    } else {
        /* Keep the crashes file name format identical */
        if (run->backtrace != 0ULL && run->global->io.saveUnique) {
            snprintf(run->crashFileName, sizeof(run->crashFileName),
                "%s/%s.PC.%" REG_PM ".STACK.%" PRIx64 ".CODE.%s.ADDR.%p.INSTR.%s.%s",
                run->global->io.crashDir, "SAN", pc, run->backtrace, op, crashAddr, "[UNKNOWN]",
                run->global->io.fileExtn);
        } else {
            /* If no stack hash available, all crashes treated as unique */
            char localtmstr[PATH_MAX];
            util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
            snprintf(run->crashFileName, sizeof(run->crashFileName),
                "%s/%s.PC.%" REG_PM ".STACK.%" PRIx64 ".CODE.%s.ADDR.%p.INSTR.%s.%s.%s",
                run->global->io.crashDir, "SAN", pc, run->backtrace, op, crashAddr, "[UNKNOWN]",
                localtmstr, run->global->io.fileExtn);
        }
    }

    int fd = TEMP_FAILURE_RETRY(open(run->crashFileName, O_WRONLY | O_EXCL | O_CREAT, 0600));
    if (fd == -1 && errno == EEXIST) {
        LOG_I("It seems that '%s' already exists, skipping", run->crashFileName);
        return;
    } else if (fd == -1) {
        PLOG_E("Cannot create output file '%s'", run->crashFileName);
        return;
    } else {
        defer {
            close(fd);
        };
        if (files_writeToFd(fd, run->dynamicFile, run->dynamicFileSz)) {
            LOG_I("Ok, that's interesting, saved new crash as '%s'", run->crashFileName);
            /* Clear stack hash so that verifier can understand we hit a duplicate */
            run->backtrace = 0ULL;
            /* Increase unique crashes counters */
            ATOMIC_POST_INC(run->global->cnts.uniqueCrashesCnt);
            ATOMIC_CLEAR(run->global->cfg.dynFileIterExpire);
        } else {
            LOG_E("Couldn't save crash to '%s'", run->crashFileName);
            /* In case of write error, clear crashFileName to so that other monitored TIDs can retry
             */
            memset(run->crashFileName, 0, sizeof(run->crashFileName));
            return;
        }
    }

    /* Generate report */
    run->report[0] = '\0';
    util_ssnprintf(run->report, sizeof(run->report), "EXIT_CODE: %d\n", HF_SAN_EXIT_CODE);
    util_ssnprintf(run->report, sizeof(run->report), "ORIG_FNAME: %s\n", run->origFileName);
    util_ssnprintf(run->report, sizeof(run->report), "FUZZ_FNAME: %s\n", run->crashFileName);
    util_ssnprintf(run->report, sizeof(run->report), "PID: %d\n", pid);
    util_ssnprintf(run->report, sizeof(run->report), "OPERATION: %s\n", op);
    util_ssnprintf(run->report, sizeof(run->report), "FAULT ADDRESS: %p\n", crashAddr);
    if (funcCnt > 0) {
        util_ssnprintf(
            run->report, sizeof(run->report), "STACK HASH: %016" PRIx64 "\n", run->backtrace);
        util_ssnprintf(run->report, sizeof(run->report), "STACK:\n");
        for (int i = 0; i < funcCnt; i++) {
            util_ssnprintf(run->report, sizeof(run->report), " <" REG_PD REG_PM "> ",
                (REG_TYPE)(long)funcs[i].pc);
            if (funcs[i].mapName[0] != '\0') {
                util_ssnprintf(run->report, sizeof(run->report), "[%s + 0x%zx]\n", funcs[i].mapName,
                    funcs[i].line);
            } else {
                util_ssnprintf(run->report, sizeof(run->report), "[]\n");
            }
        }
    }
}

static void arch_traceExitAnalyzeData(run_t* run, pid_t pid) {
    void* crashAddr = 0;
    char* op = "UNKNOWN";
    int funcCnt = 0;
    funcs_t* funcs = util_Malloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };
    memset(funcs, 0, _HF_MAX_FUNCS * sizeof(funcs_t));

    funcCnt = arch_parseAsanReport(run, pid, funcs, &crashAddr, &op);

    /*
     * -1 error indicates a file not found for report. This is expected to happen often since
     * ASan report is generated once for crashing TID. Ptrace arch is not guaranteed to parse
     * that TID first. Not setting the 'crashFileName' variable will ensure that this branch
     * is executed again for all TIDs until the matching report is found
     */
    if (funcCnt == -1) {
        return;
    }

    /* If frames successfully recovered, calculate stack hash & populate crash PC */
    arch_hashCallstack(run, funcs, funcCnt, false);
}

void arch_traceExitAnalyze(run_t* run, pid_t pid) {
    if (run->mainWorker) {
        /* Main fuzzing threads */
        arch_traceExitSaveData(run, pid);
    } else {
        /* Post crash analysis (e.g. crashes verifier) */
        arch_traceExitAnalyzeData(run, pid);
    }
}

#define __WEVENT(status) ((status & 0xFF0000) >> 16)
static void arch_traceEvent(run_t* run, int status, pid_t pid) {
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
                if (WEXITSTATUS(event_msg) == (unsigned long)HF_SAN_EXIT_CODE) {
                    arch_traceExitAnalyze(run, pid);
                }
            } else if (WIFSIGNALED(event_msg)) {
                LOG_D(
                    "PID: %d terminated with signal: %lu", pid, (unsigned long)WTERMSIG(event_msg));
            } else {
                LOG_D("PID: %d exited with unknown status: %lu", pid, event_msg);
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
        return arch_traceEvent(run, status, pid);
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
        /*
         * Target exited with sanitizer defined exitcode (used when SIGABRT is not monitored)
         */
        if (WEXITSTATUS(status) == (unsigned long)HF_SAN_EXIT_CODE) {
            arch_traceExitAnalyze(run, pid);
        }
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
    DIR* dir = opendir(path);
    if (!dir) {
        PLOG_E("Couldn't open dir '%s'", path);
        return false;
    }
    defer {
        closedir(dir);
    };

    for (;;) {
        errno = 0;
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
    /* Default is true for all platforms except Android */
    arch_sigs[SIGABRT].important = hfuzz->cfg.monitorSIGABRT;

    /* Default is false */
    arch_sigs[SIGVTALRM].important = hfuzz->timing.tmoutVTALRM;
}
