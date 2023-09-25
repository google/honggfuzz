/*
 *
 * honggfuzz - architecture dependent code (NETBSD/PTRACE)
 * -----------------------------------------
 *
 * Author: Kamil Rytarowski <n54@gmx.com>
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

#include "netbsd/trace.h"

// clang-format off
#include <sys/param.h>
#include <sys/types.h>
// clang-format on

#include <capstone/capstone.h>
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
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "netbsd/unwind.h"
#include "report.h"
#include "sanitizers.h"
#include "subproc.h"

/*
 * Size in characters required to store a string representation of a
 * register value (0xdeadbeef style))
 */
#define REGSIZEINCHAR (2 * sizeof(register_t) + 3)

#define _HF_INSTR_SZ 64

#if defined(__i386__) || defined(__x86_64__)
#define MAX_INSTR_SZ 16
#elif defined(__arm__) || defined(__powerpc__) || defined(__powerpc64__)
#define MAX_INSTR_SZ 4
#elif defined(__aarch64__)
#define MAX_INSTR_SZ 8
#elif defined(__mips__) || defined(__mips64__)
#define MAX_INSTR_SZ 8
#endif

/*
 * Keep in sync the important signals with the PT_SET_SIGPASS call.
 */
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
#define SI_FROMUSER(siptr) ((siptr)->si_code == SI_USER)
#endif /* SI_FROMUSER */

/*
 * Check whether VA0 page is mappable into the process address space.
 */
static bool get_user_va0_disable(void) {
    static int user_va0_disable     = -1;
    size_t     user_va0_disable_len = sizeof(user_va0_disable);

    if (user_va0_disable == -1) {
        if (sysctlbyname(
                "vm.user_va0_disable", &user_va0_disable, &user_va0_disable_len, NULL, 0) == -1) {
            return true;
        }
    }

    if (user_va0_disable > 0)
        return true;
    else
        return false;
}

static size_t arch_getProcMem(pid_t pid, uint8_t* buf, size_t len, register_t pc) {
    struct ptrace_io_desc io;
    size_t                bytes_read;

    /*
     * Check whether the 0x0 virtual address is always invalid, if so
     * an attempt of reading from its address will return EINVAL.
     */
    if (pc == 0 && get_user_va0_disable() == true) return 0;

    bytes_read  = 0;
    io.piod_op  = PIOD_READ_D;
    io.piod_len = len;

    do {
        io.piod_offs = (void*)(pc + bytes_read);
        io.piod_addr = buf + bytes_read;

        if (ptrace(PT_IO, pid, &io, 0) == -1) {
            PLOG_W("Couldn't read process memory on pid %d, "
                   "piod_op: %d offs: %p addr: %p piod_len: %zu",
                pid, io.piod_op, io.piod_offs, io.piod_addr, io.piod_len);
            break;
        }

        bytes_read  = io.piod_len;
        io.piod_len = len - bytes_read;
    } while (bytes_read < len);

    return bytes_read;
}

static size_t arch_getPC(
    pid_t pid, lwpid_t lwp, register_t* pc, register_t* status_reg HF_ATTR_UNUSED) {
    struct reg r;

    if (ptrace(PT_GETREGS, pid, &r, lwp) != 0) {
        PLOG_D("ptrace(PT_GETREGS) failed");
        return 0;
    }
    *pc = PTRACE_REG_PC(&r);
#if defined(__i386__)
    *status_reg = r.regs[_REG_EFLAGS];
#elif defined(__x86_64__)
    *status_reg = r.regs[_REG_RFLAGS];
#elif defined(__aarch64__)
    *status_reg = r.r_spsr;
#else
#error unsupported CPU architecture
#endif

    return sizeof(r);
}

static void arch_getInstrStr(pid_t pid, lwpid_t lwp, register_t* pc, char* instr) {
    /*
     * We need a value aligned to 8
     * which is sizeof(long) on 64bit CPU archs (on most of them, I hope;)
     */
    uint8_t    buf[MAX_INSTR_SZ];
    size_t     memsz;
    register_t status_reg = 0;

    snprintf(instr, _HF_INSTR_SZ, "%s", "[UNKNOWN]");

    size_t pcRegSz = arch_getPC(pid, lwp, pc, &status_reg);
    if (!pcRegSz) {
        LOG_W("Current architecture not supported for disassembly");
        return;
    }

    if ((memsz = arch_getProcMem(pid, buf, sizeof(buf), *pc)) == 0) {
        snprintf(instr, _HF_INSTR_SZ, "%s", "[NOT_MMAPED]");
        return;
    }

    cs_arch arch;
    cs_mode mode;

#if defined(__i386__)
    arch = CS_ARCH_X86;
    mode = CS_MODE_32;
#elif defined(__x86_64__)
    arch = CS_ARCH_X86;
    mode = CS_MODE_64;
#else
#error Unsupported CPU architecture
#endif

    csh    handle;
    cs_err err = cs_open(arch, mode, &handle);
    if (err != CS_ERR_OK) {
        LOG_W("Capstone initialization failed: '%s'", cs_strerror(err));
        return;
    }

    cs_insn* insn;
    size_t   count = cs_disasm(handle, buf, sizeof(buf), *pc, 0, &insn);

    if (count < 1) {
        LOG_W("Couldn't disassemble the assembler instructions' stream: '%s'",
            cs_strerror(cs_errno(handle)));
        cs_close(&handle);
        return;
    }

    snprintf(instr, _HF_INSTR_SZ, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, count);
    cs_close(&handle);

    for (int x = 0; instr[x] && x < _HF_INSTR_SZ; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace((unsigned char)instr[x]) ||
            !isprint((unsigned char)instr[x])) {
            instr[x] = '_';
        }
    }

    return;
}

static void arch_traceAnalyzeData(run_t* run, pid_t pid) {
    ptrace_siginfo_t info;
    register_t       pc = 0, status_reg = 0;

    if (ptrace(PT_GET_SIGINFO, pid, &info, sizeof(info)) == -1) {
        PLOG_W("Couldn't get siginfo for pid %d", pid);
    }

    size_t pcRegSz = arch_getPC(pid, info.psi_lwpid, &pc, &status_reg);
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

    size_t funcCnt = 0;

    /*
     * Use PC from ptrace GETREGS if not zero.
     * If PC reg zero return and callers should handle zero hash case.
     */
    if (pc) {
        /* Manually update major frame PC & frames counter */
        funcs[0].pc = (void*)(uintptr_t)pc;
        funcCnt     = 1;
    } else {
        return;
    }

    /*
     * Calculate backtrace callstack hash signature
     */
    run->backtrace = sanitizers_hashCallstack(run, funcs, funcCnt, false);
}

static void arch_traceSaveData(run_t* run, pid_t pid) {
    register_t pc = 0;

    /* Local copy since flag is overridden for some crashes */
    bool saveUnique = run->global->io.saveUnique;

    char                  instr[_HF_INSTR_SZ] = "\x00";
    struct ptrace_siginfo info;
    memset(&info, 0, sizeof(info));

    if (ptrace(PT_GET_SIGINFO, pid, &info, sizeof(info)) == -1) {
        PLOG_W("Couldn't get siginfo for pid %d", pid);
    }

    arch_getInstrStr(pid, info.psi_lwpid, &pc, instr);

    void* sig_addr = info.psi_siginfo.si_addr;
    /* User-induced signals don't set si.si_addr */
    if (SI_FROMUSER(&info.psi_siginfo)) {
        sig_addr = NULL;
    }

    LOG_D("Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %" PRIxREGISTER ", instr: '%s'",
        pid, info.psi_siginfo.si_signo, info.psi_siginfo.si_errno, info.psi_siginfo.si_code,
        sig_addr, pc, instr);

    if (!SI_FROMUSER(&info.psi_siginfo) && pc && sig_addr < run->global->arch_netbsd.ignoreAddr) {
        LOG_I("Input is interesting (%s), but the si.si_addr is %p (below %p), skipping",
            util_sigName(info.psi_siginfo.si_signo), sig_addr, run->global->arch_netbsd.ignoreAddr);
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

    size_t funcCnt = 0;

    /*
     * Use PC from ptrace GETREGS if not zero.
     * If PC reg zero, temporarily disable uniqueness flag since callstack
     * hash will be also zero, thus not safe for unique decisions.
     */
    if (pc) {
        /* Manually update major frame PC & frames counter */
        funcs[0].pc = (void*)(uintptr_t)pc;
        funcCnt     = 1;
    } else {
        saveUnique = false;
    }

    /*
     * Temp local copy of previous backtrace value in case worker hit crashes into multiple
     * tids for same target main thread. Will be 0 for first crash against target.
     */
    uint64_t oldBacktrace = run->backtrace;

    /*
     * Calculate backtrace callstack hash signature
     */
    run->backtrace = sanitizers_hashCallstack(run, funcs, funcCnt, saveUnique);

    /*
     * If unique flag is set and single frame crash, disable uniqueness for this crash
     * to always save (timestamp will be added to the filename)
     */
    if (saveUnique && (funcCnt == 1)) {
        saveUnique = false;
    }

    /*
     * If worker crashFileName member is set, it means that a tid has already crashed
     * from target main thread.
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
     * Check if backtrace contains allowlisted symbol. Whitelist overrides
     * both stackhash and symbol blocklist. Crash is always kept regardless
     * of the status of uniqueness flag.
     */
    if (run->global->arch_netbsd.symsWl) {
        char* wlSymbol = arch_btContainsSymbol(
            run->global->arch_netbsd.symsWlCnt, run->global->arch_netbsd.symsWl, funcCnt, funcs);
        if (wlSymbol != NULL) {
            saveUnique = false;
            LOG_D("Whitelisted symbol '%s' found, skipping blocklist checks", wlSymbol);
        }
    } else {
        /*
         * Check if stackhash is blocklisted
         */
        if (run->global->feedback.blocklist &&
            (fastArray64Search(run->global->feedback.blocklist, run->global->feedback.blocklistCnt,
                 run->backtrace) != -1)) {
            LOG_I("Blacklisted stack hash '%" PRIx64 "', skipping", run->backtrace);
            ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
            return;
        }

        /*
         * Check if backtrace contains blocklisted symbol
         */
        char* blSymbol = arch_btContainsSymbol(
            run->global->arch_netbsd.symsBlCnt, run->global->arch_netbsd.symsBl, funcCnt, funcs);
        if (blSymbol != NULL) {
            LOG_I("Blacklisted symbol '%s' found, skipping", blSymbol);
            ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
            return;
        }
    }

    /* If non-blocklisted crash detected, zero set two MSB */
    ATOMIC_POST_ADD(run->global->cfg.dynFileIterExpire, _HF_DYNFILE_SUB_MASK);

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->dynfile->path);
    } else if (saveUnique) {
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIxREGISTER ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s",
            run->global->io.crashDir, util_sigName(info.psi_siginfo.si_signo), pc, run->backtrace,
            info.psi_siginfo.si_code, sig_addr, instr, run->global->io.fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIxREGISTER ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s",
            run->global->io.crashDir, util_sigName(info.psi_siginfo.si_signo), pc, run->backtrace,
            info.psi_siginfo.si_code, sig_addr, instr, localtmstr, pid, run->global->io.fileExtn);
    }

    if (files_exists(run->crashFileName)) {
        LOG_I("Crash (dup): '%s' already exists, skipping", run->crashFileName);
        // Clear filename so that verifier can understand we hit a duplicate
        memset(run->crashFileName, 0, sizeof(run->crashFileName));
        return;
    }

    if (!files_writeBufToFile(run->crashFileName, run->dynfile->data, run->dynfile->size,
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC)) {
        LOG_E("Couldn't write to '%s'", run->crashFileName);
        return;
    }

    LOG_I("Crash: saved as '%s'", run->crashFileName);

    ATOMIC_POST_INC(run->global->cnts.uniqueCrashesCnt);
    /* If unique crash found, reset dynFile counter */
    ATOMIC_CLEAR(run->global->cfg.dynFileIterExpire);

    report_appendReport(pid, run, funcs, funcCnt, pc, (uint64_t)info.psi_siginfo.si_addr,
        info.psi_siginfo.si_signo, instr, "");
}

static void arch_traceEvent(run_t* run HF_ATTR_UNUSED, pid_t pid) {
    ptrace_state_t   state;
    ptrace_siginfo_t info;
    int              sig = 0;

    if (ptrace(PT_GET_SIGINFO, pid, &info, sizeof(info)) == -1) {
        PLOG_E("ptrace(PT_GET_SIGINFO, pid=%d)", (int)pid);
    } else {
        switch (info.psi_siginfo.si_code) {
        case TRAP_BRKPT:
            /* Software breakpoint trap, pass it over to tracee */
            sig = SIGTRAP;
            LOG_D("PID: %d breakpoint software trap (TRAP_BRKPT)", pid);
            break;
        case TRAP_TRACE:
            /* Single step unused */
            LOG_E("PID: %d unexpected single step trace trap (TRAP_TRACE)", pid);
            break;
        case TRAP_EXEC:
            /* exec(3) trap, ignore */
            LOG_D("PID: %d breakpoint software trap (TRAP_EXEC)", pid);
            break;
        case TRAP_CHLD:
        case TRAP_LWP:
            /* Child/LWP trap, unused */
            if (ptrace(PT_GET_PROCESS_STATE, pid, &state, sizeof(state)) != -1) {
                switch (state.pe_report_event) {
                case PTRACE_FORK:
                    LOG_D("PID: %d child trap (TRAP_CHLD) : fork", (int)pid);
                    break;
                case PTRACE_VFORK:
                    LOG_D("PID: %d child trap (TRAP_CHLD) : vfork", (int)pid);
                    break;
                case PTRACE_VFORK_DONE:
                    LOG_D("PID: %d child trap (TRAP_CHLD) : vfork (PTRACE_VFORK_DONE)", (int)pid);
                    break;
#ifdef PTRACE_POSIX_SPAWN
                case PTRACE_POSIX_SPAWN:
                    LOG_D("PID: %d child trap (TRAP_CHLD) : spawn (POSIX_SPAWN)", (int)pid);
                    break;
#endif
                case PTRACE_LWP_CREATE:
                    LOG_E("PID: %d unexpected lwp trap (TRAP_LWP) : create "
                          "(PTRACE_LWP_CREATE)",
                        (int)pid);
                    break;
                case PTRACE_LWP_EXIT:
                    LOG_E("PID: %d unexpected lwp trap (TRAP_LWP) : exit (PTRACE_LWP_EXIT)",
                        (int)pid);
                    break;
                default:
                    LOG_D("PID: %d unknown child/lwp trap (TRAP_LWP/TRAP_CHLD) : unknown "
                          "pe_report_event=%d",
                        (int)pid, state.pe_report_event);
                    break;
                }
            }
            break;
        case TRAP_DBREG:
            /* Debug Register trap unused */
            LOG_E("PID: %d unexpected debug register trap (TRAP_DBREG)", pid);
            break;
        case TRAP_SCE:
            /* Syscall Enter trap unused */
            LOG_E("PID: %d unexpected syscall enter trap (TRAP_SCE)", pid);
            break;
        case TRAP_SCX:
            /* Syscall Exit trap unused */
            LOG_E("PID: %d unexpected syscall exit trap (TRAP_SCX)", pid);
            break;
        default:
            /* Other trap, pass it over to tracee */
            sig = SIGTRAP;
            LOG_D("PID: %d other trap si_code=%d", pid, info.psi_siginfo.si_code);
            break;
        }
    }

    ptrace(PT_CONTINUE, pid, (void*)1, sig);
}

void arch_traceAnalyze(run_t* run, int status, pid_t pid) {
    /*
     * It's a ptrace event, deal with it elsewhere
     */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        return arch_traceEvent(run, pid);
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
        /* Do not deliver SIGSTOP */
        int sig = (WSTOPSIG(status) != SIGSTOP) ? WSTOPSIG(status) : 0;
        ptrace(PT_CONTINUE, pid, (void*)1, sig);
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

bool arch_traceWaitForPidStop(pid_t pid) {
    LOG_D("Waiting for pid=%d to stop", (int)pid);

    for (;;) {
        int   status;
        pid_t ret = wait4(pid, &status, __WALL | WUNTRACED | WTRAPPED, NULL);
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

        LOG_D("pid=%d stopped", (int)pid);
        return true;
    }
}

bool arch_traceAttach(run_t* run) {
    if (!arch_traceWaitForPidStop(run->pid)) {
        return false;
    }
    if (ptrace(PT_ATTACH, run->pid, NULL, 0) == -1) {
        PLOG_W("Couldn't ptrace(PT_ATTACH) to pid: %d", (int)run->pid);
        return false;
    }
    if (!arch_traceWaitForPidStop(run->pid)) {
        return false;
    }

#ifdef PT_SET_SIGPASS
    /*
     * Don't intercept uninteresting signals.
     *
     * Note that crash signals (SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGTRAP) for
     * real crashes (thus not including: kill(2), raise(2) etc) are never passed
     * over and are always directed to the debugger.
     *
     * Keep in sync with struct arch_sigs[].
     */
    sigset_t set;
    sigfillset(&set);
    sigdelset(&set, SIGABRT);
    sigdelset(&set, SIGSYS);
    if (ptrace(PT_SET_SIGPASS, run->pid, &set, sizeof(set)) == -1) {
        PLOG_W("Couldn't ptrace(PT_SET_SIGPASS) to pid: %d", (int)run->pid);
        return false;
    }
#endif

    LOG_D("Attached to PID: %d", run->pid);

    if (ptrace(PT_CONTINUE, run->pid, (void*)1, 0) == -1) {
        PLOG_W("Couldn't ptrace(PT_CONTINUE) to pid: (int)%d", run->pid);
        return false;
    }

    return true;
}

void arch_traceDetach(pid_t pid) {
    if (ptrace(PT_DETACH, pid, NULL, 0) == -1) {
        PLOG_E("PID: %d ptrace(PT_DETACH) failed", pid);
    }
}

void arch_traceSignalsInit(honggfuzz_t* hfuzz) {
    /* Default is false */
    arch_sigs[SIGVTALRM].important = hfuzz->timing.tmoutVTALRM;
}
