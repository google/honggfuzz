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

#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

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
#include <time.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"
#include "netbsd/unwind.h"
#include "sancov.h"
#include "sanitizers.h"
#include "socketfuzzer.h"
#include "subproc.h"

#include <capstone/capstone.h>

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
#define SI_FROMUSER(siptr) ((siptr)->si_code == SI_USER)
#endif /* SI_FROMUSER */

static __thread char arch_signame[32];
static const char* arch_sigName(int signo) {
    snprintf(arch_signame, sizeof(arch_signame), "SIG%s", signalname(signo));
    return arch_signame;
}

static size_t arch_getProcMem(pid_t pid, uint8_t* buf, size_t len, register_t pc) {
    struct ptrace_io_desc io;
    size_t bytes_read;

    bytes_read = 0;
    io.piod_op = PIOD_READ_D;
    io.piod_len = len;

    do {
        io.piod_offs = (void*)(pc + bytes_read);
        io.piod_addr = buf + bytes_read;

        if (ptrace(PT_IO, pid, &io, 0) == -1) {
            PLOG_W(
                "Couldn't read process memory on pid %d, "
                "piod_op: %d offs: %p addr: %p piod_len: %zu",
                pid, io.piod_op, io.piod_offs, io.piod_addr, io.piod_len);
            break;
        }

        bytes_read = io.piod_len;
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
    uint8_t buf[MAX_INSTR_SZ];
    size_t memsz;
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

    for (int x = 0; instr[x] && x < _HF_INSTR_SZ; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace((unsigned char)instr[x]) ||
            !isprint((unsigned char)instr[x])) {
            instr[x] = '_';
        }
    }

    return;
}

static void arch_hashCallstack(
    run_t* run, funcs_t* funcs HF_ATTR_UNUSED, size_t funcCnt, bool enableMasking) {
    uint64_t hash = 0;
    for (size_t i = 0; i < funcCnt && i < run->global->netbsd.numMajorFrames; i++) {
        /*
         * Convert PC to char array to be compatible with hash function
         */
        char pcStr[REGSIZEINCHAR] = {0};
        snprintf(pcStr, REGSIZEINCHAR, "%" PRIxREGISTER, (register_t)(long)funcs[i].pc);

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
        util_ssnprintf(run->report, sizeof(run->report), " <%" PRIxREGISTER "> [%s():%zu at %s]\n",
            (register_t)(long)funcs[i].pc, funcs[i].func, funcs[i].line, funcs[i].mapName);
    }

    return;
}

static void arch_traceAnalyzeData(run_t* run, pid_t pid) {
    ptrace_siginfo_t info;
    register_t pc = 0, status_reg = 0;

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
        funcCnt = 1;
    } else {
        return;
    }

    /*
     * Calculate backtrace callstack hash signature
     */
    arch_hashCallstack(run, funcs, funcCnt, false);
}

static void arch_traceSaveData(run_t* run, pid_t pid) {
    register_t pc = 0;

    /* Local copy since flag is overridden for some crashes */
    bool saveUnique = run->global->io.saveUnique;

    char instr[_HF_INSTR_SZ] = "\x00";
    struct ptrace_siginfo info;
    memset(&info, 0, sizeof(info));

    if (ptrace(PT_GET_SIGINFO, pid, &info, sizeof(info)) == -1) {
        PLOG_W("Couldn't get siginfo for pid %d", pid);
    }

    arch_getInstrStr(pid, info.psi_lwpid, &pc, instr);

    LOG_D("Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %" PRIxREGISTER ", instr: '%s'",
        pid, info.psi_siginfo.si_signo, info.psi_siginfo.si_errno, info.psi_siginfo.si_code,
        info.psi_siginfo.si_addr, pc, instr);

    if (!SI_FROMUSER(&info.psi_siginfo) && pc &&
        info.psi_siginfo.si_addr < run->global->netbsd.ignoreAddr) {
        LOG_I("Input is interesting (%s), but the si.si_addr is %p (below %p), skipping",
            arch_sigName(info.psi_siginfo.si_signo), info.psi_siginfo.si_addr,
            run->global->netbsd.ignoreAddr);
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
        funcCnt = 1;
    } else {
        saveUnique = false;
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
     * If fuzzing with sanitizer coverage feedback increase crashes counter used
     * as metric for dynFile evolution
     */
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_SANCOV) {
        run->sanCovCnts.crashesCnt++;
    }

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
    if (run->global->netbsd.symsWl) {
        char* wlSymbol = arch_btContainsSymbol(
            run->global->netbsd.symsWlCnt, run->global->netbsd.symsWl, funcCnt, funcs);
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
            run->global->netbsd.symsBlCnt, run->global->netbsd.symsBl, funcCnt, funcs);
        if (blSymbol != NULL) {
            LOG_I("Blacklisted symbol '%s' found, skipping", blSymbol);
            ATOMIC_POST_INC(run->global->cnts.blCrashesCnt);
            return;
        }
    }

    /* If non-blacklisted crash detected, zero set two MSB */
    ATOMIC_POST_ADD(run->global->cfg.dynFileIterExpire, _HF_DYNFILE_SUB_MASK);

    void* sig_addr = info.psi_siginfo.si_addr;
    pc = 0UL;
    sig_addr = NULL;

    /* User-induced signals don't set si.si_addr */
    if (SI_FROMUSER(&info.psi_siginfo)) {
        sig_addr = NULL;
    }

    /* If dry run mode, copy file with same name into workspace */
    if (run->global->mutate.mutationsPerRun == 0U && run->global->cfg.useVerifier) {
        snprintf(run->crashFileName, sizeof(run->crashFileName), "%s/%s", run->global->io.crashDir,
            run->origFileName);
    } else if (saveUnique) {
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIxREGISTER ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s",
            run->global->io.crashDir, arch_sigName(info.psi_siginfo.si_signo), pc, run->backtrace,
            info.psi_siginfo.si_code, sig_addr, instr, run->global->io.fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
        snprintf(run->crashFileName, sizeof(run->crashFileName),
            "%s/%s.PC.%" PRIxREGISTER ".STACK.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s",
            run->global->io.crashDir, arch_sigName(info.psi_siginfo.si_signo), pc, run->backtrace,
            info.psi_siginfo.si_code, sig_addr, instr, localtmstr, pid, run->global->io.fileExtn);
    }

    /* Target crashed (no duplicate detection yet) */
    if (run->global->socketFuzzer.enabled) {
        LOG_D("SocketFuzzer: trace: Crash Identified");
        run->hasCrashed = true;
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

    arch_traceGenerateReport(pid, run, funcs, funcCnt, &info.psi_siginfo, instr);
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
            while (*pLineLC != '\0' && isspace((unsigned char)*pLineLC)) {
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
    register_t pc = 0;
    void* crashAddr = 0;
    char* op = "UNKNOWN";
    pid_t targetPid = (run->global->netbsd.pid > 0) ? run->global->netbsd.pid : run->pid;

    /* Save only the first hit for each worker */
    if (run->crashFileName[0] != '\0') {
        return;
    }

    /* Increase global crashes counter */
    ATOMIC_POST_INC(run->global->cnts.crashesCnt);
    ATOMIC_POST_AND(run->global->cfg.dynFileIterExpire, _HF_DYNFILE_SUB_MASK);

    /*
     * If fuzzing with sanitizer coverage feedback increase crashes counter used
     * as metric for dynFile evolution
     */
    if (run->global->feedback.dynFileMethod & _HF_DYNFILE_SANCOV) {
        run->sanCovCnts.crashesCnt++;
    }

    /* If sanitizer produces reports with stack traces (e.g. ASan), they're parsed manually */
    int funcCnt = 0;
    funcs_t* funcs = util_Malloc(_HF_MAX_FUNCS * sizeof(funcs_t));
    defer {
        free(funcs);
    };
    memset(funcs, 0, _HF_MAX_FUNCS * sizeof(funcs_t));

    /* Sanitizers save reports against parent PID */
    if (targetPid != pid) {
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
    if (crashAddr < run->global->netbsd.ignoreAddr) {
        LOG_I("Input is interesting, but the crash addr is %p (below %p), skipping", crashAddr,
            run->global->netbsd.ignoreAddr);
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
                "%s/%s.PC.%" PRIxREGISTER ".STACK.%" PRIx64 ".CODE.%s.ADDR.%p.INSTR.%s.%s",
                run->global->io.crashDir, "SAN", pc, run->backtrace, op, crashAddr, "[UNKNOWN]",
                run->global->io.fileExtn);
        } else {
            /* If no stack hash available, all crashes treated as unique */
            char localtmstr[PATH_MAX];
            util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));
            snprintf(run->crashFileName, sizeof(run->crashFileName),
                "%s/%s.PC.%" PRIxREGISTER ".STACK.%" PRIx64 ".CODE.%s.ADDR.%p.INSTR.%s.%s.%s",
                run->global->io.crashDir, "SAN", pc, run->backtrace, op, crashAddr, "[UNKNOWN]",
                localtmstr, run->global->io.fileExtn);
        }
    }

    int fd = open(run->crashFileName, O_WRONLY | O_EXCL | O_CREAT, 0600);
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
            util_ssnprintf(run->report, sizeof(run->report), " <%" PRIxREGISTER "> ",
                (register_t)(long)funcs[i].pc);
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

static void arch_traceEvent(run_t* run HF_ATTR_UNUSED, pid_t pid) {
    ptrace_state_t state;
    ptrace_siginfo_t info;
    int sig = 0;

    ptrace(PT_GET_SIGINFO, pid, &info, sizeof(info));
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
            /* Child/LWP trap, ignore */
            if (ptrace(PT_GET_PROCESS_STATE, pid, &state, sizeof(state)) != -1) {
                switch (state.pe_report_event) {
                    case PTRACE_FORK:
                    case PTRACE_VFORK:
                        LOG_D("PID: %d child trap (TRAP_CHLD) : fork (%s)", pid,
                            state.pe_report_event == PTRACE_FORK ? "PTRACE_FORK" : "PTRACE_VFORK");
                        /* Do not support fuzzing (v)forkees */
                        int status;
                        waitpid(state.pe_other_pid, &status, 0);
                        ptrace(PT_DETACH, state.pe_other_pid, (void*)1, 0);
                        break;
                    case PTRACE_VFORK_DONE:
                        LOG_D("PID: %d child trap (TRAP_CHLD) : vfork (PTRACE_VFORK_DONE)", pid);
                        break;
                    case PTRACE_LWP_CREATE:
                        LOG_E("PID: %d unexpected lwp trap (TRAP_LWP) : create (PTRACE_LWP_CREATE)",
                            pid);
                        break;
                    case PTRACE_LWP_EXIT:
                        LOG_E(
                            "PID: %d unexpected lwp trap (TRAP_LWP) : exit (PTRACE_LWP_EXIT)", pid);
                        break;
                    default:
                        LOG_D(
                            "PID: %d unknown child/lwp trap (TRAP_LWP/TRAP_CHLD) : unknown "
                            "pe_report_event=%d",
                            pid, state.pe_report_event);
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

bool arch_traceAttach(run_t* run, pid_t pid) {
    ptrace_event_t event;

    if (ptrace(PT_ATTACH, pid, NULL, 0) == -1) {
        PLOG_W("Couldn't ptrace(PT_ATTACH) to pid: %d", pid);
        return false;
    }

    if (run->global->netbsd.pid == 0 && !arch_traceWaitForPidStop(pid)) {
        return false;
    }

    event.pe_set_event = PTRACE_FORK | PTRACE_VFORK | PTRACE_VFORK_DONE;

    if (ptrace(PT_SET_EVENT_MASK, pid, &event, sizeof(event)) == -1) {
        PLOG_W("Couldn't ptrace(PT_SET_EVENT_MASK) to pid: %d", pid);
        return false;
    }

    LOG_D("Attached to PID: %d", pid);

    if (ptrace(PT_CONTINUE, pid, (void*)1, 0) == -1) {
        PLOG_W("Couldn't ptrace(PT_CONTINUE) to pid: %d", pid);
        return false;
    }

    /* It only makes sense to attach to threads with -p */
    if (run->global->netbsd.pid == 0) {
        return true;
    }

    return true;
}

void arch_traceDetach(pid_t pid) {
    if (ptrace(PT_DETACH, pid, NULL, 0) == -1) {
        PLOG_E("PID: %d ptrace(PT_DETACH) failed", pid);
    }
}

void arch_traceSignalsInit(honggfuzz_t* hfuzz) {
    /* Default is true for all platforms except Android */
    arch_sigs[SIGABRT].important = hfuzz->cfg.monitorSIGABRT;

    /* Default is false */
    arch_sigs[SIGVTALRM].important = hfuzz->timing.tmoutVTALRM;
}
