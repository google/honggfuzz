/*

   honggfuzz - architecture dependent code (LINUX/PTRACE)
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>

   Copyright 2010-2015 by Google Inc. All Rights Reserved.

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

#include "common.h"
#include "arch.h"

#include <capstone/capstone.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <endian.h>
#include <errno.h>
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

static size_t arch_getProcMem(pid_t pid, uint8_t * buf, size_t len, uint64_t pc)
{
    /* Let's try process_vm_readv first */
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

static bool arch_getArch(pid_t pid, cs_arch * arch, size_t * code_size, uint64_t * pc)
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

    /* 32-bit */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)buf;
        *arch = CS_ARCH_X86;
        *code_size = CS_MODE_32;
        *pc = r32->eip;
        return true;
    }
    /* 64-bit */
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)buf;
        *arch = CS_ARCH_X86;
        *code_size = CS_MODE_64;
        *pc = r64->ip;
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /*  defined(__i386__) || defined(__x86_64__)  */
#if defined(__arm__)
    struct user_regs_struct_32 {
        uint32_t uregs[18];
    };
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)buf;
        *arch = CS_ARCH_ARM;
        *code_size = CS_MODE_ARM;
#ifndef ARM_pc
#define ARM_pc 15
#endif                          /* ARM_pc */
        *pc = r32->uregs[ARM_pc];
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /*  defined(__arm__) */
#if defined(__aarch64__)
    struct user_regs_struct_64 {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    };
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)buf;
        *arch = CS_ARCH_ARM64;
        *code_size = CS_MODE_ARM;
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
        /* elf.h's ELF_NGREG says it's 48 registers, so kernel fills it in with some zeros */
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
        /* elf.h's ELF_NGREG says it's 48 registers, so kernel fills it in with some zeros */
        uint64_t zero0;
        uint64_t zero1;
        uint64_t zero2;
        uint64_t zero3;
    };
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_32)) {
        struct user_regs_struct_32 *r32 = (struct user_regs_struct_32 *)buf;
        *arch = CS_ARCH_PPC;
        *code_size = CS_MODE_32;
        *pc = r32->nip;
        return true;
    }
    if (pt_iov.iov_len == sizeof(struct user_regs_struct_64)) {
        struct user_regs_struct_64 *r64 = (struct user_regs_struct_64 *)buf;
        *arch = CS_ARCH_PPC;
        *code_size = CS_MODE_64;
        *pc = r64->nip;
        return true;
    }
    LOGMSG(l_WARN, "Unknown PTRACE_GETREGSET structure size: '%d'", pt_iov.iov_len);
    return false;
#endif                          /* defined(__powerpc64__) || defined(__powerpc__) */
    LOGMSG(l_DEBUG, "Unknown/unsupported CPU architecture");
    return false;
}

#ifndef MAX_OP_STRING
#define MAX_OP_STRING 48
#endif                          /* MAX_OP_STRING */
static void arch_getInstrStr(pid_t pid, uint64_t * pc, char *instr)
{
    /*
     * We need a value aligned to 8
     * which is sizeof(long) on 64bit CPU archs (on most of them, I hope;)
     */
    uint8_t buf[16];
    size_t memsz;

    snprintf(instr, MAX_OP_STRING, "%s", "[UNKNOWN]");

    cs_arch arch;
    size_t code_size;
    if (!arch_getArch(pid, &arch, &code_size, pc)) {
        LOGMSG(l_WARN, "Current architecture not supported for disassembly");
        return;
    }
#if __BYTE_ORDER == __BIG_ENDIAN
    code_size |= CS_MODE_BIG_ENDIAN;
#else                           /* __BYTE_ORDER == __BIG_ENDIAN */
    code_size |= CS_MODE_LITTLE_ENDIAN;
#endif                          /* __BYTE_ORDER == __BIG_ENDIAN */

    if ((memsz = arch_getProcMem(pid, buf, sizeof(buf), *pc)) == 0) {
        snprintf(instr, MAX_OP_STRING, "%s", "[NOT_MMAPED]");
        return;
    }

    csh handle;
    cs_err err = cs_open(arch, code_size, &handle);
    if (err != CS_ERR_OK) {
        LOGMSG(l_WARN, "Capstone initilization failed: '%s'", cs_strerror(err))
            return;
    }

    cs_insn *insn;
    size_t count = cs_disasm_ex(handle, buf, memsz, *pc, 1, &insn);

    if (count < 1) {
        LOGMSG(l_WARN, "Couldn't disassemble the assembler instructions' stream: '%s'",
               cs_strerror(cs_errno(handle)));
        cs_close(&handle);
        return;
    }

    snprintf(instr, MAX_OP_STRING, "%s %s", insn[0].mnemonic, insn[0].op_str);
    cs_free(insn, count);
    cs_close(&handle);

    for (int x = 0; instr[x] && x < MAX_OP_STRING; x++) {
        if (instr[x] == '/' || instr[x] == '\\' || isspace(instr[x]) || !isprint(instr[x])) {
            instr[x] = '_';
        }
    }
}

static void arch_savePtraceData(honggfuzz_t * hfuzz, pid_t pid, fuzzer_t * fuzzer)
{
    uint64_t pc = NULL;

    char instr[MAX_OP_STRING] = "\x00";
    siginfo_t si;

    if (ptrace(PT_GETSIGINFO, pid, 0, &si) == -1) {
        LOGMSG_P(l_WARN, "Couldn't get siginfo for pid %d", pid);
        return;
    }

    arch_getInstrStr(pid, &pc, instr);

    LOGMSG(l_DEBUG,
           "Pid: %d, signo: %d, errno: %d, code: %d, addr: %p, pc: %" PRIx64 ", instr: '%s'",
           pid, si.si_signo, si.si_errno, si.si_code, si.si_addr, pc, instr);

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
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr, instr,
                 fuzzer->origFileName, hfuzz->fileExtn);
    } else {
        char localtmstr[PATH_MAX];
        util_getLocalTime("%F.%H.%M.%S", localtmstr, sizeof(localtmstr));
        snprintf(newname, sizeof(newname), "%s.PC.%" PRIx64 ".CODE.%d.ADDR.%p.INSTR.%s.%s.%d.%s.%s",
                 arch_sigs[si.si_signo].descr, pc, si.si_code, si.si_addr, instr, localtmstr, pid,
                 fuzzer->origFileName, hfuzz->fileExtn);
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
}

/*
 * Returns true if a process exited (so, presumably, we can delete an input
 * file)
 */
static bool arch_analyzePtrace(honggfuzz_t * hfuzz, int status, fuzzer_t * fuzzer)
{
    /*
     * If it's an uninteresting signal (even SIGTRAP), let it run and relay the
     * signal (if not SIGTRAP)
     */
    if (WIFSTOPPED(status) && !arch_sigs[WSTOPSIG(status)].important) {
        int sig = WSTOPSIG(status) == SIGTRAP ? 0 : WSTOPSIG(status);
        ptrace(PT_CONTINUE, fuzzer->pid, 0, sig);
        return false;
    }

    /*
     * If it's an interesting signal, save the testcase, and detach
     * the tracer (relay the signal as well)
     */
    if (WIFSTOPPED(status) && arch_sigs[WSTOPSIG(status)].important) {
        arch_savePtraceData(hfuzz, fuzzer->pid, fuzzer);
        ptrace(PT_CONTINUE, fuzzer->pid, 0, WSTOPSIG(status));
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
    /*
     * Kill a process which corrupts its own heap (with ABRT)
     */
    if (setenv("MALLOC_CHECK_", "3", 1) == -1) {
        LOGMSG_P(l_ERROR, "setenv(MALLOC_CHECK_=3) failed");
        return false;
    }

    /*
     * Tell asan to ignore SEGVs
     */
    if (setenv("ASAN_OPTIONS", "handle_segv=0", 1) == -1) {
        LOGMSG_P(l_ERROR, "setenv(ASAN_OPTIONS) failed");
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
        /*
         * The hfuzz->tmOut is real CPU usage time...
         */
        struct itimerval it_prof = {
            .it_interval = {.tv_sec = hfuzz->tmOut,.tv_usec = 0},
            .it_value = {.tv_sec = 0,.tv_usec = 0}
        };
        if (setitimer(ITIMER_PROF, &it_prof, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't set the ITIMER_PROF timer");
            return false;
        }

        /*
         * ...so, if a process sleeps, this one should
         * trigger a signal...
         */
        struct itimerval it_real = {
            .it_interval = {.tv_sec = hfuzz->tmOut * 2UL,.tv_usec = 0},
            .it_value = {.tv_sec = 0,.tv_usec = 0}
        };
        if (setitimer(ITIMER_REAL, &it_real, NULL) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't set the ITIMER_REAL timer");
            return false;
        }

        /*
         * ..if a process sleeps and catches SIGPROF/SIGALRM
         * rlimits won't help either
         */
        struct rlimit rl = {
            .rlim_cur = hfuzz->tmOut * 2,
            .rlim_max = hfuzz->tmOut * 2,
        };
        if (setrlimit(RLIMIT_CPU, &rl) == -1) {
            LOGMSG_P(l_ERROR, "Couldn't enforce the RLIMIT_CPU resource limit");
            return false;
        }
    }

    /*
     * The address space limit. If big enough - roughly the size of RAM used
     */
    if (hfuzz->asLimit) {
        struct rlimit rl = {
            .rlim_cur = hfuzz->asLimit * 1024UL * 1024UL,
            .rlim_max = hfuzz->asLimit * 1024UL * 1024UL,
        };
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

void arch_reapChild(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int status;

    for (;;) {
        while (wait3(&status, __WNOTHREAD | __WALL, NULL) != fuzzer->pid) ;

        LOGMSG(l_DEBUG, "Process (pid %d) came back with status %d", fuzzer->pid, status);

        if (arch_analyzePtrace(hfuzz, status, fuzzer)) {
            return;
        }
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
