/*
 *
 * honggfuzz - architecture dependent code (LINUX/PERF)
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linux/perf.h"
#include "log.h"

#define _HF_RT_SIG (SIGRTMIN + 10)

/* Buffer used with BTS (branch recording) */
static __thread uint8_t *perfMmapBuf = NULL;
/* By default it's 1MB which allows to run 1 fuzzing thread */
static __thread size_t perfMmapSz = 0UL;
/* Have we seen PERF_RECRORD_LOST events */
static __thread unsigned int perfRecordLost = 0;
/* Don't record branches using address above this parameter */
static __thread uint64_t perfCutOffAddr = ~(1ULL);

#define _HF_PERF_BRANCHES_SZ (1024 * 16)
/*  *INDENT-OFF* */
static __thread struct {
  uint64_t from;
  uint64_t to;
} perfBranch[_HF_PERF_BRANCHES_SZ];
/*  *INDENT-ON* */

static size_t arch_perfCountBranches(void)
{
    size_t i = 0;
    for (i = 0; i < _HF_PERF_BRANCHES_SZ; i++) {
        if (perfBranch[i].from == 0ULL && perfBranch[i].to == 0ULL) {
            return i;
        }
        LOGMSG(l_DEBUG, "Branch entry: FROM: %" PRIx64 ", TO: %" PRIx64, perfBranch[i].from,
               perfBranch[i].to);
    }
    LOGMSG(l_FATAL, "Branch buffer too small (%zu elements)", ARRAYSIZE(perfBranch));
    return i;
}

static inline void arch_perfAddBranch(uint64_t from, uint64_t to)
{
    /*
     * Kernel sometimes reports branches from the kernel (iret), we are not interested in that as it
     * makes the whole concept of unique branch counting less predictable
     */
    if (from > 0xFFFFFFFF00000000 || to > 0xFFFFFFFF00000000) {
        return;
    }
    if (from >= perfCutOffAddr || to >= perfCutOffAddr) {
        return;
    }
    for (size_t i = 0; i < _HF_PERF_BRANCHES_SZ; i++) {
        if (perfBranch[i].from == from && perfBranch[i].to == to) {
            break;
        }
        if (perfBranch[i].from == 0ULL && perfBranch[i].to == 0ULL) {
            perfBranch[i].from = from;
            perfBranch[i].to = to;
            break;
        }
    }
}

static inline void arch_perfSkip(size_t skip)
{
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;
    uint64_t dataTailOff = pem->data_tail;
    dataTailOff += skip;
    if (dataTailOff > perfMmapSz) {
        dataTailOff %= perfMmapSz;
    }
    pem->data_tail = dataTailOff;
}

/* Memory Barriers */
#if defined(__x86_64__)
#define rmb()	__asm__ __volatile__ ("lfence" ::: "memory")
#elif defined(__i386__)
#define rmb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)" ::: "memory")
#else
#define rmb()	__asm__ __volatile__ ("" ::: "memory")
#endif
static inline uint64_t arch_perfGetMulti64(uint64_t * ret)
{
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;
    uint64_t dataHeadOff = pem->data_head % perfMmapSz;
    rmb();
    uint64_t dataTailOff = pem->data_tail % perfMmapSz;

#if 0
    LOGMSG(l_ERROR, "HEAD: %llu TAIL: %llu", dataHeadOff, dataTailOff);
#endif

    int64_t dataLen = 0;
    if (dataHeadOff > dataTailOff) {
        dataLen = dataHeadOff - dataTailOff;
    }
    if (dataHeadOff < dataTailOff) {
        dataLen = perfMmapSz - dataTailOff + dataHeadOff;
    }

    if (dataLen < (int64_t) sizeof(uint64_t)) {
        return false;
    }

    *ret = *(uint64_t *) (perfMmapBuf + getpagesize() + dataTailOff);

    dataTailOff = (dataTailOff + sizeof(uint64_t)) % perfMmapSz;
    pem->data_tail = dataTailOff;

    return true;
}

static inline void arch_perfMmapParse(void)
{
    for (;;) {
        uint64_t tmp;
        if (arch_perfGetMulti64(&tmp) == false) {
            break;
        }

        struct perf_event_header *peh = (struct perf_event_header *)&tmp;
        if (peh->type == PERF_RECORD_LOST) {
            perfRecordLost++;
            arch_perfSkip(peh->size - sizeof(uint64_t));
            continue;
        }
        if (peh->type != PERF_RECORD_SAMPLE) {
            LOGMSG(l_DEBUG, "(struct perf_event_header)->type != PERF_RECORD_SAMPLE (%" PRIu16 ")",
                   peh->type);
            arch_perfSkip(peh->size - sizeof(uint64_t));
            continue;
        }
        if (peh->misc != PERF_RECORD_MISC_USER && peh->misc != PERF_RECORD_MISC_KERNEL) {
            LOGMSG(l_FATAL,
                   "(struct perf_event_header)->type != PERF_RECORD_MISC_USER (%" PRIu16 ")",
                   peh->misc);
            arch_perfSkip(peh->size - sizeof(uint64_t));
            continue;
        }

        uint64_t from, to;
        if (arch_perfGetMulti64(&from) == false) {
            LOGMSG(l_FATAL, "arch_perfGetMulti64(&from) failed");
        }
        if (arch_perfGetMulti64(&to) == false) {
            LOGMSG(l_FATAL, "arch_perfGetMulti64(&to) failed");
        }

        arch_perfAddBranch(from, to);
    }
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
                            unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void arch_perfSigHandler(int signum, siginfo_t * si, void *unused)
{
    if (signum != _HF_RT_SIG) {
        return;
    }
    if (si->si_code != POLL_IN) {
        return;
    }

    arch_perfMmapParse();

    if (unused == NULL) {
        return;
    }
}

static size_t arch_perfGetMmapBufSz(honggfuzz_t * hfuzz)
{
    /*
     * mmap buffer's size must divisible by a power of 2.
     * The maximal, cumulative size for all threads is 1MB
     */
    size_t ret = (1024 * 1024);
    if (hfuzz->threadsMax > 1) {
        for (size_t i = 0; i < 31; i++) {
            if ((hfuzz->threadsMax - 1) >> i) {
                ret >>= 1;
            }
            if (ret < (size_t) getpagesize()) {
                LOGMSG(l_FATAL, "Too many fuzzing threads for hardware support (%d)",
                       hfuzz->threadsMax);
            }
        }
    }
    return ret;
}

bool arch_perfEnable(pid_t pid, honggfuzz_t * hfuzz, int *perfFd)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return true;
    }

    perfMmapSz = arch_perfGetMmapBufSz(hfuzz);
    perfCutOffAddr = hfuzz->dynamicCutOffAddr;

    LOGMSG(l_DEBUG, "Enabling PERF for PID=%d (mmapBufSz=%zu)", pid, perfMmapSz);

    bzero(perfBranch, sizeof(perfBranch));

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.disabled = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.exclude_callchain_kernel = 1;
    pe.type = PERF_TYPE_HARDWARE;

    switch (hfuzz->dynFileMethod) {
    case _HF_DYNFILE_INSTR_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_COUNT_HW_INSTRUCTIONS for PID: %d", pid);
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_BRANCH_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_COUNT_HW_BRANCH_INSTRUCTIONS for PID: %d", pid);
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_UNIQUE_PC_COUNT:
        LOGMSG(l_DEBUG,
               "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_IP|PERF_SAMPLE_ADDR for PID: %d", pid);
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
        pe.sample_period = 1;   /* It's BTS based, so must be equal to 1 */
        pe.wakeup_events = 8000;        /* Experimentally obtained value */
        break;
    default:
        LOGMSG(l_ERROR, "Unknown perf mode: '%d' for PID: %d", hfuzz->dynFileMethod, pid);
        return false;
        break;
    }

    *perfFd = perf_event_open(&pe, pid, -1, -1, 0);
    if (*perfFd == -1) {
        if (hfuzz->dynFileMethod == _HF_DYNFILE_UNIQUE_PC_COUNT) {
            LOGMSG(l_ERROR,
                   "-Dp mode (sample IP/PC) requires LBR/BTS, which present in Intel Haswell and newer CPUs (i.e. not in AMD CPUs)");
        }
        LOGMSG_P(l_FATAL, "perf_event_open() failed");
        return false;
    }

    if (hfuzz->dynFileMethod != _HF_DYNFILE_UNIQUE_PC_COUNT) {
        return true;
    }

    perfMmapBuf =
        mmap(NULL, perfMmapSz + getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0);
    if (perfMmapBuf == MAP_FAILED) {
        LOGMSG_P(l_ERROR, "mmap() failed");
        close(*perfFd);
        return false;
    }

    sigset_t smask;
    sigemptyset(&smask);
    struct sigaction sa = {
        .sa_handler = NULL,
        .sa_sigaction = arch_perfSigHandler,
        .sa_mask = smask,
        .sa_flags = SA_SIGINFO | SA_RESTART,
        .sa_restorer = NULL
    };
    if (sigaction(_HF_RT_SIG, &sa, NULL) == -1) {
        LOGMSG_P(l_ERROR, "sigaction() failed");
        return false;
    }

    if (fcntl(*perfFd, F_SETFL, O_RDWR | O_NONBLOCK | O_ASYNC) == -1) {
        LOGMSG_P(l_ERROR, "fnctl(F_SETFL)");
        close(*perfFd);
        return false;
    }
    if (fcntl(*perfFd, F_SETSIG, _HF_RT_SIG) == -1) {
        LOGMSG_P(l_ERROR, "fnctl(F_SETSIG)");
        close(*perfFd);
        return false;
    }
    struct f_owner_ex foe = {
        .type = F_OWNER_TID,
        .pid = syscall(__NR_gettid)
    };
    if (fcntl(*perfFd, F_SETOWN_EX, &foe) == -1) {
        LOGMSG_P(l_ERROR, "fnctl(F_SETOWN_EX)");
        close(*perfFd);
        return false;
    }

    return true;
}

void arch_perfAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int perfFd)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    ioctl(perfFd, PERF_EVENT_IOC_DISABLE, 0);

    if (perfRecordLost > 0) {
        LOGMSG(l_WARN,
               "%u PERF_RECORD_LOST events received, possibly too many concurrent fuzzing threads in progress",
               perfRecordLost);
    }

    uint64_t count = 0LL;
    if (hfuzz->dynFileMethod == _HF_DYNFILE_UNIQUE_PC_COUNT) {
        arch_perfMmapParse();
        count = fuzzer->branchCnt = arch_perfCountBranches();
        goto out;
    }

    if (read(perfFd, &count, sizeof(count)) != sizeof(count)) {
        LOGMSG_P(l_ERROR, "read(perfFd='%d') failed", perfFd);
        goto out;
    }
    fuzzer->branchCnt = count;
 out:
    LOGMSG(l_INFO,
           "File size (New/Best): %zu/%zu, Perf feedback: Best: %" PRIu64 " / New: %" PRIu64,
           fuzzer->dynamicFileSz, hfuzz->dynamicFileBestSz, hfuzz->branchBestCnt, count);
    if (perfMmapBuf != NULL) {
        munmap(perfMmapBuf, perfMmapSz + getpagesize());
    }
    close(perfFd);
    return;
}
