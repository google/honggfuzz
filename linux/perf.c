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
#include "util.h"

#define _HF_RT_SIG (SIGIO)

/* Buffer used with BTS (branch recording) */
static __thread uint8_t *perfMmapBuf = NULL;
/* By default it's 1MB which allows to run 1 fuzzing thread */
static __thread size_t perfMmapSz = 0UL;
/* Unique path counter */
static __thread uint64_t perfBranchesCnt = 0;
/* Have we seen PERF_RECRORD_LOST events */
static __thread uint64_t perfRecordsLost = 0;
/* Don't record branches using address above this parameter */
static __thread uint64_t perfCutOffAddr = ~(0ULL);
/* Perf method - to be used in signal handlers */
static __thread dynFileMethod_t perfDynamicMethod = _HF_DYNFILE_NONE;

#define _HF_PERF_BLOOM_SZ (1024 * 1024 * 2)
static __thread uint8_t perfBloom[_HF_PERF_BLOOM_SZ];

static size_t arch_perfCountBranches(void)
{
    return perfBranchesCnt;
}

static inline void arch_perfAddBranch(uint64_t from, uint64_t to)
{
    /*
     * Kernel sometimes reports branches from the kernel (iret), we are not interested in that as it
     * makes the whole concept of unique branch counting less predictable
     */
    if (__builtin_expect(from > 0xFFFFFFFF00000000, false)
        || __builtin_expect(to > 0xFFFFFFFF00000000, false)) {
        LOGMSG(l_DEBUG, "Adding branch %#018" PRIx64 " - %#018" PRIx64, from, to);
        return;
    }
    if (from >= perfCutOffAddr || to >= perfCutOffAddr) {
        return;
    }

    /* It's 24-bit max, so should fit in a 2MB bitmap */
    size_t pos = 0ULL;
    if (perfDynamicMethod == _HF_DYNFILE_UNIQUE_BLOCK_COUNT) {
        pos = from & 0xFFFFFF;
    }
    if (perfDynamicMethod == _HF_DYNFILE_UNIQUE_EDGE_COUNT) {
        pos = ((from & 0xFFF) | ((to << 12) & 0xFFF000));
    }

    size_t byteOff = pos / 8;
    size_t bitOff = pos % 8;

    uint8_t prev = __sync_fetch_and_or(&perfBloom[byteOff], ((uint8_t) 1 << bitOff));
    if ((prev & ((uint8_t) 1 << bitOff)) == 0) {
        perfBranchesCnt++;
    }
}

/* Memory Barriers */
#define rmb()	__asm__ __volatile__("":::"memory")
#define wmb()	__sync_synchronize()
static inline uint64_t arch_perfGetMmap64(bool fatal)
{
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;

    register uint64_t dataHeadOff = pem->data_head % perfMmapSz;
    register uint64_t dataTailOff = pem->data_tail % perfMmapSz;
    rmb();
    /* Memory barrier - needed as per perf_event_open(2) */

    if (__builtin_expect(dataHeadOff == dataTailOff, false)) {
        if (fatal) {
            LOGMSG(l_FATAL, "No data in the mmap buffer");
        }
        return ~(0ULL);
    }

    register uint64_t ret = *(uint64_t *) (perfMmapBuf + getpagesize() + dataTailOff);
    pem->data_tail = dataTailOff + sizeof(uint64_t);
    wmb();

    return ret;
}

static inline void arch_perfMmapParse(void)
{
    for (;;) {
        uint64_t tmp;
        if ((tmp = arch_perfGetMmap64(false /* fatal */ )) == ~(0ULL)) {
            break;
        }

        struct perf_event_header *peh = (struct perf_event_header *)&tmp;
        if (__builtin_expect(peh->type == PERF_RECORD_LOST, false)) {
            /* It's id an we can ignore it */
            arch_perfGetMmap64(true /* fatal */ );
            register uint64_t lost = arch_perfGetMmap64(true /* fatal */ );
            perfRecordsLost += lost;
            continue;
        }
        if (__builtin_expect(peh->type != PERF_RECORD_SAMPLE, false)) {
            LOGMSG(l_FATAL, "(struct perf_event_header)->type != PERF_RECORD_SAMPLE (%" PRIu16 ")",
                   peh->type);
        }
        if (__builtin_expect
            (peh->misc != PERF_RECORD_MISC_USER && peh->misc != PERF_RECORD_MISC_KERNEL, false)) {
            LOGMSG(l_FATAL,
                   "(struct perf_event_header)->type != PERF_RECORD_MISC_USER (%" PRIu16 ")",
                   peh->misc);
        }

        register uint64_t from = arch_perfGetMmap64(true /* fatal */ );
        register uint64_t to = 0ULL;
        if (perfDynamicMethod == _HF_DYNFILE_UNIQUE_EDGE_COUNT) {
            to = arch_perfGetMmap64(true /* fatal */ );
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
    if (__builtin_expect(signum != _HF_RT_SIG, false)) {
        return;
    }
    if (__builtin_expect(si->si_code != POLL_IN, false)) {
        return;
    }

    arch_perfMmapParse();
    return;

    if (unused == NULL) {
        return;
    }
}

static size_t arch_perfGetMmapBufSz(honggfuzz_t * hfuzz)
{
    /*
     * mmap buffer's size must divisible by a power of 2.
     * The maximal, cumulative size for all threads is 2MiB.
     */
    size_t ret = (1024 * 1024 * 2);
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

static bool arch_perfOpen(pid_t pid, dynFileMethod_t method, int *perfFd)
{
    LOGMSG(l_DEBUG, "Enabling PERF for PID=%d (mmapBufSz=%zu), method=%x", pid, perfMmapSz, method);

    perfDynamicMethod = method;
    perfBranchesCnt = 0;
    perfRecordsLost = 0;

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.disabled = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.exclude_callchain_kernel = 1;
    pe.enable_on_exec = 1;
    pe.type = PERF_TYPE_HARDWARE;

    switch (method) {
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
    case _HF_DYNFILE_UNIQUE_BLOCK_COUNT:
        bzero(perfBloom, sizeof(perfBloom));
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_IP for PID: %d", pid);
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_IP;
        pe.sample_period = 1;   /* It's BTS based, so must be equal to 1 */
        pe.watermark = 1;
        pe.wakeup_watermark = perfMmapSz / 32;
        break;
    case _HF_DYNFILE_UNIQUE_EDGE_COUNT:
        bzero(perfBloom, sizeof(perfBloom));
        LOGMSG(l_DEBUG,
               "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_IP|PERF_SAMPLE_ADDR for PID: %d", pid);
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
        pe.sample_period = 1;   /* It's BTS based, so must be equal to 1 */
        pe.watermark = 1;
        pe.wakeup_watermark = perfMmapSz / 32;
        break;
    default:
        LOGMSG(l_ERROR, "Unknown perf mode: '%d' for PID: %d", method, pid);
        return false;
        break;
    }

    *perfFd = perf_event_open(&pe, pid, -1, -1, 0);
    if (*perfFd == -1) {
        if (method == _HF_DYNFILE_UNIQUE_BLOCK_COUNT || method == _HF_DYNFILE_UNIQUE_EDGE_COUNT) {
            LOGMSG(l_ERROR,
                   "-Dp/-De mode (sample IP/jump) requires LBR/BTS, which present in Intel Haswell and newer CPUs (i.e. not in AMD CPUs)");
        }
        LOGMSG_P(l_FATAL, "perf_event_open() failed");
        return false;
    }

    if (method != _HF_DYNFILE_UNIQUE_BLOCK_COUNT && method != _HF_DYNFILE_UNIQUE_EDGE_COUNT) {
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

bool arch_perfEnable(pid_t pid, honggfuzz_t * hfuzz, int *perfFd)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return true;
    }

    perfMmapSz = arch_perfGetMmapBufSz(hfuzz);
    perfCutOffAddr = hfuzz->dynamicCutOffAddr;

    perfFd[0] = -1;
    perfFd[1] = -1;
    perfFd[2] = -1;

    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        if (arch_perfOpen(pid, _HF_DYNFILE_INSTR_COUNT, &perfFd[0]) == false) {
            LOGMSG(l_ERROR, "Cannot set up perf for PID=%d (_HF_DYNFILE_INSTR_COUNT)", pid);
            close(perfFd[0]);
            close(perfFd[1]);
            close(perfFd[2]);
            return false;
        }
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        if (arch_perfOpen(pid, _HF_DYNFILE_BRANCH_COUNT, &perfFd[1]) == false) {
            LOGMSG(l_ERROR, "Cannot set up perf for PID=%d (_HF_DYNFILE_BRANCH_COUNT)", pid);
            close(perfFd[0]);
            close(perfFd[1]);
            close(perfFd[2]);
            return false;
        }
    }

    if ((hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT)
        && (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_EDGE_COUNT)) {
        LOGMSG(l_FATAL,
               "_HF_DYNFILE_UNIQUE_BLOCK_COUNT and _HF_DYNFILE_UNIQUE_EDGE_COUNT cannot be specified together");
    }

    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT) {
        if (arch_perfOpen(pid, _HF_DYNFILE_UNIQUE_BLOCK_COUNT, &perfFd[2]) == false) {
            LOGMSG(l_ERROR, "Cannot set up perf for PID=%d (_HF_DYNFILE_UNIQUE_BLOCK_COUNT)", pid);
            close(perfFd[0]);
            close(perfFd[1]);
            close(perfFd[2]);
            return false;
        }
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_EDGE_COUNT) {
        if (arch_perfOpen(pid, _HF_DYNFILE_UNIQUE_EDGE_COUNT, &perfFd[2]) == false) {
            LOGMSG(l_ERROR, "Cannot set up perf for PID=%d (_HF_DYNFILE_UNIQUE_EDGE_COUNT)", pid);
            close(perfFd[0]);
            close(perfFd[1]);
            close(perfFd[2]);
            return false;
        }
    }

    return true;
}

void arch_perfAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int *perfFd)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    uint64_t instrCount = 0;
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        ioctl(perfFd[0], PERF_EVENT_IOC_DISABLE, 0);
        if (read(perfFd[0], &instrCount, sizeof(instrCount)) != sizeof(instrCount)) {
            LOGMSG_P(l_ERROR, "read(perfFd='%d') failed", perfFd);
        }
        close(perfFd[0]);
    }

    uint64_t branchCount = 0;
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        ioctl(perfFd[1], PERF_EVENT_IOC_DISABLE, 0);
        if (read(perfFd[1], &branchCount, sizeof(branchCount)) != sizeof(branchCount)) {
            LOGMSG_P(l_ERROR, "read(perfFd='%d') failed", perfFd);
        }
        close(perfFd[1]);
    }

    uint64_t edgeCount = 0;
    if ((hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT)
        || (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_EDGE_COUNT)) {
        ioctl(perfFd[2], PERF_EVENT_IOC_DISABLE, 0);
        close(perfFd[2]);
        arch_perfMmapParse();
        edgeCount = arch_perfCountBranches();

        if (perfRecordsLost > 0UL) {
            LOGMSG(l_WARN,
                   "%" PRId64
                   " PERF_RECORD_LOST events received, possibly too many concurrent fuzzing threads in progress",
                   perfRecordsLost);
        }
    }

    if (perfMmapBuf != NULL) {
        munmap(perfMmapBuf, perfMmapSz + getpagesize());
    }

    fuzzer->branchCnt[0] = instrCount;
    fuzzer->branchCnt[1] = branchCount;
    fuzzer->branchCnt[2] = edgeCount;

    return;
}
