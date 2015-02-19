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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linux/perf.h"
#include "log.h"

/*
 * 1 + 16 pages
 */
#define _HF_PERF_MMAP_DATA_SZ (getpagesize() << 7)
#define _HF_PERF_MMAP_TOT_SZ (getpagesize() + _HF_PERF_MMAP_DATA_SZ)

static __thread uint8_t *perfMmap = NULL;

#define _HF_PERF_BRANCHES_SZ (4096)
/*  *INDENT-OFF* */
static __thread struct {
    uint64_t from;
    uint64_t to;
} perfBranches[_HF_PERF_BRANCHES_SZ] = {
  [0 ... (_HF_PERF_BRANCHES_SZ - 1)].from = 0ULL,
  [0 ... (_HF_PERF_BRANCHES_SZ - 1)].to = 0ULL
};
/*  *INDENT-ON* */

static size_t arch_perfCountBranches(void)
{
    size_t i = 0;
    for (i = 0; i < _HF_PERF_BRANCHES_SZ; i++) {
        if (perfBranches[i].from == 0ULL && perfBranches[i].to == 0ULL) {
            return i;
        }
        LOGMSG(l_DEBUG, "Branch entry: FROM: %" PRIx64 " TO: %" PRIx64, perfBranches[i].from,
               perfBranches[i].to);
    }
    return i;
}

static inline void arch_perfAddFromToBranch(uint64_t from, uint64_t to)
{
    for (size_t i = 0; i < _HF_PERF_BRANCHES_SZ; i++) {
        if (perfBranches[i].from == from && perfBranches[i].to == to) {
            break;
        }
        if (perfBranches[i].from == 0ULL && perfBranches[i].to == 0ULL) {
            perfBranches[i].from = from;
            perfBranches[i].to = to;
            break;
        }
    }
}

static inline void arch_perfMmapParse(int fd)
{
    uint8_t localData[_HF_PERF_MMAP_DATA_SZ];
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmap;

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t dataHeadOff = pem->data_head % _HF_PERF_MMAP_DATA_SZ;
/* Memory Barrier - see perf_event_open */
#if defined(__x86_64__)
#define rmb()	__asm__ __volatile__ ("lfence" ::: "memory")
#elif defined(__i386__)
#define rmb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)" ::: "memory")
#else
#define rmb()	__asm__ __volatile__ ("" ::: "memory")
#endif

    rmb();
    uint64_t dataTailOff = pem->data_tail % _HF_PERF_MMAP_DATA_SZ;
    uint8_t *dataTailPtr = perfMmap + getpagesize() + dataTailOff;
    size_t localDataLen = 0;

    if (dataHeadOff > dataTailOff) {
        localDataLen = dataHeadOff - dataTailOff;
        memcpy(localData, dataTailPtr, localDataLen);
    }

    if (dataHeadOff < dataTailOff) {
        localDataLen = _HF_PERF_MMAP_DATA_SZ - dataTailOff + dataHeadOff;
        memcpy(&localData[0], dataTailPtr, _HF_PERF_MMAP_DATA_SZ - dataTailOff);
        memcpy(&localData[_HF_PERF_MMAP_DATA_SZ - dataTailOff], perfMmap + getpagesize(),
               dataHeadOff);
    }

    /* Ok, let it go */
    pem->data_tail = pem->data_head;
    ioctl(fd, PERF_EVENT_IOC_REFRESH, 1);

    struct perf_event_header *peh = (struct perf_event_header *)localData;

    while ((uintptr_t) peh < (uintptr_t) (localData + localDataLen)) {
        if (peh->size == 0) {
            break;
        }

        if (peh->type != PERF_RECORD_SAMPLE) {
            peh = (struct perf_event_header *)((uint8_t *) peh + peh->size);
            continue;
        }
        if (peh->misc != PERF_RECORD_MISC_USER) {
            peh = (struct perf_event_header *)((uint8_t *) peh + peh->size);
            continue;
        }

        uint64_t bnr = *(uint64_t *) ((uint8_t *) peh + sizeof(peh));
        struct perf_branch_entry *lbr =
            (struct perf_branch_entry *)((uint8_t *) peh + sizeof(peh) + sizeof(uint64_t));

        for (uint64_t i = 0; i < bnr; i++) {
            arch_perfAddFromToBranch(lbr[i].from, lbr[i].to);
        }

        peh = (struct perf_event_header *)((uint8_t *) peh + peh->size);
    }
}

static void arch_perfHandler(int signum, siginfo_t * si, void *unused)
{
    int tmpErrno = errno;
    arch_perfMmapParse(si->si_fd);
    errno = tmpErrno;

    return;
/* Unused params */
    if (signum || unused) {
        return;
    }
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

bool arch_perfEnable(pid_t pid, honggfuzz_t * hfuzz, int *perfFd)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return true;
    }

    LOGMSG(l_DEBUG, "Enabling PERF for PID=%d", pid);

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.exclude_callchain_kernel = 1;
    pe.pinned = 1;

    switch (hfuzz->dynFileMethod) {
    case _HF_DYNFILE_INSTR_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_COUNT_HW_INSTRUCTIONS for PID: %d", pid);
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_BRANCH_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_COUNT_HW_BRANCH_INSTRUCTIONS for PID: %d", pid);
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.inherit = 1;
        break;

#define _HF_SAMPLE_PERIOD 25    /* investigate */
#define _HF_WAKEUP_EVENTS 0     /* investigate */
    case _HF_DYNFILE_EDGE_ANY_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY for PID: %d", pid);
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
        pe.wakeup_events = _HF_WAKEUP_EVENTS;
        break;
    case _HF_DYNFILE_EDGE_CALL_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY for PID: %d", pid);
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
        pe.wakeup_events = _HF_WAKEUP_EVENTS;
        break;
    case _HF_DYNFILE_EDGE_RETURN_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY for PID: %d", pid);
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
        pe.wakeup_events = _HF_WAKEUP_EVENTS;
        break;
    case _HF_DYNFILE_EDGE_IND_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY for PID: %d", pid);
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_IND_CALL;
        pe.wakeup_events = _HF_WAKEUP_EVENTS;
        break;
    default:
        LOGMSG(l_ERROR, "Unknown perf mode: '%c' for PID: %d", hfuzz->dynFileMethod, pid);
        return false;
        break;
    }

    *perfFd = perf_event_open(&pe, pid, -1, -1, 0);
    if (*perfFd == -1) {
        LOGMSG_P(l_WARN, "perf_event_open() failed");
        if (hfuzz->dynFileMethod >= _HF_DYNFILE_EDGE_ANY_COUNT) {
            LOGMSG(l_WARN,
                   "-De mode requires LBR feature present in Intel Haswell and newer CPUs (i.e. not in AMD)");
        }
        return false;
    }

    if (hfuzz->dynFileMethod >= _HF_DYNFILE_EDGE_ANY_COUNT) {
        sigset_t smask;
        sigemptyset(&smask);
        struct sigaction sa = {
            .sa_handler = NULL,
            .sa_sigaction = arch_perfHandler,
            .sa_mask = smask,
            .sa_flags = SA_SIGINFO,
            .sa_restorer = NULL
        };

        if (sigaction(SIGIO, &sa, NULL) == -1) {
            LOGMSG_P(l_ERROR, "sigaction() failed");
            return false;
        }

        perfMmap = mmap(NULL, _HF_PERF_MMAP_TOT_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0);
        if (perfMmap == MAP_FAILED) {
            LOGMSG_P(l_ERROR, "mmap() failed");
            close(*perfFd);
            return false;
        }
        if (fcntl(*perfFd, F_SETFL, O_RDWR | O_NONBLOCK | O_ASYNC) == -1) {
            LOGMSG_P(l_ERROR, "fnctl(F_SETFL)");
            close(*perfFd);
            return false;
        }

        struct f_owner_ex foe = {
            .type = F_OWNER_TID,
            .pid = syscall(__NR_gettid)
        };
        if (fcntl(*perfFd, F_SETSIG, SIGIO) == -1) {
            LOGMSG_P(l_ERROR, "fnctl(F_SETSIG)");
            close(*perfFd);
            return false;
        }

        if (fcntl(*perfFd, F_SETOWN_EX, &foe) == -1) {
            LOGMSG_P(l_ERROR, "fnctl(F_SETOWN_EX)");
            close(*perfFd);
            return false;
        }
    }

    if (ioctl(*perfFd, PERF_EVENT_IOC_RESET, 0) == -1) {
        LOGMSG_P(l_ERROR, "ioctl(perfFd='%d', PERF_EVENT_IOC_RESET) failed", perfFd);
        close(*perfFd);
        return false;
    }

    if (ioctl(*perfFd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        LOGMSG_P(l_ERROR, "ioctl(perfFd='%d', PERF_EVENT_IOC_ENABLE) failed", perfFd);
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
    if (ioctl(perfFd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        LOGMSG_P(l_ERROR, "ioctl(perfFd='%d', PERF_EVENT_IOC_DISABLE) failed", perfFd);
        goto out;
    }

    uint64_t count = 0LL;
    if (hfuzz->dynFileMethod >= _HF_DYNFILE_EDGE_ANY_COUNT) {
        arch_perfMmapParse(perfFd);
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
           "%" PRIu64 " perf events seen (highest: %lld), fileSz/BestSz: %zu/%zu",
           count, hfuzz->branchBestCnt, fuzzer->dynamicFileSz, hfuzz->dynamicFileBestSz);

    if (perfMmap != NULL) {
        munmap(perfMmap, _HF_PERF_MMAP_TOT_SZ);
    }
    close(perfFd);
    return;
}
