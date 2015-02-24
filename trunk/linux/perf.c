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
#include <sys/poll.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linux/perf.h"
#include "log.h"

/*
 * 1 + 16 pages
 */
#define _HF_PERF_MMAP_DATA_SZ (128 * 4096)
#define _HF_PERF_MMAP_TOT_SZ (4096 + _HF_PERF_MMAP_DATA_SZ)

static __thread uint8_t *perfMmap = NULL;
static __thread bool perfSampleIp = false;
static __thread int cnt = 0;

#define _HF_PERF_BRANCHES_SZ (8192)
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
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmap;

/* Memory Barriers */
#if defined(__x86_64__)
#define rmb()	__asm__ __volatile__ ("lfence" ::: "memory")
#elif defined(__i386__)
#define rmb()	__asm__ __volatile__ ("lock; addl $0,0(%%esp)" ::: "memory")
#else
#define rmb()	__asm__ __volatile__ ("" ::: "memory")
#endif

    uint64_t dataHeadOff = pem->data_head % _HF_PERF_MMAP_DATA_SZ;
    uint64_t dataTailOff = pem->data_tail % _HF_PERF_MMAP_DATA_SZ;
    /* Required as per 'man perf_event_open' */
    rmb();

    uint8_t *dataTailPtr = perfMmap + getpagesize() + dataTailOff;

    uint8_t localData[_HF_PERF_MMAP_DATA_SZ];
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

    if (localDataLen == 0) {
        return;
    }

    /* Ok, let it go */
    pem->data_tail = pem->data_head;

    for (struct perf_event_header * peh = (struct perf_event_header *)localData;
         (uintptr_t) peh < (uintptr_t) (localData + localDataLen);
         peh = (struct perf_event_header *)((uint8_t *) peh + peh->size)) {

        /* Cannot recover from this condition */
        if (peh->size == 0) {
            LOGMSG(l_FATAL, "(struct perf_event_header)->size == 0 (%" PRIu16 ")", peh->size);
            break;
        }
        if (peh->type != PERF_RECORD_SAMPLE) {
            LOGMSG(l_DEBUG, "(struct perf_event_header)->type != PERF_RECORD_SAMPLE (%" PRIu16 ")",
                   peh->type);
            continue;
        }
        if (peh->misc != PERF_RECORD_MISC_USER && peh->misc != PERF_RECORD_MISC_KERNEL) {
            LOGMSG(l_FATAL,
                   "(struct perf_event_header)->type != PERF_RECORD_MISC_USER (%" PRIu16 ")",
                   peh->misc);
            continue;
        }

        if (perfSampleIp == true) {
            cnt++;
            uint64_t ip = *(uint64_t *) ((uint8_t *) peh + sizeof(peh));
            arch_perfAddFromToBranch(ip, 0ULL);
            continue;
        }

        uint64_t bnr = *(uint64_t *) ((uint8_t *) peh + sizeof(peh));
        struct perf_branch_entry *lbr =
            (struct perf_branch_entry *)((uint8_t *) peh + sizeof(peh) + sizeof(uint64_t));

        for (uint64_t i = 0; i < bnr; i++) {
            arch_perfAddFromToBranch(lbr[i].from, lbr[i].to);
        }
    }
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void arch_perfSigHandler(int signum, siginfo_t * si, void *unused)
{
    return;
    if (signum == SIGCHLD) {
        return;
    }
    if (si == NULL) {
        return;
    }
    if (unused == NULL) {
        return;
    }
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
#define _HF_SAMPLE_PERIOD 1     /* investigate */
    case _HF_DYNFILE_EDGE_ANY_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY for PID: %d", pid);
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        break;
    case _HF_DYNFILE_EDGE_CALL_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY_CALL for PID: %d",
               pid);
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY_CALL;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        break;
    case _HF_DYNFILE_EDGE_RETURN_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY_RETURN for PID: %d",
               pid);
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_ANY_RETURN;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        break;
    case _HF_DYNFILE_EDGE_IND_COUNT:
        LOGMSG(l_DEBUG,
               "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_ANY_IND_CALL for PID: %d", pid);
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_IND_CALL;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        break;
#ifndef PERF_SAMPLE_BRANCH_COND /* Since around kernel version 3.15 */
#define PERF_SAMPLE_BRANCH_COND (1U << 10)
#endif                          /* PERF_SAMPLE_BRANCH_COND */
    case _HF_DYNFILE_EDGE_COND_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_BRANCH_COND for PID: %d", pid);
        pe.sample_type = PERF_SAMPLE_BRANCH_STACK;
        pe.branch_sample_type = PERF_SAMPLE_BRANCH_COND;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        break;
    case _HF_DYNFILE_EDGE_IP_COUNT:
        LOGMSG(l_DEBUG, "Using: PERF_SAMPLE_BRANCH_STACK/PERF_SAMPLE_IP for PID: %d", pid);
        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.size = sizeof(struct perf_event_attr);
        pe.disabled = 0;
        pe.sample_type = PERF_SAMPLE_IP;
        pe.sample_period = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;

#if 0
        pe.sample_type = PERF_SAMPLE_IP;
        pe.sample_period = _HF_SAMPLE_PERIOD;
        pe.wakeup_watermark = getpagesize() * 32;
        pe.watermark = 1;
#endif
        perfSampleIp = true;
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
                   "-D* modes require LBR/BTS feature present since Intel Haswell (i.e. not in AMD CPUs)");
        }
        return false;
    }

    if (hfuzz->dynFileMethod < _HF_DYNFILE_EDGE_ANY_COUNT) {
        if (ioctl(*perfFd, PERF_EVENT_IOC_RESET, 0) == -1) {
            LOGMSG_P(l_ERROR, "ioctl(perfFd='%d', PERF_EVENT_IOC_RESET) failed", perfFd);
            close(*perfFd);
            return false;
        }
        return true;
    }

    perfMmap = mmap(NULL, _HF_PERF_MMAP_TOT_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0);
    if (perfMmap == MAP_FAILED) {
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
        .sa_flags = SA_SIGINFO,
        .sa_restorer = NULL
    };
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        LOGMSG_P(l_ERROR, "sigaction() failed");
        return false;
    }
    if (sigaction(SIGTRAP, &sa, NULL) == -1) {
        LOGMSG_P(l_ERROR, "sigaction() failed");
        return false;
    }
    return true;
}

void arch_perfPoll(int perfFd)
{

    for (;;) {
        struct pollfd pollfds = {.fd = perfFd,.events = POLLIN,.revents = 0 };

        LOGMSG(l_ERROR, "ENTRY");
        int ret = poll(&pollfds, 1, -1);
        LOGMSG(l_ERROR, "RET: %d", ret);
        if (ret == 0) {
            break;
        }
        if (ret < 0 && errno == EINTR) {
            break;
        }
        if (ret < 0) {
            LOGMSG(l_ERROR, "poll() failed");
            break;
        }
        arch_perfMmapParse(perfFd);
    }
}

void arch_perfAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int perfFd)
{
    uint64_t count = 0LL;
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }
    if (ioctl(perfFd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        LOGMSG_P(l_ERROR, "ioctl(perfFd='%d', PERF_EVENT_IOC_DISABLE) failed", perfFd);
        goto out;
    }

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
    LOGMSG(l_ERROR, "CNT: %d", cnt);
    LOGMSG(l_INFO,
           "File size (New/Best): %zu/%zu, Perf events seen: Best: %" PRIu64 " / New: %" PRIu64,
           fuzzer->dynamicFileSz, hfuzz->dynamicFileBestSz, hfuzz->branchBestCnt, count);

    if (perfMmap != NULL) {
        munmap(perfMmap, _HF_PERF_MMAP_TOT_SZ);
    }
    close(perfFd);
    return;
}
