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
#include "linux/perf.h"

#include <asm/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sysctl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "files.h"
#include "linux/pt.h"
#include "log.h"
#include "util.h"

/* Buffer used with BTS (branch recording) */
static __thread uint8_t *perfMmapBuf = NULL;
/* Buffer used with BTS (branch recording) */
static __thread uint8_t *perfMmapAux = NULL;
#define _HF_PERF_MAP_SZ (1024 * 128)
#define _HF_PERF_AUX_SZ (1024 * 1024)
/* Don't record branches using address above this parameter */
static uint64_t perfCutOffAddr = ~(0ULL);
/* PERF_TYPE for Intel_PT/BTS -1 if none */
static int32_t perfIntelPtPerfType = -1;
static int32_t perfIntelBtsPerfType = -1;

__thread size_t perfBloomSz = 0U;
__thread uint8_t *perfBloom = NULL;

static inline uint64_t arch_perfAddBranch(uint64_t from, uint64_t to)
{
    /*
     * Kernel sometimes reports branches from the kernel (iret), we are not interested in that as it
     * makes the whole concept of unique branch counting less predictable
     */
    if (__builtin_expect(from > 0xFFFFFFFF00000000, false)
        || __builtin_expect(to > 0xFFFFFFFF00000000, false)) {
        LOG_D("Adding branch %#018" PRIx64 " - %#018" PRIx64, from, to);
        return 0ULL;
    }
    if (from >= perfCutOffAddr || to >= perfCutOffAddr) {
        return 0ULL;
    }

    register size_t pos = 0UL;
    if (to == 0ULL) {
        pos = from % (perfBloomSz * 8);
    } else {
        pos = (from * to) % (perfBloomSz * 8);
    }

    size_t byteOff = pos / 8;
    uint8_t bitSet = (uint8_t) (1 << (pos % 8));

    register uint8_t prev = ATOMIC_POST_OR(perfBloom[byteOff], bitSet);
    if (!(prev & bitSet)) {
        return 1ULL;
    }
    return 0ULL;
}

static inline uint64_t arch_perfMmapParse(honggfuzz_t * hfuzz)
{
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;
#if defined(PERF_ATTR_SIZE_VER5)
    if (pem->aux_head == pem->aux_tail) {
        return 0ULL;
    }
    if (pem->aux_head < pem->aux_tail) {
        LOG_F("The PERF AUX data has been overwritten. The AUX buffer is too small");
    }

    uint64_t cnt = 0ULL;
    struct bts_branch {
        uint64_t from;
        uint64_t to;
        uint64_t misc;
    };
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK) {
        struct bts_branch *br = (struct bts_branch *)perfMmapAux;
        for (; br < ((struct bts_branch *)(perfMmapAux + pem->aux_head)); br++) {
            cnt += arch_perfAddBranch(br->from, 0UL);
        }
        return cnt;
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        struct bts_branch *br = (struct bts_branch *)perfMmapAux;
        for (; br < ((struct bts_branch *)(perfMmapAux + pem->aux_head)); br++) {
            cnt += arch_perfAddBranch(br->from, br->to);
        }
        return cnt;
    }
#endif                          /* defined(PERF_ATTR_SIZE_VER5) */

    return arch_ptAnalyze(pem, perfMmapAux, arch_perfAddBranch);
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd,
                            unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, (uintptr_t) pid, (uintptr_t) cpu,
                   (uintptr_t) group_fd, (uintptr_t) flags);
}

static bool arch_perfOpen(honggfuzz_t * hfuzz, pid_t pid, dynFileMethod_t method, int *perfFd)
{
    LOG_D("Enabling PERF for PID=%d method=%x", pid, method);

    if (*perfFd != -1) {
        LOG_F("The PERF FD is already initialized, possibly conflicting perf types enabled");
    }

    if (((method & _HF_DYNFILE_BTS_BLOCK) || method & _HF_DYNFILE_BTS_EDGE)
        && perfIntelBtsPerfType == -1) {
        LOG_F("Intel BTS events (new type) are not supported on this platform");
    }
    if ((method & _HF_DYNFILE_IPT_BLOCK)
        && perfIntelPtPerfType == -1) {
        LOG_F("Intel PT events are not supported on this platform");
    }

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.exclude_guest = 1;
    pe.exclude_idle = 1;
    pe.exclude_callchain_kernel = 1;
    pe.exclude_callchain_user = 1;
    if (hfuzz->pid > 0) {
        pe.disabled = 0;
        pe.enable_on_exec = 0;
    } else {
        pe.disabled = 1;
        pe.enable_on_exec = 1;
    }
    pe.type = PERF_TYPE_HARDWARE;
    pe.pinned = 1;
    pe.precise_ip = 1;

    switch (method) {
    case _HF_DYNFILE_INSTR_COUNT:
        LOG_D("Using: PERF_COUNT_HW_INSTRUCTIONS for PID: %d", pid);
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_BRANCH_COUNT:
        LOG_D("Using: PERF_COUNT_HW_BRANCH_INSTRUCTIONS for PID: %d", pid);
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.inherit = 1;
        break;
    case _HF_DYNFILE_BTS_BLOCK:
        LOG_D("Using: (Intel BTS) type=%" PRIu32 " for PID: %d", perfIntelBtsPerfType, pid);
        pe.type = perfIntelBtsPerfType;
        break;
    case _HF_DYNFILE_BTS_EDGE:
        LOG_D("Using: (Intel BTS) type=%" PRIu32 " for PID: %d", perfIntelBtsPerfType, pid);
        pe.type = perfIntelBtsPerfType;
        break;
    case _HF_DYNFILE_IPT_BLOCK:
        LOG_D("Using: (Intel PT) type=%" PRIu32 " for PID: %d", perfIntelPtPerfType, pid);
        pe.type = perfIntelPtPerfType;
        pe.config = (1U << 11); /* Disable RETCompression */
        break;
    default:
        LOG_E("Unknown perf mode: '%d' for PID: %d", method, pid);
        return false;
        break;
    }

    *perfFd = perf_event_open(&pe, pid, -1, -1, 0);
    if (*perfFd == -1) {
        PLOG_F("perf_event_open() failed");
        return false;
    }

    if (method != _HF_DYNFILE_BTS_BLOCK && method != _HF_DYNFILE_BTS_EDGE
        && method != _HF_DYNFILE_IPT_BLOCK) {
        return true;
    }
#if defined(PERF_ATTR_SIZE_VER5)
    perfMmapBuf =
        mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, *perfFd, 0);
    if (perfMmapBuf == MAP_FAILED) {
        perfMmapBuf = NULL;
        PLOG_E("mmap(mmapBuf) failed, sz=%zu, try increasing kernel.perf_event_mlock_kb",
               (size_t) _HF_PERF_MAP_SZ + getpagesize());
        close(*perfFd);
        return false;
    }

    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)perfMmapBuf;
    pem->aux_offset = pem->data_offset + pem->data_size;
    pem->aux_size = _HF_PERF_AUX_SZ;
    perfMmapAux = mmap(NULL, pem->aux_size, PROT_READ, MAP_SHARED, *perfFd, pem->aux_offset);
    if (perfMmapAux == MAP_FAILED) {
        munmap(perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
        perfMmapBuf = NULL;
        PLOG_E("mmap(mmapAuxBuf) failed, try increasing kernel.perf_event_mlock_kb");
        close(*perfFd);
        return false;
    }
#else                           /* defined(PERF_ATTR_SIZE_VER5) */
    LOG_F("Your <linux/perf_event.h> includes are too old to support Intel PT/BTS");
#endif                          /* defined(PERF_ATTR_SIZE_VER5) */

    return true;
}

bool arch_perfEnable(pid_t pid, honggfuzz_t * hfuzz, perfFd_t * perfFds)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return true;
    }

    perfBloom = hfuzz->bbMap;
    perfBloomSz = hfuzz->bbMapSz;

    perfFds->cpuInstrFd = -1;
    perfFds->cpuBranchFd = -1;
    perfFds->cpuIptBtsFd = -1;

    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        if (arch_perfOpen(hfuzz, pid, _HF_DYNFILE_INSTR_COUNT, &perfFds->cpuInstrFd) == false) {
            LOG_E("Cannot set up perf for PID=%d (_HF_DYNFILE_INSTR_COUNT)", pid);
            goto out;
        }
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        if (arch_perfOpen(hfuzz, pid, _HF_DYNFILE_BRANCH_COUNT, &perfFds->cpuBranchFd) == false) {
            LOG_E("Cannot set up perf for PID=%d (_HF_DYNFILE_BRANCH_COUNT)", pid);
            goto out;
        }
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK) {
        if (arch_perfOpen(hfuzz, pid, _HF_DYNFILE_BTS_BLOCK, &perfFds->cpuIptBtsFd) == false) {
            LOG_E("Cannot set up perf for PID=%d (_HF_DYNFILE_BTS_BLOCK)", pid);
            goto out;
        }
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        if (arch_perfOpen(hfuzz, pid, _HF_DYNFILE_BTS_EDGE, &perfFds->cpuIptBtsFd) == false) {
            LOG_E("Cannot set up perf for PID=%d (_HF_DYNFILE_BTS_EDGE)", pid);
            goto out;
        }
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        if (arch_perfOpen(hfuzz, pid, _HF_DYNFILE_IPT_BLOCK, &perfFds->cpuIptBtsFd) == false) {
            LOG_E("Cannot set up perf for PID=%d (_HF_DYNFILE_IPT_BLOCK)", pid);
            goto out;
        }
    }

    return true;

 out:
    close(perfFds->cpuInstrFd);
    close(perfFds->cpuBranchFd);
    close(perfFds->cpuIptBtsFd);

    return false;
}

void arch_perfAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, perfFd_t * perfFds)
{
    if (hfuzz->dynFileMethod == _HF_DYNFILE_NONE) {
        return;
    }

    uint64_t instrCount = 0;
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        ioctl(perfFds->cpuInstrFd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(perfFds->cpuInstrFd, &instrCount, sizeof(instrCount)) != sizeof(instrCount)) {
            PLOG_E("read(perfFd='%d') failed", perfFds->cpuInstrFd);
        }
        close(perfFds->cpuInstrFd);
    }

    uint64_t branchCount = 0;
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        ioctl(perfFds->cpuBranchFd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(perfFds->cpuBranchFd, &branchCount, sizeof(branchCount)) != sizeof(branchCount)) {
            PLOG_E("read(perfFd='%d') failed", perfFds->cpuBranchFd);
        }
        close(perfFds->cpuBranchFd);
    }

    uint64_t newbbCount = 0;
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK) {
        close(perfFds->cpuIptBtsFd);
        newbbCount = arch_perfMmapParse(hfuzz);
    }

    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        close(perfFds->cpuIptBtsFd);
        newbbCount = arch_perfMmapParse(hfuzz);
    }

    if (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        close(perfFds->cpuIptBtsFd);
        newbbCount = arch_perfMmapParse(hfuzz);
    }

    if (perfMmapAux != NULL) {
        munmap(perfMmapAux, _HF_PERF_AUX_SZ);
        perfMmapAux = NULL;
    }
    if (perfMmapBuf != NULL) {
        munmap(perfMmapBuf, _HF_PERF_MAP_SZ + getpagesize());
        perfMmapBuf = NULL;
    }

    fuzzer->hwCnts.cpuInstrCnt = instrCount;
    fuzzer->hwCnts.cpuBranchCnt = branchCount;
    fuzzer->hwCnts.bbCnt = newbbCount;
}

bool arch_perfInit(honggfuzz_t * hfuzz)
{
    perfCutOffAddr = hfuzz->dynamicCutOffAddr;

    uint8_t buf[PATH_MAX + 1];
    size_t sz =
        files_readFileToBufMax("/sys/bus/event_source/devices/intel_pt/type", buf, sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = '\0';
        perfIntelPtPerfType = (int32_t) strtoul((char *)buf, NULL, 10);
        LOG_D("perfIntelPtPerfType = %" PRIu32, perfIntelPtPerfType);
    }
    sz = files_readFileToBufMax("/sys/bus/event_source/devices/intel_bts/type", buf,
                                sizeof(buf) - 1);
    if (sz > 0) {
        buf[sz] = '\0';
        perfIntelBtsPerfType = (int32_t) strtoul((char *)buf, NULL, 10);
        LOG_D("perfIntelBtsPerfType = %" PRIu32, perfIntelBtsPerfType);
    }
    return true;
}
