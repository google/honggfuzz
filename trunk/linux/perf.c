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

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linux/perf.h"
#include "log.h"

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

bool arch_perfEnable(pid_t pid, honggfuzz_t * hfuzz, int *perfFd)
{
    if (hfuzz->createDynamically == false) {
        return true;
    }

    LOGMSG(l_DEBUG, "Enabling PERF for PID=%d", pid);

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    *perfFd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (*perfFd == -1) {
        LOGMSG_P(l_ERROR, "Error opening leader %llx", pe.config);
        return false;
    }

    ioctl(*perfFd, PERF_EVENT_IOC_RESET, 0);
    ioctl(*perfFd, PERF_EVENT_IOC_ENABLE, 0);
    return true;
}

void arch_perfAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, int perfFd)
{
    if (hfuzz->createDynamically == false) {
        return;
    }

    ioctl(perfFd, PERF_EVENT_IOC_DISABLE, 0);

    long long count = 0LL;
    read(perfFd, &count, sizeof(long long int));
    fuzzer->branchCnt = count;

    LOGMSG(l_INFO, "Executed %lld branch instructions", count);

    close(perfFd);
    if (fuzzer) {
        return;
    }
    return;
}
