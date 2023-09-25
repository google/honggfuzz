/*
 *
 * honggfuzz - display statistics
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

#include "display.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#include <sys/resource.h>
#include <sys/sysctl.h>
#if defined(__OpenBSD__)
#include <sys/sched.h>
#endif
#endif

#if defined(__sun)
#include <kstat.h>
#endif

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/task_info.h>
#endif

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#define ESC_CLEAR_ALL           "\033[2J"
#define ESC_CLEAR_LINE          "\033[2K"
#define ESC_CLEAR_ABOVE         "\033[1J"
#define ESC_TERM_RESET          "\033c"
#define ESC_NAV(x, y)           "\033[" #x ";" #y "H"
#define ESC_BOLD                "\033[1m"
#define ESC_RED                 "\033[31m"
#define ESC_RESET               "\033[0m"
#define ESC_SCROLL_REGION(x, y) "\033[" #x ";" #y "r"
#define ESC_SCROLL_DISABLE      "\033[?7h"
#define ESC_SCROLL_RESET        "\033[r"
#define ESC_NAV_DOWN(x)         "\033[" #x "B"
#define ESC_NAV_HORIZ(x)        "\033[" #x "G"
#define ESC_RESET_SETTINGS      "\033[!p"

static char displayBuf[1024 * 1024];
static void display_start(void) {
    memset(displayBuf, '\0', sizeof(displayBuf));
}

static void display_stop(void) {
    TEMP_FAILURE_RETRY(write(logFd(), displayBuf, strlen(displayBuf)));
}

__attribute__((format(printf, 1, 2))) static void display_put(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    util_vssnprintf(displayBuf, sizeof(displayBuf), fmt, args);
    va_end(args);
}

static void display_imm(const char* str) {
    TEMP_FAILURE_RETRY(write(logFd(), str, strlen(str)));
}

static void display_printKMG(uint64_t val) {
    if (val >= 1000000000000ULL) {
        display_put(" [%.02LfT]", (long double)val / 1000000000.0L);
    } else if (val >= 1000000000UL) {
        display_put(" [%.02LfG]", (long double)val / 1000000000.0L);
    } else if (val >= 1000000UL) {
        display_put(" [%.02LfM]", (long double)val / 1000000.0L);
    } else if (val >= 1000UL) {
        display_put(" [%.02Lfk]", (long double)val / 1000.0L);
    }
}

static unsigned getCpuUse(int numCpus) {
    static uint64_t prevUserT   = 0UL;
    static uint64_t prevNiceT   = 0UL;
    static uint64_t prevSystemT = 0UL;
    static uint64_t prevIdleT   = 0UL;
    uint64_t        userT       = 0UL;
    uint64_t        niceT       = 0UL;
    uint64_t        systemT     = 0UL;
    uint64_t        idleT       = 0UL;

#if defined(__linux__) || defined(__CYGWIN__)
    FILE* f = fopen("/proc/stat", "re");
    if (UNLIKELY(f == NULL)) {
        return 0;
    }
    defer {
        fclose(f);
    };
    if (fscanf(f, "cpu  %" PRIu64 "%" PRIu64 "%" PRIu64 "%" PRIu64, &userT, &niceT, &systemT,
            &idleT) != 4) {
        LOG_W("fscanf('/proc/stat') != 4");
        return 0;
    }
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    long   ticks      = (1000 / sysconf(_SC_CLK_TCK));
    long   off        = 0;
    size_t cpuDataLen = sizeof(long) * CPUSTATES * numCpus;
    long*  cpuData    = malloc(cpuDataLen);
    if (UNLIKELY(cpuData == NULL)) {
        return 0;
    }

    if (sysctlbyname("kern.cp_times", cpuData, &cpuDataLen, NULL, 0) != 0) {
        LOG_W("sysctlbyname('kern.cp_times') != 0");
        free(cpuData);
        return 0;
    }

    userT = niceT = systemT = idleT = 0;

    for (int i = 0; i < numCpus; i++) {
        userT += cpuData[CP_USER + off] * ticks;
        niceT += cpuData[CP_NICE + off] * ticks;
        systemT += cpuData[CP_SYS + off] * ticks;
        idleT += cpuData[CP_IDLE + off] * ticks;
        off += CPUSTATES;
    }

    free(cpuData);
#elif defined(__NetBSD__)
    long ticks = (1000 / sysconf(_SC_CLK_TCK));

    userT = niceT = systemT = idleT = 0;

    for (int i = 0; i < numCpus; i++) {
        uint64_t cpuData[CPUSTATES];
        size_t   cpuDataLen = sizeof(cpuData);
        char     mib[24]    = {0};
        snprintf(mib, sizeof(mib), "kern.cp_time.%d", i);
        if (sysctlbyname(mib, &cpuData, &cpuDataLen, NULL, 0) != 0) {
            LOG_W("sysctlbyname('kern.cp_time') != 0");
            return 0;
        }
        userT += cpuData[CP_USER] * ticks;
        niceT += cpuData[CP_NICE] * ticks;
        systemT += cpuData[CP_SYS] * ticks;
        idleT += cpuData[CP_IDLE] * ticks;
    }
#elif defined(__OpenBSD__)
    long ticks = (1000 / sysconf(_SC_CLK_TCK));

    userT = niceT = systemT = idleT = 0;

    for (int i = 0; i < numCpus; i++) {
        uint64_t cpuData[CPUSTATES];
        size_t   cpuDataLen = sizeof(cpuData);
        int      mib[3]     = {CTL_KERN, KERN_CPTIME2, i};
        if (sysctl(mib, 3, &cpuData, &cpuDataLen, NULL, 0) != 0) {
            LOG_W("sysctl('KERN_CPTIME2') != 0");
            return 0;
        }
        userT += cpuData[CP_USER] * ticks;
        niceT += cpuData[CP_NICE] * ticks;
        systemT += cpuData[CP_SYS] * ticks;
        idleT += cpuData[CP_IDLE] * ticks;
    }
#elif defined(__sun)
    kstat_ctl_t* kctl = kstat_open();
    for (int i = 0; i < numCpus; i++) {
        kstat_named_t* data;
        kstat_t*       cpu = kstat_lookup(kctl, "cpu", i, NULL);
        if (!cpu) {
            LOG_W("kstat_lookup('cpu_info') != 0");
            continue;
        }
        kstat_read(kctl, cpu, NULL);
        data = kstat_data_lookup(cpu, "cpu_ticks_user");
        userT += data->value.ui64;
        data = kstat_data_lookup(cpu, "cpu_ticks_kernel");
        systemT += data->value.ui64;
        data = kstat_data_lookup(cpu, "cpu_ticks_idle");
        idleT += data->value.ui64;
    }

    kstat_close(kctl);
#else
    host_cpu_load_info_data_t avg;
    mach_msg_type_number_t    num = HOST_CPU_LOAD_INFO_COUNT;
    userT = niceT = systemT = idleT = 0;

    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&avg, &num) ==
        KERN_SUCCESS) {
        userT   = avg.cpu_ticks[CPU_STATE_USER];
        niceT   = avg.cpu_ticks[CPU_STATE_NICE];
        systemT = avg.cpu_ticks[CPU_STATE_SYSTEM];
        idleT   = avg.cpu_ticks[CPU_STATE_IDLE];
    }

#endif

    uint64_t userCycles   = (userT - prevUserT);
    uint64_t niceCycles   = (niceT - prevNiceT);
    uint64_t systemCycles = (systemT - prevSystemT);
    uint64_t idleCycles   = (idleT - prevIdleT);

    prevUserT   = userT;
    prevNiceT   = niceT;
    prevSystemT = systemT;
    prevIdleT   = idleT;

    uint64_t allCycles = userCycles + niceCycles + systemCycles + idleCycles;
    if (UNLIKELY(allCycles == 0)) {
        return 0;
    }

    return ((userCycles + niceCycles + systemCycles) * numCpus * 100) / (allCycles);
}

static void getDuration(time_t elapsed_second, char* buf, size_t bufSz) {
    if (elapsed_second < 0) {
        snprintf(buf, bufSz, "----");
        return;
    }

    unsigned int day, hour, min, second;
    day            = elapsed_second / 24 / 3600;
    elapsed_second = elapsed_second - day * 24 * 3600;
    hour           = elapsed_second / 3600;
    min            = (elapsed_second - 3600 * hour) / 60;
    second         = elapsed_second - hour * 3600 - min * 60;
    snprintf(buf, bufSz, "%u days %02u hrs %02u mins %02u secs", day, hour, min, second);
}

void display_createTargetStr(honggfuzz_t* hfuzz) {
    if (!hfuzz->exe.cmdline[0]) {
        LOG_W("Your fuzzed binary is not specified");
        snprintf(hfuzz->display.cmdline_txt, sizeof(hfuzz->display.cmdline_txt), "[EMPTY]");
        return;
    }

    static char tmpstr[1024 * 128] = {0};
    snprintf(tmpstr, sizeof(tmpstr), "%s", hfuzz->exe.cmdline[0]);
    for (int i = 1; i < hfuzz->exe.argc; i++) {
        util_ssnprintf(tmpstr, sizeof(tmpstr), " %s", hfuzz->exe.cmdline[i]);
    }

    size_t len = strlen(tmpstr);
    if (len <= (sizeof(hfuzz->display.cmdline_txt) - 1)) {
        snprintf(hfuzz->display.cmdline_txt, sizeof(hfuzz->display.cmdline_txt), "%s", tmpstr);
        return;
    }

    snprintf(hfuzz->display.cmdline_txt, sizeof(hfuzz->display.cmdline_txt), "%.32s.....%s", tmpstr,
        &tmpstr[len - 27]);
}

void display_display(honggfuzz_t* hfuzz) {
    if (!logIsTTY()) {
        return;
    }

    const time_t  curr_sec          = time(NULL);
    const time_t  elapsed_sec       = curr_sec - hfuzz->timing.timeStart;
    const int64_t curr_time_usecs   = util_timeNowUSecs();
    const int64_t elapsed_usecs     = curr_time_usecs - hfuzz->display.lastDisplayUSecs;
    hfuzz->display.lastDisplayUSecs = curr_time_usecs;

    char lastCovStr[64];
    getDuration(curr_sec - ATOMIC_GET(hfuzz->timing.lastCovUpdate), lastCovStr, sizeof(lastCovStr));
    char timeStr[64];
    if (ATOMIC_GET(hfuzz->timing.runEndTime)) {
        getDuration(ATOMIC_GET(hfuzz->timing.runEndTime) - curr_sec, timeStr, sizeof(timeStr));
    } else {
        getDuration(elapsed_sec, timeStr, sizeof(timeStr));
    }

    size_t curr_exec_cnt = ATOMIC_GET(hfuzz->cnts.mutationsCnt);
    /*
     * We increase the mutation counter unconditionally in threads, but if it's
     * above hfuzz->mutationsMax we don't really execute the fuzzing loop.
     * Therefore at the end of fuzzing, the mutation counter might be higher
     * than hfuzz->mutationsMax
     */
    if (hfuzz->mutate.mutationsMax > 0 && curr_exec_cnt > hfuzz->mutate.mutationsMax) {
        curr_exec_cnt = hfuzz->mutate.mutationsMax;
    }
    int exeProgress = 0;
    if (hfuzz->mutate.mutationsMax > 0) {
        exeProgress = (curr_exec_cnt * 100) / hfuzz->mutate.mutationsMax;
    }

    static size_t prev_exec_cnt = 0UL;
    size_t        exec_per_usecs =
        elapsed_usecs ? ((curr_exec_cnt - prev_exec_cnt) * 1000000) / elapsed_usecs : 0;
    prev_exec_cnt = curr_exec_cnt;

    display_start();

    display_put(ESC_NAV(13, 1) ESC_CLEAR_ABOVE ESC_NAV(1, 1));
    display_put("------------------------[" ESC_BOLD "%31s " ESC_RESET "]----------------------\n",
        timeStr);
    display_put("  Iterations : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET, curr_exec_cnt);
    display_printKMG(curr_exec_cnt);
    if (hfuzz->mutate.mutationsMax) {
        display_put(" (out of: " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET " [%d%%])",
            hfuzz->mutate.mutationsMax, exeProgress);
    }
    switch (ATOMIC_GET(hfuzz->feedback.state)) {
    case _HF_STATE_STATIC:
        display_put("\n        Mode : " ESC_BOLD "Static" ESC_RESET "\n");
        break;
    case _HF_STATE_DYNAMIC_DRY_RUN: {
        if (ATOMIC_GET(hfuzz->cfg.switchingToFDM)) {
            display_put("\n  Mode [2/3] : " ESC_BOLD
                        "Switching to the Feedback Driven Mode" ESC_RESET " [%zu/%zu]\n",
                hfuzz->io.testedFileCnt, hfuzz->io.fileCnt);
        } else {
            display_put("\n  Mode [1/3] : " ESC_BOLD "Feedback Driven Dry Run" ESC_RESET
                        " [%zu/%zu]\n",
                hfuzz->io.testedFileCnt, hfuzz->io.fileCnt);
        }
    } break;
    case _HF_STATE_DYNAMIC_MAIN:
        display_put("\n  Mode [3/3] : " ESC_BOLD "Feedback Driven Mode" ESC_RESET "\n");
        break;
    case _HF_STATE_DYNAMIC_MINIMIZE:
        display_put("\n  Mode [3/3] : " ESC_BOLD "Corpus Minimization" ESC_RESET "\n");
        break;
    default:
        display_put("\n        Mode : " ESC_BOLD "Unknown" ESC_RESET "\n");
        break;
    }
    display_put("      Target : " ESC_BOLD "%s" ESC_RESET "\n", hfuzz->display.cmdline_txt);

    static long num_cpu = 0;
    if (num_cpu == 0) {
        num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
    if (num_cpu <= 0) {
        num_cpu = 1;
    }
    unsigned cpuUse = getCpuUse(num_cpu);
    display_put("     Threads : " ESC_BOLD "%zu" ESC_RESET ", CPUs: " ESC_BOLD "%ld" ESC_RESET
                ", CPU%%: " ESC_BOLD "%u" ESC_RESET "%% [" ESC_BOLD "%lu" ESC_RESET "%%/CPU]\n",
        hfuzz->threads.threadsMax, num_cpu, cpuUse, cpuUse / num_cpu);

    size_t tot_exec_per_sec = elapsed_sec ? (curr_exec_cnt / elapsed_sec) : 0;
    display_put("       Speed : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET "/sec [avg: " ESC_BOLD
                "%" _HF_NONMON_SEP "zu" ESC_RESET "]\n",
        exec_per_usecs, tot_exec_per_sec);

    uint64_t crashesCnt = ATOMIC_GET(hfuzz->cnts.crashesCnt);
    /* colored the crash count as red when exist crash */
    display_put("     Crashes : " ESC_BOLD "%s"
                "%zu" ESC_RESET " [unique: %s" ESC_BOLD "%zu" ESC_RESET ", blocklist: " ESC_BOLD
                "%zu" ESC_RESET ", verified: " ESC_BOLD "%zu" ESC_RESET "]\n",
        crashesCnt > 0 ? ESC_RED : "", hfuzz->cnts.crashesCnt, crashesCnt > 0 ? ESC_RED : "",
        ATOMIC_GET(hfuzz->cnts.uniqueCrashesCnt), ATOMIC_GET(hfuzz->cnts.blCrashesCnt),
        ATOMIC_GET(hfuzz->cnts.verifiedCrashesCnt));
    display_put("    Timeouts : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET " [%lu sec]\n",
        ATOMIC_GET(hfuzz->cnts.timeoutedCnt), (unsigned long)hfuzz->timing.tmOut);
    /* Feedback data sources. Common headers. */
    display_put(" Corpus Size : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET ", max: " ESC_BOLD
                "%" _HF_NONMON_SEP "zu" ESC_RESET " bytes, init: " ESC_BOLD "%" _HF_NONMON_SEP
                "zu" ESC_RESET " files\n",
        hfuzz->io.dynfileqCnt, hfuzz->mutate.maxInputSz, ATOMIC_GET(hfuzz->io.fileCnt));
    display_put("  Cov Update : " ESC_BOLD "%s" ESC_RESET " ago\n" ESC_RESET, lastCovStr);
    display_put("    Coverage :");

    /* HW perf specific counters */
    if (hfuzz->feedback.dynFileMethod == 0) {
        display_put(" [none]");
    }
    if (hfuzz->feedback.dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        display_put(" hwi: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->feedback.hwCnts.cpuInstrCnt));
    }
    if (hfuzz->feedback.dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        display_put(" hwb: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->feedback.hwCnts.cpuBranchCnt));
    }
    if (hfuzz->feedback.dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        display_put(" bts: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->feedback.hwCnts.bbCnt));
    }
    if (hfuzz->feedback.dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        display_put(" ipt: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->feedback.hwCnts.bbCnt));
    }
    if (hfuzz->feedback.dynFileMethod & _HF_DYNFILE_SOFT) {
        uint64_t softCntPc   = ATOMIC_GET(hfuzz->feedback.hwCnts.softCntPc);
        uint64_t softCntEdge = ATOMIC_GET(hfuzz->feedback.hwCnts.softCntEdge);
        uint64_t softCntCmp  = ATOMIC_GET(hfuzz->feedback.hwCnts.softCntCmp);
        uint64_t guardNb     = ATOMIC_GET(hfuzz->feedback.covFeedbackMap->guardNb);
        display_put(" edge: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET "/"
                    "%" _HF_NONMON_SEP PRIu64 " [%" PRId64 "%%]",
            softCntEdge, guardNb, guardNb ? ((softCntEdge * 100) / guardNb) : 0);
        display_put(" pc: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET, softCntPc);
        display_put(" cmp: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET, softCntCmp);
    }

    display_put("\n---------------------------------- [ " ESC_BOLD "LOGS" ESC_RESET
                " ] ------------------/ " ESC_BOLD "%s %s " ESC_RESET "/-",
        PROG_NAME, PROG_VERSION);
    display_put(ESC_SCROLL_REGION(13, ) ESC_NAV_HORIZ(1) ESC_NAV_DOWN(500));

    MX_SCOPED_LOCK(logMutexGet());
    display_stop();
}

static void display_fini(void) {
    display_imm(ESC_SCROLL_RESET ESC_NAV_DOWN(500));
}

void display_clear(void) {
    display_imm(ESC_CLEAR_ALL);
    display_imm(ESC_NAV_DOWN(500));
}

void display_init(void) {
    atexit(display_fini);
    display_clear();
}
