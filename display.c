/*
 *
 * honggfuzz - display statistics
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

#define _WITH_DPRINTF

#include "display.h"

#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libcommon/common.h"
#include "libcommon/log.h"
#include "libcommon/util.h"

#define ESC_CLEAR_ALL "\033[2J"
#define ESC_CLEAR_LINE "\033[2K"
#define ESC_CLEAR_ABOVE "\033[1J"
#define ESC_TERM_RESET "\033c"
#define ESC_NAV(x, y) "\033[" #x ";" #y "H"
#define ESC_BOLD "\033[1m"
#define ESC_RED "\033[31m"
#define ESC_RESET "\033[0m"
#define ESC_SCROLL(x, y) "\033[" #x ";" #y "r"
#define ESC_SCROLL_DISABLE "\033[?7h"
#define ESC_SCROLL_ENABLE "\033[r"
#define ESC_RESET_SETTINGS "\033[!p"

#if defined(_HF_ARCH_LINUX)
#define _HF_MONETARY_MOD "'"
#else
#define _HF_MONETARY_MOD ""
#endif

static void display_put(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vdprintf(logFd(), fmt, args);
    va_end(args);
}

static void display_printKMG(uint64_t val) {
    if (val >= 1000000000UL) {
        display_put(" [%.2lfG]", (double)val / 1000000000.0);
    } else if (val >= 1000000UL) {
        display_put(" [%.2lfM]", (double)val / 1000000.0);
    } else if (val >= 1000UL) {
        display_put(" [%.2lfk]", (double)val / 1000.0);
    }
}

static unsigned getCpuUse(long num_cpu) {
    static uint64_t prevIdleT = 0UL;

    FILE* f = fopen("/proc/stat", "re");
    if (f == NULL) {
        return 0;
    }
    defer { fclose(f); };
    uint64_t userT, niceT, systemT, idleT;
    if (fscanf(f, "cpu  %" PRIu64 "%" PRIu64 "%" PRIu64 "%" PRIu64, &userT, &niceT, &systemT,
            &idleT) != 4) {
        LOG_W("fscanf('/proc/stat') != 4");
        return 0;
    }

    if (prevIdleT == 0UL) {
        prevIdleT = idleT;
        return 0;
    }

    uint64_t cpuUse = (num_cpu * sysconf(_SC_CLK_TCK)) - (idleT - prevIdleT);
    prevIdleT = idleT;
    return cpuUse * 100 / sysconf(_SC_CLK_TCK);
}

static void display_displayLocked(honggfuzz_t* hfuzz) {
    static bool firstDisplay = true;
    if (firstDisplay) {
        display_put(ESC_CLEAR_ALL);
        firstDisplay = false;
    }

    unsigned long elapsed_second = (unsigned long)(time(NULL) - hfuzz->timing.timeStart);
    unsigned int day, hour, min, second;
    char time_elapsed_str[64];
    if (elapsed_second < 24 * 3600) {
        hour = elapsed_second / 3600;
        min = (elapsed_second - 3600 * hour) / 60;
        second = elapsed_second - hour * 3600 - min * 60;
        snprintf(
            time_elapsed_str, sizeof(time_elapsed_str), "%u hrs %u min %u sec", hour, min, second);
    } else {
        day = elapsed_second / 24 / 3600;
        elapsed_second = elapsed_second - day * 24 * 3600;
        hour = elapsed_second / 3600;
        min = (elapsed_second - 3600 * hour) / 60;
        second = elapsed_second - hour * 3600 - min * 60;
        snprintf(time_elapsed_str, sizeof(time_elapsed_str), "%u days %u hrs %u min %u sec", day,
            hour, min, second);
    }

    size_t curr_exec_cnt = ATOMIC_GET(hfuzz->cnts.mutationsCnt);
    /*
     * We increase the mutation counter unconditionally in threads, but if it's
     * above hfuzz->mutationsMax we don't really execute the fuzzing loop.
     * Therefore at the end of fuzzing, the mutation counter might be higher
     * than hfuzz->mutationsMax
     */
    if (hfuzz->mutationsMax > 0 && curr_exec_cnt > hfuzz->mutationsMax) {
        curr_exec_cnt = hfuzz->mutationsMax;
    }
    float exeProgress = 0.0f;
    if (hfuzz->mutationsMax > 0) {
        exeProgress = ((float)curr_exec_cnt * 100 / hfuzz->mutationsMax);
    }

    static size_t prev_exec_cnt = 0UL;
    uintptr_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    /* The lock should be acquired before any output is printed on the screen */
    MX_SCOPED_LOCK(logMutexGet());

    display_put(ESC_NAV(13, 1) ESC_CLEAR_ABOVE ESC_NAV(1, 1));
    display_put("--------------------------- [ " ESC_BOLD "HONGGFUZZ" ESC_RESET " / " ESC_BOLD
                "v%s" ESC_RESET " ] ------------------------------\n",
        PROG_VERSION);
    display_put("  Iterations : " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET, curr_exec_cnt);
    display_printKMG(curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        display_put(" (out of: " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET " [" ESC_BOLD
                    "%.2f" ESC_RESET "%%])",
            hfuzz->mutationsMax, exeProgress);
    }
    switch (ATOMIC_GET(hfuzz->state)) {
        case _HF_STATE_STATIC:
            display_put("\n       Phase : " ESC_BOLD "Main" ESC_RESET);
            break;
        case _HF_STATE_DYNAMIC_PRE:
            display_put("\n       Phase : " ESC_BOLD "Dynamic Dry Run (1/2)" ESC_RESET);
            break;
        case _HF_STATE_DYNAMIC_MAIN:
            display_put("\n       Phase : " ESC_BOLD "Dynamic Main (2/2)" ESC_RESET);
            break;
        default:
            display_put("\n       Phase : " ESC_BOLD "Unknown" ESC_RESET);
            break;
    }

    display_put("\n    Run Time : " ESC_BOLD "%s" ESC_RESET, time_elapsed_str);
    if (hfuzz->timing.runEndTime > 0) {
        time_t time_left = hfuzz->timing.runEndTime - time(NULL);
        if (time_left < 0) {
            time_left = 0;
        }
        if (time_left > 3600) {
            char end_time_str[512];
            util_getLocalTime(
                "%F %H:%M:%S", end_time_str, sizeof(end_time_str), hfuzz->timing.runEndTime);
            display_put(", end time: " ESC_BOLD "%s" ESC_RESET, end_time_str);
        } else {
            display_put(", left: " ESC_BOLD "%d" ESC_RESET " sec.", time_left);
        }
    }
    display_put("\n   Input Dir : [% " _HF_MONETARY_MOD "zu] '" ESC_BOLD "%s" ESC_RESET "'\n",
        ATOMIC_GET(hfuzz->io.fileCnt), hfuzz->io.inputDir);

    if (hfuzz->linux.pid > 0) {
        display_put("  Remote cmd : [" ESC_BOLD "%d" ESC_RESET "] '" ESC_BOLD "%s" ESC_RESET "'\n",
            hfuzz->linux.pid, hfuzz->linux.pidCmd);
    } else {
        display_put("  Fuzzed Cmd : '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->cmdline_txt);
    }

    static long num_cpu = 0;
    if (num_cpu == 0) {
        num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
    unsigned cpuUse = getCpuUse(num_cpu);
    display_put("     Threads : " ESC_BOLD "%zu" ESC_RESET ", CPUs: " ESC_BOLD "%ld" ESC_RESET
                ", CPU%: " ESC_BOLD "%u" ESC_RESET "%% (" ESC_BOLD "%u" ESC_RESET "%%/CPU)\n",
        hfuzz->threads.threadsMax, num_cpu, cpuUse, cpuUse / num_cpu);

    display_put("       Speed : " ESC_BOLD "% " _HF_MONETARY_MOD "zu" ESC_RESET
                "/sec"
                " (avg: " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET ")\n",
        exec_per_sec, elapsed_second ? (curr_exec_cnt / elapsed_second) : 0);

    uint64_t crashesCnt = ATOMIC_GET(hfuzz->cnts.crashesCnt);
    /* colored the crash count as red when exist crash */
    display_put("     Crashes : " ESC_BOLD
                "%s"
                "%zu" ESC_RESET " (unique: %s" ESC_BOLD "%zu" ESC_RESET ", blacklist: " ESC_BOLD
                "%zu" ESC_RESET ", verified: " ESC_BOLD "%zu" ESC_RESET ")\n",
        crashesCnt > 0 ? ESC_RED : "", hfuzz->cnts.crashesCnt, crashesCnt > 0 ? ESC_RED : "",
        ATOMIC_GET(hfuzz->cnts.uniqueCrashesCnt), ATOMIC_GET(hfuzz->cnts.blCrashesCnt),
        ATOMIC_GET(hfuzz->cnts.verifiedCrashesCnt));
    display_put("    Timeouts : " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET
                " [%" _HF_MONETARY_MOD "zu sec.]\n",
        ATOMIC_GET(hfuzz->cnts.timeoutedCnt), hfuzz->timing.tmOut);
    /* Feedback data sources. Common headers. */
    display_put(" Corpus Size : " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET
                ", max file size: " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET "\n",
        hfuzz->dynfileqCnt, hfuzz->maxFileSz);
    display_put("    Coverage :");

    /* HW perf specific counters */
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        display_put(" hwi: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.cpuInstrCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        display_put(" hwb: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.cpuBranchCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        display_put(" bts: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        display_put(" ipt: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_SOFT) {
        uint64_t softCntPc = ATOMIC_GET(hfuzz->linux.hwCnts.softCntPc);
        uint64_t softCntEdge = ATOMIC_GET(hfuzz->linux.hwCnts.softCntEdge);
        uint64_t softCntCmp = ATOMIC_GET(hfuzz->linux.hwCnts.softCntCmp);
        display_put(" edge: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET, softCntEdge);
        display_put(" pc: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET, softCntPc);
        display_put(" cmp: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET, softCntCmp);
    }

    /* Sanitizer coverage specific counters */
    if (hfuzz->useSanCov) {
        uint64_t hitBB = ATOMIC_GET(hfuzz->sanCovCnts.hitBBCnt);
        uint64_t totalBB = ATOMIC_GET(hfuzz->sanCovCnts.totalBBCnt);
        float covPer = totalBB ? (((float)hitBB * 100) / totalBB) : 0.0;
        display_put(" #sancov_bb: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    " (cov: " ESC_BOLD "%.2f" ESC_RESET "%%)",
            hitBB, covPer);
        display_put(" #dso: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->sanCovCnts.iDsoCnt));
        display_put(" #newbb: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->sanCovCnts.newBBCnt));
        display_put(" #crashes: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->sanCovCnts.crashesCnt));
    }
    display_put("\n---------------------------------- [ " ESC_BOLD "LOGS" ESC_RESET
                " ] -----------------------------------\n");
    display_put(ESC_SCROLL(14, 999) ESC_NAV(999, 1));
}

extern void display_display(honggfuzz_t* hfuzz) {
    if (logIsTTY() == false) {
        return;
    }
    display_displayLocked(hfuzz);
}

extern void display_fini(void) { display_put(ESC_SCROLL_ENABLE ESC_NAV(999, 1)); }

extern void display_init(void) {
    atexit(display_fini);
    display_put(ESC_NAV(999, 1));
}
