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

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#define ESC_CLEAR_ALL "\033[2J"
#define ESC_CLEAR_LINE "\033[2K"
#define ESC_CLEAR_ABOVE "\033[1J"
#define ESC_TERM_RESET "\033c"
#define ESC_NAV(x, y) "\033[" #x ";" #y "H"
#define ESC_BOLD "\033[1m"
#define ESC_RED "\033[31m"
#define ESC_RESET "\033[0m"
#define ESC_SCROLL_REGION(x, y) "\033[" #x ";" #y "r"
#define ESC_SCROLL_DISABLE "\033[?7h"
#define ESC_SCROLL_RESET "\033[r"
#define ESC_NAV_DOWN(x) "\033[" #x "B"
#define ESC_NAV_HORIZ(x) "\033[" #x "G"
#define ESC_RESET_SETTINGS "\033[!p"

/* printf() nonmonetary separator. According to MacOSX's man it's supported there as well */
#define _HF_NONMON_SEP "'"

__attribute__((format(printf, 1, 2))) static void display_put(const char* fmt, ...) {
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
    defer {
        fclose(f);
    };
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

static void display_Duration(time_t elapsed_second, char* buf, size_t bufSz) {
    if (elapsed_second < 0) {
        snprintf(buf, bufSz, "----");
        return;
    }

    unsigned int day, hour, min, second;
    day = elapsed_second / 24 / 3600;
    elapsed_second = elapsed_second - day * 24 * 3600;
    hour = elapsed_second / 3600;
    min = (elapsed_second - 3600 * hour) / 60;
    second = elapsed_second - hour * 3600 - min * 60;
    snprintf(buf, bufSz, "%u days %02u hrs %02u mins %02u secs", day, hour, min, second);
}

static void display_displayLocked(honggfuzz_t* hfuzz) {
    const time_t curr_time = time(NULL);
    const time_t elapsed_sec = curr_time - hfuzz->timing.timeStart;

    char lastCovStr[64];
    display_Duration(
        curr_time - ATOMIC_GET(hfuzz->timing.lastCovUpdate), lastCovStr, sizeof(lastCovStr));
    char timeStr[64];
    if (ATOMIC_GET(hfuzz->timing.runEndTime)) {
        display_Duration(
            ATOMIC_GET(hfuzz->timing.runEndTime) - curr_time, timeStr, sizeof(timeStr));
    } else {
        display_Duration(elapsed_sec, timeStr, sizeof(timeStr));
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
    size_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    /* The lock should be acquired before any output is printed on the screen */
    MX_SCOPED_LOCK(logMutexGet());

    display_put(ESC_NAV(13, 1) ESC_CLEAR_ABOVE ESC_NAV(1, 1));
    display_put("------------------------[" ESC_BOLD "%31s " ESC_RESET "]----------------------\n",
        timeStr);
    display_put("  Iterations : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET, curr_exec_cnt);
    display_printKMG(curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        display_put(" (out of: " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET " [%.2f%%])",
            hfuzz->mutationsMax, exeProgress);
    }
    switch (ATOMIC_GET(hfuzz->state)) {
        case _HF_STATE_STATIC:
            display_put("\n        Mode : " ESC_BOLD "Static" ESC_RESET "\n");
            break;
        case _HF_STATE_DYNAMIC_DRY_RUN:
            display_put(
                "\n        Mode : " ESC_BOLD "Feedback Driven Dry Run (1/2)" ESC_RESET "\n");
            break;
        case _HF_STATE_DYNAMIC_MAIN:
            display_put("\n        Mode : " ESC_BOLD "Feedback Driven Mode (2/2)" ESC_RESET "\n");
            break;
        default:
            display_put("\n        Mode : " ESC_BOLD "Unknown" ESC_RESET "\n");
            break;
    }

    if (hfuzz->linux.pid > 0) {
        display_put("      Target : [" ESC_BOLD "%d" ESC_RESET "] '" ESC_BOLD "%s" ESC_RESET "'\n",
            hfuzz->linux.pid, hfuzz->linux.pidCmd);
    } else {
        display_put("      Target : " ESC_BOLD "%s" ESC_RESET "\n", hfuzz->cmdline_txt);
    }

    static long num_cpu = 0;
    if (num_cpu == 0) {
        num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
    unsigned cpuUse = getCpuUse(num_cpu);
    display_put("     Threads : " ESC_BOLD "%zu" ESC_RESET ", CPUs: " ESC_BOLD "%ld" ESC_RESET
                ", CPU%%: " ESC_BOLD "%u" ESC_RESET "%% (" ESC_BOLD "%lu" ESC_RESET "%%/CPU)\n",
        hfuzz->threads.threadsMax, num_cpu, cpuUse, cpuUse / num_cpu);

    size_t tot_exec_per_sec = elapsed_sec ? (curr_exec_cnt / elapsed_sec) : 0;
    display_put("       Speed : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET
                "/sec"
                " (avg: " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET ")\n",
        exec_per_sec, tot_exec_per_sec);

    uint64_t crashesCnt = ATOMIC_GET(hfuzz->cnts.crashesCnt);
    /* colored the crash count as red when exist crash */
    display_put("     Crashes : " ESC_BOLD
                "%s"
                "%zu" ESC_RESET " (unique: %s" ESC_BOLD "%zu" ESC_RESET ", blacklist: " ESC_BOLD
                "%zu" ESC_RESET ", verified: " ESC_BOLD "%zu" ESC_RESET ")\n",
        crashesCnt > 0 ? ESC_RED : "", hfuzz->cnts.crashesCnt, crashesCnt > 0 ? ESC_RED : "",
        ATOMIC_GET(hfuzz->cnts.uniqueCrashesCnt), ATOMIC_GET(hfuzz->cnts.blCrashesCnt),
        ATOMIC_GET(hfuzz->cnts.verifiedCrashesCnt));
    display_put("    Timeouts : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET " [%lu sec]\n",
        ATOMIC_GET(hfuzz->cnts.timeoutedCnt), (unsigned long)hfuzz->timing.tmOut);
    /* Feedback data sources. Common headers. */
    display_put(" Corpus Size : " ESC_BOLD "%" _HF_NONMON_SEP "zu" ESC_RESET ", max size: " ESC_BOLD
                "%" _HF_NONMON_SEP "zu" ESC_RESET " bytes, init dir: " ESC_BOLD "%" _HF_NONMON_SEP
                "zu" ESC_RESET " files\n",
        hfuzz->dynfileqCnt, hfuzz->maxFileSz, ATOMIC_GET(hfuzz->io.fileCnt));
    display_put("  Cov Update : " ESC_BOLD "%s" ESC_RESET " ago\n" ESC_RESET, lastCovStr);
    display_put("    Coverage :");

    /* HW perf specific counters */
    if (hfuzz->dynFileMethod == 0) {
        display_put(" [none]");
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        display_put(" hwi: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.cpuInstrCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        display_put(" hwb: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.cpuBranchCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        display_put(" bts: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        display_put(" ipt: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_SOFT) {
        uint64_t softCntPc = ATOMIC_GET(hfuzz->linux.hwCnts.softCntPc);
        uint64_t softCntEdge = ATOMIC_GET(hfuzz->linux.hwCnts.softCntEdge);
        uint64_t softCntCmp = ATOMIC_GET(hfuzz->linux.hwCnts.softCntCmp);
        display_put(" edge: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET, softCntEdge);
        display_put(" pc: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET, softCntPc);
        display_put(" cmp: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET, softCntCmp);
    }

    /* Sanitizer coverage specific counters */
    if (hfuzz->dynFileMethod & _HF_DYNFILE_SANCOV) {
        uint64_t hitBB = ATOMIC_GET(hfuzz->sanCovCnts.hitBBCnt);
        uint64_t totalBB = ATOMIC_GET(hfuzz->sanCovCnts.totalBBCnt);
        float covPer = totalBB ? (((float)hitBB * 100) / totalBB) : 0.0;
        display_put(" #sancov_bb: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET " (cov: " ESC_BOLD
                    "%.2f" ESC_RESET "%%)",
            hitBB, covPer);
        display_put(" #dso: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->sanCovCnts.iDsoCnt));
        display_put(" #newbb: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->sanCovCnts.newBBCnt));
        display_put(" #crashes: " ESC_BOLD "%" _HF_NONMON_SEP PRIu64 ESC_RESET,
            ATOMIC_GET(hfuzz->sanCovCnts.crashesCnt));
    }
    display_put("\n---------------------------------- [ " ESC_BOLD "LOGS" ESC_RESET
                " ] ------------------/ " ESC_BOLD "%s %s " ESC_RESET "/-",
        PROG_NAME, PROG_VERSION);
    display_put(ESC_SCROLL_REGION(13, ) ESC_NAV_HORIZ(1) ESC_NAV_DOWN(500));
}

void display_createTargetStr(honggfuzz_t* hfuzz) {
    if (!hfuzz->exe.cmdline[0]) {
        LOG_W("Your fuzzed binary is not specified");
        snprintf(hfuzz->cmdline_txt, sizeof(hfuzz->cmdline_txt), "[EMPTY]");
        return;
    }

    static char tmpstr[1024 * 128] = {0};
    snprintf(tmpstr, sizeof(tmpstr), "%s", hfuzz->exe.cmdline[0]);
    for (int i = 1; i < hfuzz->exe.argc; i++) {
        util_ssnprintf(tmpstr, sizeof(tmpstr), " %s", hfuzz->exe.cmdline[i]);
    }

    size_t len = strlen(tmpstr);
    if (len <= (sizeof(hfuzz->cmdline_txt) - 1)) {
        snprintf(hfuzz->cmdline_txt, sizeof(hfuzz->cmdline_txt), "%s", tmpstr);
        return;
    }

    snprintf(
        hfuzz->cmdline_txt, sizeof(hfuzz->cmdline_txt), "%.32s.....%s", tmpstr, &tmpstr[len - 27]);
}

void display_display(honggfuzz_t* hfuzz) {
    if (logIsTTY() == false) {
        return;
    }
    display_displayLocked(hfuzz);
}

void display_fini(void) {
    display_put(ESC_SCROLL_RESET ESC_NAV_DOWN(500));
}

void display_init(void) {
    atexit(display_fini);
    display_put(ESC_CLEAR_ALL);
    display_put(ESC_NAV_DOWN(500));
}
