/*
 *
 * honggfuzz - display statistics
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *         riusksk <riusksk@qq.com>
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

#include "common.h"
#include "display.h"
#include "files.h"

#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

#define ESC_CLEAR "\033[H\033[2J"
#define ESC_NAV(x,y) "\033["#x";"#y"H"
#define ESC_BOLD "\033[1m"
#define ESC_RED "\033[31m"
#define ESC_GREEN "\033[32m"
#define ESC_PINK "\033[35m"
#define ESC_WHITE "\033[37m"
#define ESC_YELLOW "\033[33m"
#define ESC_BLUE "\033[34m"
#define ESC_RESET "\033[0m"

#define ESC_CLEAR_ALL "\033[2J"
#define ESC_CLEAR_ABOVE "\033[1J"
#define ESC_SCROLL(x,y) "\033["#x";"#y"r"
#define ESC_SCROLL_DISABLE "\033[?7h"

#if defined(_HF_ARCH_LINUX)
#define _HF_MONETARY_MOD "'"
#else
#define _HF_MONETARY_MOD ""
#endif

static void display_put(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vdprintf(logFd(), fmt, args);
    va_end(args);
}

static void display_printKMG(uint64_t val)
{
    if (val >= 1000000000UL) {
        display_put(" [%.2lfG]", (double)val / 1000000000.0);
    } else if (val >= 1000000UL) {
        display_put(" [%.2lfM]", (double)val / 1000000.0);
    } else if (val >= 1000UL) {
        display_put(" [%.2lfk]", (double)val / 1000.0);
    }
}

static double getCpuUse(long num_cpu)
{
    static uint64_t prevIdleT = 0UL;

    FILE *f = fopen("/proc/stat", "re");
    if (f == NULL) {
        return NAN;
    }
    defer {
        fclose(f);
    };
    uint64_t userT, niceT, systemT, idleT; 
    if (fscanf
        (f, "cpu  %" PRIu64 "%" PRIu64 "%" PRIu64 "%" PRIu64, &userT, &niceT, &systemT,
         &idleT) != 4) {
        LOG_W("fscanf('/proc/stat') != 4");
        return NAN;
    }

    if (prevIdleT == 0UL) {
        prevIdleT = idleT;
        return NAN;
    }

    uint64_t cpuUse = (num_cpu * sysconf(_SC_CLK_TCK)) - (idleT - prevIdleT);
    prevIdleT = idleT;
    return (double)cpuUse / sysconf(_SC_CLK_TCK) * 100;
}

static char* get_time_elapsed(uint64_t start_time) 
{
    unsigned long elapsed_second;
    elapsed_second = (unsigned long)(time(NULL) - start_time);
   
    unsigned int day, hour, min, second;
    static char str_time_elapsed[64];

    if (elapsed_second < 24 * 3600) {
        hour = elapsed_second / 3600;
        min = (elapsed_second - 3600 * hour) / 60;
        second = elapsed_second - hour * 3600 - min * 60;
        snprintf(str_time_elapsed, sizeof(str_time_elapsed), "%02u:%02u:%02u", hour,
                 min, second);
    } else {
        day = elapsed_second / 24 / 3600;
        elapsed_second = elapsed_second - day * 24 * 3600;
        hour = elapsed_second / 3600;
        min = (elapsed_second - 3600 * hour) / 60;
        second = elapsed_second - hour * 3600 - min * 60;
        snprintf(str_time_elapsed, sizeof(str_time_elapsed),
                 "%u days %02u:%02u:%02u", day, hour, min, second);
    }
    return str_time_elapsed;
}    

static char* get_time_remain(unsigned long remain_second) 
{   
    unsigned int day, hour, min, second;
    static char str_time_remain[64];

    if (remain_second < 24 * 3600) {
        hour = remain_second / 3600;
        min = (remain_second - 3600 * hour) / 60;
        second = remain_second - hour * 3600 - min * 60;
        snprintf(str_time_remain, sizeof(str_time_remain), "%02u:%02u:%02u", hour,
                 min, second);
    } else {
        day = remain_second / 24 / 3600;
        remain_second = remain_second - day * 24 * 3600;
        hour = remain_second / 3600;
        min = (remain_second - 3600 * hour) / 60;
        second = remain_second - hour * 3600 - min * 60;
        snprintf(str_time_remain, sizeof(str_time_remain),
                 "%u days %02u:%02u:%02u", day, hour, min, second);
    }
    return str_time_remain;
}

static void display_displayLocked(honggfuzz_t * hfuzz)
{
    static bool firstDisplay = true;
    if (firstDisplay) {
        display_put(ESC_CLEAR_ALL);
        firstDisplay = false;
    }

    char *target;
    char *extern_fuzzer;
    char *time_elapsed_str;
    char *time_remain_str;
    unsigned long elapsed_second;
    unsigned long remain_second;
    float speed_second;

    elapsed_second = (unsigned long)(time(NULL) - hfuzz->timeStart);
    time_elapsed_str = get_time_elapsed(hfuzz->timeStart);
   
    size_t curr_exec_cnt = ATOMIC_GET(hfuzz->mutationsCnt);
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

    target = files_get_filename_in_path(hfuzz->cmdline[0]);
    hfuzz->target = target;

    speed_second =  elapsed_second ? ((float)curr_exec_cnt / elapsed_second) : ((float)ATOMIC_GET(hfuzz->tmOut)/hfuzz->threadsMax);
    LOG_D("speed_second: %f\n", speed_second);
    int remain_file_cnt = ATOMIC_GET(hfuzz->fileCnt) - curr_exec_cnt;
    remain_second = (remain_file_cnt>0? remain_file_cnt:1) / speed_second;
    time_remain_str = get_time_remain(remain_second);

    display_put(ESC_NAV(11, 1) ESC_CLEAR_ABOVE ESC_NAV(1, 1));
    display_put("-------------------------[ " ESC_BOLD ESC_YELLOW "%s " ESC_RESET ESC_BOLD"v%s "  ESC_PINK "(%s)" ESC_RESET" ]-------------------------\n",
                PROG_NAME, PROG_VERSION, target );
    display_put(ESC_WHITE "  Iterations : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET, curr_exec_cnt);
    display_printKMG(curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        display_put(" (out of: " ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET " [" ESC_BOLD "%.2f"
            ESC_RESET "%%])", hfuzz->mutationsMax, exeProgress);
    }

    switch (ATOMIC_GET(hfuzz->state)) {
    case _HF_STATE_STATIC:
        display_put(ESC_WHITE "\n    Run Mode : " ESC_RESET ESC_GREEN ESC_BOLD "Dumb Fuzzing" ESC_RESET);
        break;
    case _HF_STATE_DRY_RUN:
        display_put(ESC_WHITE "\n    Run Mode : " ESC_RESET ESC_GREEN ESC_BOLD "Dry Run" ESC_RESET);
    break;
    case _HF_STATE_DYNAMIC_PRE:
        display_put(ESC_WHITE "\n    Run Mode : " ESC_RESET ESC_GREEN ESC_BOLD "Dynamic Fuzzing" ESC_RESET);
        break;
    case _HF_STATE_DYNAMIC_MAIN:
        display_put(ESC_WHITE "\n    Run Mode : " ESC_RESET ESC_GREEN ESC_BOLD "Feedback-driven Fuzzing" ESC_RESET);
        break;
    case _HF_STATE_EXTERN:
        extern_fuzzer = files_get_filename_in_path(hfuzz->externalCommand);
        display_put(ESC_WHITE "\n    Run Mode : " ESC_RESET ESC_GREEN ESC_BOLD "External (%s)" ESC_RESET, extern_fuzzer);
        break;
    default:
        display_put(ESC_WHITE "\n    Run Mode : " ESC_RESET ESC_GREEN ESC_BOLD "Unknown" ESC_RESET);
        break;
    }

    char start_time_str[128];
    util_getLocalTime("%F %T", start_time_str, sizeof(start_time_str), hfuzz->timeStart);
    if(ATOMIC_GET(hfuzz->state) == _HF_STATE_DRY_RUN){
        display_put(ESC_WHITE "\n    Run Time : " ESC_RESET ESC_BOLD "%s (" ESC_RESET ESC_WHITE "Remain: " ESC_RESET ESC_BOLD "%s)\n" ESC_RESET , time_elapsed_str, time_remain_str);
    }else{
        display_put(ESC_WHITE "\n    Run Time : " ESC_RESET ESC_BOLD "%s\n" ESC_RESET , time_elapsed_str);   
    }

    static char tmpstr[1024] = {0};
    size_t len = strlen(hfuzz->inputDir);
    if(len > 40){
        snprintf(tmpstr, sizeof(tmpstr), "%.32s...%s", hfuzz->inputDir, hfuzz->inputDir+len-18);
    }else{
        snprintf(tmpstr, sizeof(tmpstr), "%s", hfuzz->inputDir);
    }
    
    display_put(ESC_WHITE "   Input Dir : " ESC_RESET ESC_RED "[% " _HF_MONETARY_MOD "zu] " ESC_RESET ESC_BOLD "'%s" ESC_RESET "'\n",
                ATOMIC_GET(hfuzz->fileCnt), tmpstr);
    /*
    display_put(ESC_WHITE "  Fuzzed Cmd : " ESC_RESET ESC_BOLD "'%s" ESC_RESET "'\n", hfuzz->cmdline_txt);
    if (hfuzz->linux.pid > 0) {
        display_put(ESC_WHITE "Remote cmd [" ESC_BOLD "%d" ESC_RESET "]: '" ESC_RESET ESC_BOLD "%s" ESC_RESET
                    "'\n", hfuzz->linux.pid, hfuzz->linux.pidCmd);
    }
    */
    static long num_cpu = 0;
    if (num_cpu == 0) {
        num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
    double cpuUse = getCpuUse(num_cpu);
    display_put(ESC_WHITE "     Threads : " ESC_RESET ESC_BOLD "%zu" ESC_RESET ", " ESC_WHITE "CPUs: " ESC_RESET ESC_BOLD "%ld" ESC_RESET
                ", " ESC_WHITE "CPU: " ESC_RESET ESC_BOLD "%.1lf" ESC_RESET "%%\n",
                hfuzz->threadsMax, num_cpu, cpuUse / num_cpu);

    display_put(ESC_WHITE "       Speed : " ESC_RESET ESC_BOLD "% " _HF_MONETARY_MOD "zu" ESC_RESET "/sec"
                " (" ESC_WHITE "avg: " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET ")\n", exec_per_sec,
                elapsed_second ? (curr_exec_cnt / elapsed_second) : 0);

    uint64_t crashesCnt = ATOMIC_GET(hfuzz->crashesCnt);
    /* colored the crash count as red when exist crash */
    display_put(ESC_WHITE "     Crashes : " ESC_RESET ESC_BOLD "%s" "%zu" ESC_RESET " (" ESC_WHITE "unique: " ESC_RESET "%s" ESC_BOLD "%zu"
                ESC_RESET ", " ESC_WHITE "blacklist: " ESC_RESET ESC_BOLD "%zu" ESC_RESET ", " ESC_WHITE "verified: " ESC_RESET 
                ESC_BOLD "%s" "%zu" ESC_RESET ")\n", crashesCnt > 0 ? ESC_RED : "", hfuzz->crashesCnt, 
                ATOMIC_GET(hfuzz->uniqueCrashesCnt) > 0 ? ESC_RED : "",
                ATOMIC_GET(hfuzz->uniqueCrashesCnt), ATOMIC_GET(hfuzz->blCrashesCnt), 
                ATOMIC_GET(hfuzz->verifiedCrashesCnt) > 0 ? ESC_RED : "",
                ATOMIC_GET(hfuzz->verifiedCrashesCnt));
    display_put(ESC_WHITE "    Timeouts : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET " [%"
                _HF_MONETARY_MOD "zu sec]\n", ATOMIC_GET(hfuzz->timeoutedCnt), hfuzz->tmOut);
    /* Feedback data sources are enabled. Start with common headers. */
    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE || hfuzz->useSanCov) {
        /*
        display_put(ESC_WHITE " Corpus Size : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET
                    ", " ESC_WHITE "max size (bytes): " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD "zu" ESC_RESET "\n",
                    hfuzz->dynfileqCnt, hfuzz->maxFileSz);
        display_put(ESC_WHITE "    Coverage :\n" ESC_RESET);
        */
    }else{
        display_put(ESC_WHITE "    Coverage : N/A\n" ESC_RESET);
    }

    /* HW perf specific counters */
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        display_put(ESC_YELLOW "       *** instructions:   " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    "\n", ATOMIC_GET(hfuzz->linux.hwCnts.cpuInstrCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        display_put(ESC_YELLOW "       *** branches:       " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    "\n", ATOMIC_GET(hfuzz->linux.hwCnts.cpuBranchCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK) {
        display_put(ESC_YELLOW "       *** BTS blocks:     " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    "\n", ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        display_put(ESC_YELLOW "       *** BTS edges:      " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    "\n", ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        display_put(ESC_YELLOW "       *** PT blocks:      " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    "\n", ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }

    if (hfuzz->dynFileMethod & _HF_DYNFILE_SOFT) {
        uint64_t softCntPc = ATOMIC_GET(hfuzz->linux.hwCnts.softCntPc);
        uint64_t softCntCmp = ATOMIC_GET(hfuzz->linux.hwCnts.softCntCmp);
        display_put(ESC_YELLOW "       *** blocks seen:    " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    ", comparison map: " ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET "\n",
                    softCntPc, softCntCmp);
    }

    /* Sanitizer coverage specific counters */
    if (hfuzz->useSanCov) {
        uint64_t hitBB = ATOMIC_GET(hfuzz->sanCovCnts.hitBBCnt);
        uint64_t totalBB = ATOMIC_GET(hfuzz->sanCovCnts.totalBBCnt);
        float covPer = totalBB ? (((float)hitBB * 100) / totalBB) : 0.0;
        display_put(ESC_YELLOW "    Coverage : " ESC_RESET ESC_BOLD "%.2f" ESC_RESET "%%"
                "(" ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET ESC_WHITE 
                ", last update:" ESC_RESET ESC_BOLD " %s" ESC_RESET ")\n", covPer, hitBB, 
                get_time_elapsed(ATOMIC_GET(hfuzz->sanCovCnts.lastBBTime)));
        /*
        display_put(ESC_YELLOW "       *** hit #bb    : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    " (" ESC_WHITE "coverage: " ESC_RESET ESC_BOLD "%.2f" ESC_RESET "%%)\n", hitBB, covPer);
        display_put(ESC_YELLOW "       *** total #dso : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    " (" ESC_WHITE "Instrumented Dynamic Shared Object" ESC_RESET ")\n", ATOMIC_GET(hfuzz->sanCovCnts.iDsoCnt));
        display_put(ESC_YELLOW "       *** new #bb    : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    " (" ESC_WHITE "last update:" ESC_RESET ESC_BOLD " %s)\n" ESC_RESET, 
                    ATOMIC_GET(hfuzz->sanCovCnts.newBBCnt), 
                    get_time_elapsed(ATOMIC_GET(hfuzz->sanCovCnts.lastBBTime)));          
        display_put(ESC_YELLOW "       *** crashes    : " ESC_RESET ESC_BOLD "%" _HF_MONETARY_MOD PRIu64 ESC_RESET
                    "\n", ATOMIC_GET(hfuzz->sanCovCnts.crashesCnt));
        */
    }
    display_put("-----------------------------------[ " ESC_BOLD ESC_YELLOW "LOGS" ESC_RESET 
                " ]-----------------------------------\n");
    display_put(ESC_SCROLL(12, 999) ESC_NAV(999, 1));
}

extern void display_display(honggfuzz_t * hfuzz)
{
    if (logIsTTY() == false) {
        return;
    }
    display_displayLocked(hfuzz);
}

extern void display_fini(void)
{
    display_put(ESC_SCROLL(1, 999) ESC_NAV(999, 1));
}

extern void display_init(void)
{
    atexit(display_fini);
    display_put(ESC_NAV(999, 1));
}
