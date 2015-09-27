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

#include "common.h"
#include "display.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

#define ESC_CLEAR "\033[H\033[2J"
#define ESC_NAV(x,y) "\033["#x";"#y"H"
#define ESC_BOLD "\033[1m"
#define ESC_RESET "\033[0m"

static void display_put(const char *fmt, ...)
{
    char buf[1024 * 512];

    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (ret <= 0) {
        return;
    }
    if (write(STDOUT_FILENO, buf, ret) == -1) {
        return;
    }
}

static void display_displayLocked(honggfuzz_t * hfuzz)
{
    unsigned long elapsed = (unsigned long)(time(NULL) - hfuzz->timeStart);

    size_t curr_exec_cnt = __sync_fetch_and_add(&hfuzz->mutationsCnt, 0UL);
    /*
     * We increase the mutation counter unconditionally in threads, but if it's
     * above hfuzz->mutationsMax we don't really execute the fuzzing loop.
     * Therefore at the end of fuzzing, the mutation counter might be higher
     * than hfuzz->mutationsMax
     */
    if (hfuzz->mutationsMax > 0 && curr_exec_cnt > hfuzz->mutationsMax) {
        curr_exec_cnt = hfuzz->mutationsMax;
    }
    static size_t prev_exec_cnt = 0UL;
    uintptr_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    display_put("%s", ESC_CLEAR);
    display_put("============================== STAT ==============================\n");

    display_put("Iterations: " ESC_BOLD "%zu" ESC_RESET, curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        display_put(" (out of: " ESC_BOLD "%zu" ESC_RESET ")", hfuzz->mutationsMax);
    }
    display_put("\n");

    char start_time_str[128];
    util_getLocalTime("%F %T", start_time_str, sizeof(start_time_str), hfuzz->timeStart);
    display_put("Start time: " ESC_BOLD "%s" ESC_RESET " (" ESC_BOLD "%lu"
                ESC_RESET " seconds elapsed)\n", start_time_str, elapsed);

    display_put("Input file/dir: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->inputFile);
    display_put("Fuzzed cmd: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->cmdline[0]);

    display_put("Fuzzing threads: " ESC_BOLD "%zu" ESC_RESET "\n", hfuzz->threadsMax);
    display_put("Execs per second: " ESC_BOLD "%zu" ESC_RESET " (avg: " ESC_BOLD "%zu" ESC_RESET
                ")\n", exec_per_sec, elapsed ? (curr_exec_cnt / elapsed) : 0);

    display_put("Crashes: " ESC_BOLD "%zu" ESC_RESET " (unique: " ESC_BOLD "%zu" ESC_RESET
                ", blacklist: " ESC_BOLD "%zu" ESC_RESET ") \n",
                __sync_fetch_and_add(&hfuzz->crashesCnt, 0UL),
                __sync_fetch_and_add(&hfuzz->uniqueCrashesCnt, 0UL),
                __sync_fetch_and_add(&hfuzz->blCrashesCnt, 0UL));
    display_put("Timeouts: " ESC_BOLD "%zu" ESC_RESET "\n",
                __sync_fetch_and_add(&hfuzz->timeoutedCnt, 0UL));

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        display_put("Dynamic file size: " ESC_BOLD "%zu" ESC_RESET " (max: " ESC_BOLD "%zu"
                    ESC_RESET ")\n", hfuzz->dynamicFileBestSz, hfuzz->maxFileSz);
        display_put("Coverage (max):\n");
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        display_put("  - cpu instructions:      " ESC_BOLD "%zu" ESC_RESET "\n",
                    __sync_fetch_and_add(&hfuzz->hwCnts.cpuInstrCnt, 0UL));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        display_put("  - cpu branches:          " ESC_BOLD "%zu" ESC_RESET "\n",
                    __sync_fetch_and_add(&hfuzz->hwCnts.cpuBranchCnt, 0UL));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT) {
        display_put("  - unique branch targets: " ESC_BOLD "%zu" ESC_RESET "\n",
                    __sync_fetch_and_add(&hfuzz->hwCnts.pcCnt, 0UL));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_EDGE_COUNT) {
        display_put("  - unique branch pairs:   " ESC_BOLD "%zu" ESC_RESET "\n",
                    __sync_fetch_and_add(&hfuzz->hwCnts.pathCnt, 0UL));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_CUSTOM) {
        display_put("  - custom counter:        " ESC_BOLD "%zu" ESC_RESET "\n",
                    __sync_fetch_and_add(&hfuzz->hwCnts.customCnt, 0UL));
    }
    display_put("============================== LOGS ==============================\n");
}

extern void display_display(honggfuzz_t * hfuzz)
{
    /* Don't mix up logs and display at this point */
    log_mutexLock();
    display_displayLocked(hfuzz);
    log_mutexUnLock();
}
