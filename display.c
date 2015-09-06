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

extern void display_display(honggfuzz_t * hfuzz)
{
    unsigned long elapsed = (unsigned long)(time(NULL) - hfuzz->timeStart);
    size_t curr_exec_cnt = __sync_fetch_and_add(&hfuzz->mutationsCnt, 0UL);
    static size_t prev_exec_cnt = 0UL;
    uintptr_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    display_put("%s", ESC_CLEAR);
    display_put("============================== STAT ==============================\n");

    display_put("Iterations: " ESC_BOLD "%zu" ESC_RESET, curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        display_put(" (out of: " ESC_BOLD "%zu" ESC_RESET ")", hfuzz->mutationsMax);
    }
    display_put(" in " ESC_BOLD "%ld" ESC_RESET " sec.\n", elapsed);

    display_put("Started: " ESC_BOLD "%s" ESC_RESET, asctime(localtime(&hfuzz->timeStart)));

    display_put("Input file/dir: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->inputFile);
    display_put("Fuzzed cmd: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->cmdline[0]);

    display_put("Fuzzing threads: " ESC_BOLD "%zu" ESC_RESET "\n", hfuzz->threadsMax);
    display_put("Execs per second: " ESC_BOLD "%zu" ESC_RESET " (avg: " ESC_BOLD "%zu" ESC_RESET
                ")\n", exec_per_sec, elapsed ? (curr_exec_cnt / elapsed) : 0);

    display_put("Crashes: " ESC_BOLD "%zu" ESC_RESET "\n",
                __sync_fetch_and_add(&hfuzz->crashesCnt, 0UL));
    display_put("Timeouts: " ESC_BOLD "%zu" ESC_RESET "\n",
                __sync_fetch_and_add(&hfuzz->timeoutedCnt, 0UL));

    display_put("Dynamic file size: " ESC_BOLD "%zu" ESC_RESET " (max: " ESC_BOLD "%zu" ESC_RESET
                ")\n", hfuzz->dynamicFileBestSz, hfuzz->maxFileSz);

    display_put("Coverage:\n");
    display_put("  max instructions taken:         " ESC_BOLD "%zu" ESC_RESET "\n",
                __sync_fetch_and_add(&hfuzz->branchBestCnt[0], 0UL));
    display_put("  max branches taken:             " ESC_BOLD "%zu" ESC_RESET "\n",
                __sync_fetch_and_add(&hfuzz->branchBestCnt[1], 0UL));
    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT) {
        display_put("  max individual PCs seen:        ");
    } else {
        display_put("  max unique branche pairs taken: ");
    }
    display_put(ESC_BOLD "%zu" ESC_RESET "\n", __sync_fetch_and_add(&hfuzz->branchBestCnt[2], 0UL));
    display_put("  max custom feedback:            " ESC_BOLD "%zu" ESC_RESET "\n",
                __sync_fetch_and_add(&hfuzz->branchBestCnt[3], 0UL));
    display_put("============================== LOGS ==============================\n");
}
