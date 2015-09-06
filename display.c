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
#include <stdio.h>
#include <unistd.h>

#include "log.h"

#define OUTFD STDOUT_FILENO
#if !defined(_HF_ARCH_LINUX)
#define dprintf(x, fmt, ...) fprintf(stdout, fmt, __VA_ARGS__)
#endif

#define ESC_CLEAR "\033[H\033[2J"
#define ESC_NAV(x,y) "\033["#x";"#y"H"
#define ESC_BOLD "\033[1m"
#define ESC_RESET "\033[0m"

extern void display_Display(honggfuzz_t * hfuzz)
{
    unsigned long elapsed = (unsigned long)(time(NULL) - hfuzz->timeStart);
    size_t curr_exec_cnt = __sync_add_and_fetch(&hfuzz->mutationsCnt, 0UL);
    static size_t prev_exec_cnt = 0UL;
    uintptr_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    dprintf(OUTFD, "%s", ESC_CLEAR);

    dprintf(OUTFD, "Iterations: " ESC_BOLD "%zu" ESC_RESET, curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        dprintf(OUTFD, " (out of: " ESC_BOLD "%zu" ESC_RESET ")", hfuzz->mutationsMax);
    }
    dprintf(OUTFD, " in " ESC_BOLD "%ld" ESC_RESET " sec.\n", elapsed);

    dprintf(OUTFD, "Started: " ESC_BOLD "%s" ESC_RESET, asctime(localtime(&hfuzz->timeStart)));

    dprintf(OUTFD, "Input file/dir: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->inputFile);
    dprintf(OUTFD, "Fuzzed cmd: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->cmdline[0]);

    dprintf(OUTFD, "Fuzzing threads: " ESC_BOLD "%zu" ESC_RESET "\n", hfuzz->threadsMax);
    dprintf(OUTFD,
            "Execs per second: " ESC_BOLD "%zu" ESC_RESET " (avg: " ESC_BOLD "%zu" ESC_RESET ")\n",
            exec_per_sec, curr_exec_cnt / elapsed);

    dprintf(OUTFD, "Crashes: " ESC_BOLD "%zu" ESC_RESET "\n",
            __sync_add_and_fetch(&hfuzz->crashesCnt, 0UL));
    dprintf(OUTFD, "Timeouts: " ESC_BOLD "%zu" ESC_RESET "\n",
            __sync_add_and_fetch(&hfuzz->timeoutedCnt, 0UL));

    dprintf(OUTFD,
            "Dynamic file size: " ESC_BOLD "%zu" ESC_RESET " (max: " ESC_BOLD "%zu" ESC_RESET ")\n",
            hfuzz->dynamicFileBestSz, hfuzz->maxFileSz);

    dprintf(OUTFD, "Coverage:\n");
    dprintf(OUTFD, "  max instructions taken:       " ESC_BOLD "%zu" ESC_RESET "\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[0], 0UL));
    dprintf(OUTFD, "  max branches taken:           " ESC_BOLD "%zu" ESC_RESET "\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[1], 0UL));
    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT) {
        dprintf(OUTFD, "  max individual PCs seen:      ");
    } else {
        dprintf(OUTFD, "  max individual branches seen: ");
    }
    dprintf(OUTFD, ESC_BOLD "%zu" ESC_RESET "\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[2], 0UL));
    dprintf(OUTFD, "  max custom feedback:          " ESC_BOLD "%zu" ESC_RESET "\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[3], 0UL));
}
