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

extern void display_Display(honggfuzz_t * hfuzz)
{
    size_t curr_exec_cnt = __sync_add_and_fetch(&hfuzz->mutationsCnt, 0UL);
    static size_t prev_exec_cnt = 0UL;

    uintptr_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    dprintf(OUTFD, "%s", ESC_CLEAR);

    dprintf(OUTFD, "Iterations: %zu", curr_exec_cnt);
    if (hfuzz->mutationsMax) {
        dprintf(OUTFD, " (out of: %zu)", hfuzz->mutationsMax);
    }
    dprintf(OUTFD, "\n");

    dprintf(OUTFD, "Input file/dir: '%s'\n", hfuzz->inputFile);
    dprintf(OUTFD, "Fuzzed cmd: '%s'\n", hfuzz->cmdline[0]);

    dprintf(OUTFD, "Fuzzing threads: %zu\n", hfuzz->threadsMax);
    dprintf(OUTFD, "Execs per second: %zu\n", exec_per_sec);

    dprintf(OUTFD, "Crashes: %zu\n", __sync_add_and_fetch(&hfuzz->crashesCnt, 0UL));

    dprintf(OUTFD, "Dynamic file size: %zu (max: %zu)\n", hfuzz->dynamicFileBestSz,
            hfuzz->maxFileSz);

    dprintf(OUTFD, "Coverage:\n");
    dprintf(OUTFD, "  max instructions taken:       %zu\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[0], 0UL));
    dprintf(OUTFD, "  max branches taken:           %zu\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[1], 0UL));
    if (hfuzz->dynFileMethod & _HF_DYNFILE_UNIQUE_BLOCK_COUNT) {
        dprintf(OUTFD, "  max individual PCs seen:      ");
    } else {
        dprintf(OUTFD, "  max individual branches seen: ");
    }
    dprintf(OUTFD, "%zu\n", __sync_add_and_fetch(&hfuzz->branchBestCnt[2], 0UL));
    dprintf(OUTFD, "  max custom feedback:          %zu\n",
            __sync_add_and_fetch(&hfuzz->branchBestCnt[3], 0UL));
}
