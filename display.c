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
#include <inttypes.h>

#include "log.h"
#include "util.h"

#define ESC_CLEAR "\033[H\033[2J"
#define ESC_NAV(x,y) "\033["#x";"#y"H"
#define ESC_BOLD "\033[1m"
#define ESC_RESET "\033[0m"

static void display_put(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vdprintf(STDOUT_FILENO, fmt, args);
    va_end(args);
}

static void display_displayLocked(honggfuzz_t * hfuzz)
{
    unsigned long elapsed = (unsigned long)(time(NULL) - hfuzz->timeStart);

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
    static size_t prev_exec_cnt = 0UL;
    uintptr_t exec_per_sec = curr_exec_cnt - prev_exec_cnt;
    prev_exec_cnt = curr_exec_cnt;

    display_put("%s", ESC_CLEAR);
    display_put("==================================== STAT ====================================\n");

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
    display_put("Fuzzed cmd: '" ESC_BOLD "%s" ESC_RESET "'\n", hfuzz->cmdline_txt);
    if (hfuzz->linux.pid > 0) {
        display_put("Remote cmd [" ESC_BOLD "%d" ESC_RESET "]: '" ESC_BOLD "%s" ESC_RESET "'\n",
                    hfuzz->linux.pid, hfuzz->linux.pidCmd);
    }

    display_put("Fuzzing threads: " ESC_BOLD "%zu" ESC_RESET "\n", hfuzz->threadsMax);
    display_put("Execs (iterations) per second: " ESC_BOLD "%zu" ESC_RESET " (avg: " ESC_BOLD "%zu"
                ESC_RESET ")\n", exec_per_sec, elapsed ? (curr_exec_cnt / elapsed) : 0);

    /* If dry run, print also the input file count */
    if (hfuzz->origFlipRate == 0.0L && hfuzz->useVerifier) {
        display_put("Input Files: '" ESC_BOLD "%zu" ESC_RESET "'\n", hfuzz->fileCnt);
    }

    display_put("Crashes: " ESC_BOLD "%zu" ESC_RESET " (unique: " ESC_BOLD "%zu" ESC_RESET
                ", blacklist: " ESC_BOLD "%zu" ESC_RESET ", verified: " ESC_BOLD "%zu" ESC_RESET
                ")\n", ATOMIC_GET(hfuzz->crashesCnt),
                ATOMIC_GET(hfuzz->uniqueCrashesCnt),
                ATOMIC_GET(hfuzz->blCrashesCnt), ATOMIC_GET(hfuzz->verifiedCrashesCnt));
    display_put("Timeouts: " ESC_BOLD "%zu" ESC_RESET "\n", ATOMIC_GET(hfuzz->timeoutedCnt));

    /* Feedback data sources are enabled. Start with common headers. */
    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE || hfuzz->useSanCov) {
        display_put("Number of dynamic files: " ESC_BOLD "%zu" ESC_RESET "\n", hfuzz->dynfileqCnt);
        display_put("Coverage (max):\n");
    }

    /* HW perf specific counters */
    if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT) {
        display_put("  - cpu instructions:      " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->linux.hwCnts.cpuInstrCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT) {
        display_put("  - cpu branches:          " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->linux.hwCnts.cpuBranchCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK) {
        display_put("  - BTS unique blocks: " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE) {
        display_put("  - BTS unique edges:   " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_IPT_BLOCK) {
        display_put("  - PT unique blocks: " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->linux.hwCnts.bbCnt));
    }
    if (hfuzz->dynFileMethod & _HF_DYNFILE_CUSTOM) {
        display_put("  - custom counter:        " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->linux.hwCnts.customCnt));
    }

    /* Sanitizer coverage specific counters */
    if (hfuzz->useSanCov) {
        uint64_t hitBB = ATOMIC_GET(hfuzz->sanCovCnts.hitBBCnt);
        uint64_t totalBB = ATOMIC_GET(hfuzz->sanCovCnts.totalBBCnt);
        uint8_t covPer = totalBB ? ((hitBB * 100) / totalBB) : 0;
        display_put("  - total hit #bb:  " ESC_BOLD "%" PRIu64 ESC_RESET " (coverage %d%%)\n",
                    hitBB, covPer);
        display_put("  - total #dso:     " ESC_BOLD "%" PRIu64 ESC_RESET " (instrumented only)\n",
                    ATOMIC_GET(hfuzz->sanCovCnts.iDsoCnt));
        display_put("  - discovered #bb: " ESC_BOLD "%" PRIu64 ESC_RESET " (new from input seed)\n",
                    ATOMIC_GET(hfuzz->sanCovCnts.newBBCnt));
        display_put("  - crashes:        " ESC_BOLD "%" PRIu64 ESC_RESET "\n",
                    ATOMIC_GET(hfuzz->sanCovCnts.crashesCnt));
    }
    display_put("==================================== LOGS ====================================\n");
}

extern void display_display(honggfuzz_t * hfuzz)
{
    display_displayLocked(hfuzz);
}
