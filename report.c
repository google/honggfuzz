/*
 *
 * honggfuzz - reporting
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
#include "report.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "util.h"

static int reportFD = -1;

#if defined(_HF_ARCH_LINUX)
static void report_printdynFileMethod(honggfuzz_t * hfuzz)
{
    dprintf(reportFD, " dynFileMethod: ");
    if (hfuzz->dynFileMethod == 0)
        dprintf(reportFD, "NONE\n");
    else {
        if (hfuzz->dynFileMethod & _HF_DYNFILE_INSTR_COUNT)
            dprintf(reportFD, "INSTR_COUNT ");
        if (hfuzz->dynFileMethod & _HF_DYNFILE_BRANCH_COUNT)
            dprintf(reportFD, "BRANCH_COUNT ");
        if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_BLOCK)
            dprintf(reportFD, "BLOCK_COUNT ");
        if (hfuzz->dynFileMethod & _HF_DYNFILE_BTS_EDGE)
            dprintf(reportFD, "EDGE_COUNT ");

        dprintf(reportFD, "\n");
    }
}
#endif

static void report_printTargetCmd(honggfuzz_t * hfuzz)
{
    dprintf(reportFD, " fuzzTarget   : ");
    for (int x = 0; hfuzz->cmdline[x]; x++) {
        dprintf(reportFD, "%s ", hfuzz->cmdline[x]);
    }
    dprintf(reportFD, "\n");
}

void report_Report(honggfuzz_t * hfuzz, char *s)
{
    if (s == NULL || s[0] == '\0') {
        return;
    }

    MX_SCOPED_LOCK(&hfuzz->report_mutex);

    if (reportFD == -1) {
        char reportFName[PATH_MAX];
        if (hfuzz->reportFile == NULL) {
            snprintf(reportFName, sizeof(reportFName), "%s/%s", hfuzz->workDir, _HF_REPORT_FILE);
        } else {
            snprintf(reportFName, sizeof(reportFName), "%s", hfuzz->reportFile);
        }

        reportFD = open(reportFName, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (reportFD == -1) {
            PLOG_F("Couldn't open('%s') for writing", reportFName);
        }
    }

    char localtmstr[PATH_MAX];
    util_getLocalTime("%F.%H:%M:%S", localtmstr, sizeof(localtmstr), time(NULL));

    dprintf(reportFD,
            "=====================================================================\n"
            "TIME: %s\n"
            "=====================================================================\n"
            "FUZZER ARGS:\n"
            " flipRate     : %lf\n"
            " externalCmd  : %s\n"
            " fuzzStdin    : %s\n"
            " timeout      : %ld (sec)\n"
            " ignoreAddr   : %p\n"
            " memoryLimit  : %" PRIu64 " (MiB)\n"
            " targetPid    : %d\n"
            " targetCmd    : %s\n"
            " wordlistFile : %s\n",
            localtmstr,
            hfuzz->origFlipRate,
            hfuzz->externalCommand == NULL ? "NULL" : hfuzz->externalCommand,
            hfuzz->fuzzStdin ? "TRUE" : "FALSE",
            hfuzz->tmOut,
            hfuzz->linux.ignoreAddr,
            hfuzz->asLimit,
            hfuzz->linux.pid,
            hfuzz->linux.pidCmd, hfuzz->dictionaryFile == NULL ? "NULL" : hfuzz->dictionaryFile);

#if defined(_HF_ARCH_LINUX)
    report_printdynFileMethod(hfuzz);
#endif

    report_printTargetCmd(hfuzz);

    dprintf(reportFD,
            "%s" "=====================================================================\n", s);
}
