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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "files.h"
#include "log.h"

static int reportFD = -1;

void report_Report(honggfuzz_t * hfuzz, char *s)
{
    if (s[0] == '\0') {
        return;
    }

    if (reportFD == -1) {
        reportFD = open(hfuzz->reportFile, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    if (reportFD == -1) {
        LOGMSG_P(l_FATAL, "Couldn't open('%s') for writing", hfuzz->reportFile);
    }

    if (files_writeStrToFd(reportFD, s) == false) {
        LOGMSG(l_ERROR, "Couldn't append a log to the report file");
    }

    return;
}
