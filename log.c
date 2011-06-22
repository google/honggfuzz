/*

   honggfuzz - log messages
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>

   Copyright 2010 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#include "common.h"
#include "log.h"

int log_minLevel;

__attribute__ ((constructor))
void log_init(void
    )
{
    log_minLevel = l_INFO;
}

void log_setMinLevel(log_level_t dl)
{
    log_minLevel = dl;
}

void log_msg(log_level_t dl,
             bool perr, const char *file, const char *func, int line, const char *fmt, ...
    )
{
    struct {
        char *descr;
        char *prefix;
    } logLevels[] = {
        {
        "[FATAL]", "\033[1;31m"}, {
        "[ERROR]", "\033[1;35m"}, {
        "[WARNING]", "\033[1;34m"}, {
        "[INFO]", "\033[1m"}, {
        "[DEBUG]", "\033[0;37m"}
    };

    char strerr[512];
    if (perr) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
    }

    if (dl > log_minLevel)
        return;

    struct tm tm;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&tv.tv_sec, &tm);

    printf("%s", logLevels[dl].prefix);

    if (log_minLevel >= l_DEBUG) {
        printf
            ("%s %d/%02d/%02d %02d:%02d:%02d (%s:%s %d) ",
             logLevels[dl].descr, tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, file, func, line);
    } else {
        printf("%s ", logLevels[dl].descr);
    }

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    if (perr) {
        printf(": %s", strerr);
    }

    printf("\033[0m\n");
    fflush(stdout);
}
