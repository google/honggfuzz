/*
 * 
 * honggfuzz - log messages -----------------------------------------
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
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static unsigned int log_minLevel;
static bool log_isStdioTTY;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const struct {
    const char *descr;
    const char *prefix;
} logLevels[] = {
    {
    "[FATAL]", "\033[1;31m"}, {
    "[ERROR]", "\033[1;35m"}, {
    "[WARNING]", "\033[1;34m"}, {
    "[INFO]", "\033[1m"}, {
    "[DEBUG]", "\033[0;37m"}
};

__attribute__ ((constructor))
void log_init(void
    )
{
    log_minLevel = l_INFO;
    if (isatty(STDOUT_FILENO) == 1) {
        log_isStdioTTY = true;
    } else {
        log_isStdioTTY = false;
    }
}

void log_setMinLevel(log_level_t dl)
{
    log_minLevel = dl;
}

void
log_msg(log_level_t dl,
        bool perr, const char *file, const char *func, int line, const char *fmt, ...
    )
{
    if (dl > log_minLevel)
        return;

    while (pthread_mutex_lock(&log_mutex)) ;

    char strerr[512];
    if (perr) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
    }

    struct tm tm;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&tv.tv_sec, &tm);

    if (log_isStdioTTY) {
        dprintf(STDOUT_FILENO, "%s", logLevels[dl].prefix);
    }

    if (log_minLevel >= l_DEBUG || !log_isStdioTTY) {
        dprintf
            (STDOUT_FILENO,
             "%s [%d] %d/%02d/%02d %02d:%02d:%02d (%s:%s %d) ",
             logLevels[dl].descr, getpid(), tm.tm_year + 1900,
             tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, file, func, line);
    } else {
        dprintf(STDOUT_FILENO, "%s ", logLevels[dl].descr);
    }

    va_list args;
    va_start(args, fmt);
    vdprintf(STDOUT_FILENO, fmt, args);
    va_end(args);

    if (perr) {
        dprintf(STDOUT_FILENO, ": %s", strerr);
    }

    if (log_isStdioTTY) {
        dprintf(STDOUT_FILENO, "\033[0m");
    }

    dprintf(STDOUT_FILENO, "\n");

    while (pthread_mutex_unlock(&log_mutex)) ;
}
