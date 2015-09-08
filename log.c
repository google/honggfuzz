/*
 *
 * honggfuzz - log messages
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
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

static unsigned int log_minLevel = l_INFO;
static bool log_isStdioTTY;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/*  *INDENT-OFF* */
static const struct {
    const char *descr;
    const char *prefix;
} logLevels[] = {
    { "[FATAL]",   "\033[1;41m" },
    { "[ERROR]",   "\033[1;31m" },
    { "[WARNING]", "\033[1;35m" },
    { "[INFO]",    "\033[1m"    },
    { "[DEBUG]",   "\033[0;37m" },
};
/*  *INDENT-ON* */

__attribute__ ((constructor))
void log_init(void)
{
    log_isStdioTTY = (isatty(STDOUT_FILENO) == 1);
}

void log_setMinLevel(log_level_t dl)
{
    log_minLevel = dl;
}

void log_mutexLock(void)
{
    while (pthread_mutex_lock(&log_mutex)) ;
}

void log_mutexUnLock(void)
{
    while (pthread_mutex_unlock(&log_mutex)) ;
}

void log_msg(log_level_t dl, bool perr, const char *file, const char *func, int line,
             const char *fmt, ...)
{
    char msg[8192] = { "\0" };

    if (dl > log_minLevel) {
        if (dl == l_FATAL) {
            exit(EXIT_FAILURE);
        }
        return;
    }

    char strerr[512];
    if (perr) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
    }

    struct tm tm;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&tv.tv_sec, &tm);

    if (log_isStdioTTY == true) {
        util_ssnprintf(msg, sizeof(msg), "%s", logLevels[dl].prefix);
    }
#if defined(_HF_ARCH_LINUX)
#include <unistd.h>
#include <sys/syscall.h>
    pid_t pid = (pid_t) syscall(__NR_gettid);
#else                           /* defined(_HF_ARCH_LINUX) */
    pid_t pid = getpid();
#endif                          /* defined(_HF_ARCH_LINUX) */

    if (log_minLevel != l_INFO || !log_isStdioTTY) {
        util_ssnprintf(msg, sizeof(msg), "%s [%d] %d/%02d/%02d %02d:%02d:%02d (%s:%s %d) ",
                       logLevels[dl].descr, pid, tm.tm_year + 1900,
                       tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, file, func,
                       line);
    } else {
        util_ssnprintf(msg, sizeof(msg), "%s ", logLevels[dl].descr);
    }

    va_list args;
    va_start(args, fmt);
    util_vssnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (perr) {
        util_ssnprintf(msg, sizeof(msg), ": %s", strerr);
    }

    if (log_isStdioTTY == true) {
        util_ssnprintf(msg, sizeof(msg), "\033[0m");
    }

    util_ssnprintf(msg, sizeof(msg), "\n");

    log_mutexLock();
    if (write(STDOUT_FILENO, msg, strlen(msg)) == -1) {
    }
    log_mutexUnLock();

    if (dl == l_FATAL) {
        exit(EXIT_FAILURE);
    }
}
