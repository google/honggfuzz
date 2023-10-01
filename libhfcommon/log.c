/*

   nsjail - logging
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

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

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "util.h"

#if defined(_HF_ARCH_LINUX)
#include <sys/syscall.h>
#define __hf_pid() (pid_t) syscall(__NR_gettid)
#elif defined(_HF_ARCH_NETBSD)
#include <lwp.h>
#define __hf_pid() _lwp_self()
#else
#define __hf_pid() getpid()
#endif

static int             hf_log_fd        = STDERR_FILENO;
static bool            hf_log_fd_isatty = false;
enum llevel_t          hf_log_level     = INFO;
static pthread_mutex_t log_mutex        = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor)) static void log_init(void) {
    hf_log_fd = fcntl(hf_log_fd, F_DUPFD_CLOEXEC, 0);
    if (hf_log_fd == -1) {
        hf_log_fd = STDERR_FILENO;
    }
    hf_log_fd_isatty = isatty(hf_log_fd);

    if (getenv("NO_COLOR")) {
        hf_log_fd_isatty = false;
    }
}

/*
 * Log to stderr by default. Use a dup()d fd, because in the future we'll associate the
 * connection socket with fd (0, 1, 2).
 */
void logInitLogFile(const char* logfile, int fd, enum llevel_t ll) {
    hf_log_level = ll;

    if (logfile) {
        hf_log_fd = TEMP_FAILURE_RETRY(open(logfile, O_CREAT | O_RDWR | O_TRUNC, 0640));
        if (hf_log_fd == -1) {
            hf_log_fd = STDERR_FILENO;
            PLOG_E("Couldn't open logfile open('%s')", logfile);
        }
    }
    if (fd != -1) {
        hf_log_fd = fd;
    }

    hf_log_fd_isatty = (isatty(hf_log_fd) == 1 ? true : false);

    if (getenv("NO_COLOR")) {
        hf_log_fd_isatty = false;
    }
}

void logLog(enum llevel_t ll, const char* fn, int ln, bool perr, const char* fmt, ...) {
    int  saved_errno = errno;
    char strerr[512];
    if (perr) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(saved_errno));
    }
    struct ll_t {
        const char* descr;
        const char* prefix;
        const bool  print_funcline;
        const bool  print_time;
    };
    static const struct ll_t logLevels[] = {
        {"F", "\033[7;35m", true, true},
        {"E", "\033[1;31m", true, true},
        {"W", "\033[0;33m", true, true},
        {"I", "\033[1m", false, false},
        {"D", "\033[0;4m", true, true},
        {"HR", "\033[0m", false, false},
        {"HB", "\033[1m", false, false},
    };

    time_t    ltstamp = time(NULL);
    struct tm utctime;
    localtime_r(&ltstamp, &utctime);
    char timestr[32];
    if (strftime(timestr, sizeof(timestr) - 1, "%FT%T%z", &utctime) == 0) {
        timestr[0] = '\0';
    }

    /* Start printing logs */
    {
        MX_LOCK(&log_mutex);

        if (hf_log_fd_isatty) {
            dprintf(hf_log_fd, "%s", logLevels[ll].prefix);
        }
        if (logLevels[ll].print_time) {
            dprintf(hf_log_fd, "[%s][%s][%d] ", timestr, logLevels[ll].descr, __hf_pid());
        }
        if (logLevels[ll].print_funcline) {
            dprintf(hf_log_fd, "%s():%d ", fn, ln);
        }

        va_list args;
        va_start(args, fmt);
        vdprintf(hf_log_fd, fmt, args);
        va_end(args);

        if (perr) {
            dprintf(hf_log_fd, ": %s", strerr);
        }
        if (hf_log_fd_isatty) {
            dprintf(hf_log_fd, "\033[0m");
        }
        dprintf(hf_log_fd, "\n");

        MX_UNLOCK(&log_mutex);
    }
    /* End printing logs */

    errno = saved_errno;
    if (ll == FATAL) {
        exit(EXIT_FAILURE);
    }
}

void logStop(int sig) {
    LOG_I("Server stops due to fatal signal (%d) caught. Exiting", sig);
}

void logRedirectLogFD(int fd) {
    hf_log_fd        = fd;
    hf_log_fd_isatty = isatty(hf_log_fd);
}

void logDirectlyToFD(const char* msg) {
    dprintf(hf_log_fd, "%s", msg);
}

pthread_mutex_t* logMutexGet(void) {
    return &log_mutex;
}

void logMutexReset(void) {
    pthread_mutex_init(&log_mutex, NULL);
}

bool logIsTTY(void) {
    return hf_log_fd_isatty;
}

int logFd(void) {
    return hf_log_fd;
}

enum llevel_t logGetLevel(void) {
    return hf_log_level;
}

#if defined(__sun)
void dprintf(int fd, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
}

int vdprintf(int fd, const char* fmt, va_list ap) {
#if defined(__LP64__)
    // The data is priv on 64 bits but size is 128
    struct FILEPRIV {
        int          _pad[8];
        int          _magic;
        unsigned int _flag;
        char         fill[88];
    };
    struct FILEPRIV fp = {
#else
    FILE fp = {
#endif
        ._magic = (unsigned char)fd,
        ._flag  = _IOREAD,
    };
    return vfprintf((FILE*)&fp, fmt, ap);
}
#endif
