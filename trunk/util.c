/*
 * 
 * honggfuzz - utilities
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

#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "log.h"

static int util_urandomFD = -1;

uint32_t util_rndGet(uint32_t min, uint32_t max)
{
    if (util_urandomFD == -1) {
        if ((util_urandomFD = open("/dev/urandom", O_RDONLY)) == -1) {
            LOGMSG_P(l_FATAL, "Couldn't open /dev/urandom");
        }
    }

    unsigned short seed16v[3];

    if (read(util_urandomFD, seed16v, sizeof(seed16v)) != sizeof(seed16v)) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        seed16v[0] = ((unsigned short)tv.tv_usec);
        gettimeofday(&tv, NULL);
        seed16v[1] = ((unsigned short)tv.tv_usec);
        gettimeofday(&tv, NULL);
        seed16v[2] = ((unsigned short)tv.tv_usec);
    }

    seed48(seed16v);
    uint32_t rnd1 = (uint32_t) lrand48();
    uint32_t rnd2 = (uint32_t) lrand48();
    uint32_t rnd = (rnd1 << 16) ^ rnd2;

    if (min > max) {
        LOGMSG(l_FATAL, "min:%d > max:%d", min, max);
    }

    return ((rnd % (max - min + 1)) + min);
}

void util_ssnprintf(char *str, size_t size, const char *format, ...)
{
    char buf1[size];
    char buf2[size];

    strncpy(buf1, str, size);

    va_list args;
    va_start(args, format);
    vsnprintf(buf2, size, format, args);
    va_end(args);

    snprintf(str, size, "%s%s", buf1, buf2);
}

void util_getLocalTime(const char *fmt, char *buf, size_t len)
{
    struct tm ltime;

    time_t t = time(NULL);

    localtime_r(&t, &ltime);
    strftime(buf, len, fmt, &ltime);
}

void util_nullifyStdio(void)
{
    int fd = open("/dev/null", O_RDWR);

    if (fd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't open '/dev/null'");
        return;
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);

    if (fd > 2) {
        close(fd);
    }

    return;
}

bool util_redirectStdin(char *inputFile)
{
    int fd = open(inputFile, O_RDONLY);

    if (fd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't open '%s'", inputFile);
        return false;
    }

    dup2(fd, 0);
    if (fd != 0) {
        close(fd);
    }

    return true;
}

void util_recoverStdio(void)
{
    int fd = open("/dev/tty", O_RDWR);

    if (fd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't open '/dev/tty'");
        return;
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);

    if (fd > 2) {
        close(fd);
    }

    return;
}

/*
 * This is not a cryptographically secure hash 
 */
extern uint64_t util_hash(const char *buf, size_t len)
{
    uint64_t ret = 0;

    for (size_t i = 0; i < len; i++) {
        ret += buf[i];
        ret += (ret << 10);
        ret ^= (ret >> 6);
    }

    return ret;
}
