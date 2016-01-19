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
#include <inttypes.h>
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
#include "files.h"
#include "log.h"

#if defined(__builtin_bswap16)
#define SWAP16(x)   __builtin_bswap16(x)
#else
#define SWAP16(x)   ((x & 0xff) << 8) | ((x & 0xff00) >> 8)
#endif

#if defined(__builtin_bswap32)
#define SWAP32(x)   __builtin_bswap32(x)
#else
#define SWAP32(x)   ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24)
#endif

static int util_urandomFd = -1;
static __thread uint64_t rndX;
static __thread uint64_t rndIni = false;

uint64_t util_rndGet(uint64_t min, uint64_t max)
{
    if (min > max) {
        LOG_F("min:%" PRIu64 " > max:%" PRIu64, min, max);
    }

    if (util_urandomFd == -1) {
        if ((util_urandomFd = open("/dev/urandom", O_RDONLY)) == -1) {
            PLOG_F("Couldn't open /dev/urandom for writing");
        }
    }

    if (rndIni == false) {
        if (files_readFromFd(util_urandomFd, (uint8_t *) & rndX, sizeof(rndX)) == false) {
            PLOG_F("Couldn't read '%zu' bytes from /dev/urandom", sizeof(rndX));
        }
        rndIni = true;
    }

    /* MMIX LCG PRNG */
    static const uint64_t a = 6364136223846793005ULL;
    static const uint64_t c = 1442695040888963407ULL;

    rndX = (a * rndX + c);

    return ((rndX % (max - min + 1)) + min);
}

void util_rndBuf(uint8_t * buf, size_t sz)
{
    /* MMIX LCG PRNG */
    static const uint64_t a = 6364136223846793005ULL;
    static const uint64_t c = 1442695040888963407ULL;
    uint64_t x = util_rndGet(0, 1ULL << 62);

    for (size_t i = 0; i < sz; i++) {
        x = (a * x + c);
        buf[i] = (uint8_t) (x & 0xFF);
    }
}

/*
 * Function has variable length stack size, although already we know it's invoked
 * with relatively small sizes (max is _HF_REPORT_SIZE), thus safe to silent warning.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-larger-than="
int util_vssnprintf(char *str, size_t size, const char *format, va_list ap)
{
    char buf1[size];
    char buf2[size];

    strncpy(buf1, str, size);

    vsnprintf(buf2, size, format, ap);

    return snprintf(str, size, "%s%s", buf1, buf2);
}

int util_ssnprintf(char *str, size_t size, const char *format, ...)
{
    char buf1[size];
    char buf2[size];

    strncpy(buf1, str, size);

    va_list args;
    va_start(args, format);
    vsnprintf(buf2, size, format, args);
    va_end(args);

    return snprintf(str, size, "%s%s", buf1, buf2);
}

#pragma GCC diagnostic pop      /* EOF diagnostic ignored "-Wstack-usage=" */

void util_getLocalTime(const char *fmt, char *buf, size_t len, time_t tm)
{
    struct tm ltime;
    localtime_r(&tm, &ltime);
    if (strftime(buf, len, fmt, &ltime) < 1) {
        snprintf(buf, len, "[date fetch error]");
    }
}

void util_nullifyStdio(void)
{
    int fd = open("/dev/null", O_RDWR);

    if (fd == -1) {
        PLOG_E("Couldn't open '/dev/null'");
        return;
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);

    if (fd > 2) {
        close(fd);
    }
}

bool util_redirectStdin(char *inputFile)
{
    int fd = open(inputFile, O_RDONLY);

    if (fd == -1) {
        PLOG_E("Couldn't open '%s'", inputFile);
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
        PLOG_E("Couldn't open '/dev/tty'");
        return;
    }

    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);

    if (tcsetpgrp(fd, getpid()) == -1) {
        PLOG_W("tcsetpgrp(%d) failed", getpid());
    }

    if (fd > 2) {
        close(fd);
    }
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

extern int64_t util_timeNowMillis(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        PLOG_F("gettimeofday()");
    }

    return (((int64_t) tv.tv_sec * 1000LL) + ((int64_t) tv.tv_usec / 1000LL));
}

extern uint16_t util_ToFromBE16(uint16_t val)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return val;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return SWAP16(val);
#else
#error "Unknown ENDIANNESS"
#endif
}

extern uint16_t util_ToFromLE16(uint16_t val)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return SWAP16(val);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return val;
#else
#error "Unknown ENDIANNESS"
#endif
}

extern uint32_t util_ToFromBE32(uint32_t val)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return val;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return SWAP32(val);
#else
#error "Unknown ENDIANNESS"
#endif
}

extern uint32_t util_ToFromLE32(uint32_t val)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return SWAP32(val);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return val;
#else
#error "Unknown ENDIANNESS"
#endif
}

extern uint64_t util_getUINT32(const uint8_t * buf)
{
    const uint8_t b0 = buf[0], b1 = buf[1], b2 = buf[2], b3 = buf[3];

#if __BYTE_ORDER == __BIG_ENDIAN
    return (uint64_t) ((uint32_t) b0 << 24) | ((uint32_t) b1 << 16) | ((uint32_t) b2 << 8) |
        (uint32_t) b3;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (uint64_t) ((uint32_t) b3 << 24) | ((uint32_t) b2 << 16) | ((uint32_t) b1 << 8) |
        (uint32_t) b0;
#else
#error "Unknown ENDIANNESS"
#endif
}

extern uint64_t util_getUINT64(const uint8_t * buf)
{
    const uint8_t b0 = buf[0], b1 = buf[1], b2 = buf[2], b3 = buf[3],
        b4 = buf[4], b5 = buf[5], b6 = buf[6], b7 = buf[7];

#if __BYTE_ORDER == __BIG_ENDIAN
    return ((uint64_t) b0 << 56) | ((uint64_t) b1 << 48) | ((uint64_t) b2 << 40) |
        ((uint64_t) b3 << 32) | ((uint64_t) b4 << 24) | ((uint64_t) b5 << 16) |
        ((uint64_t) b6 << 8) | (uint64_t) b7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return ((uint64_t) b7 << 56) | ((uint64_t) b6 << 48) | ((uint64_t) b5 << 40) |
        ((uint64_t) b4 << 32) | ((uint64_t) b3 << 24) | ((uint64_t) b2 << 16) |
        ((uint64_t) b1 << 8) | (uint64_t) b0;
#else
#error "Unknown ENDIANNESS"
#endif
}

extern void MX_LOCK(pthread_mutex_t * mutex)
{
    if (pthread_mutex_lock(mutex)) {
        PLOG_F("pthread_mutex_lock(%p)", mutex);
    }
}

extern void MX_UNLOCK(pthread_mutex_t * mutex)
{
    if (pthread_mutex_unlock(mutex)) {
        PLOG_F("pthread_mutex_unlock(%p)", mutex);
    }
}

extern int64_t fastArray64Search(uint64_t * array, size_t arraySz, uint64_t key)
{
    size_t low = 0;
    size_t high = arraySz - 1;
    size_t mid;

    while (array[high] != array[low] && key >= array[low] && key <= array[high]) {
        mid = low + (key - array[low]) * ((high - low) / (array[high] - array[low]));

        if (array[mid] < key) {
            low = mid + 1;
        } else if (key < array[mid]) {
            high = mid - 1;
        } else {
            return mid;
        }
    }

    if (key == array[low]) {
        return low;
    } else {
        return -1;
    }
}
