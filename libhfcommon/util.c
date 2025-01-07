/*
 *
 * honggfuzz - utilities
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
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

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/param.h>
#if !defined(_HF_ARCH_DARWIN) && !defined(__CYGWIN__) && !defined(__APPLE__)
#include <link.h>
#endif /* !defined(_HF_ARCH_DARWIN) && !defined(__CYGWIN__) */
#include <math.h>
#include <pthread.h>
#if defined(_HF_ARCH_LINUX)
#include <sched.h>
#include <sys/syscall.h>
#endif /* defined(_HF_ARCH_LINUX) */
#if defined(__FreeBSD__)
#include <pthread_np.h>
#include <sys/cpuset.h>
#endif /* defined(__FreeBSD__) */
#if defined(_HF_ARCH_NETBSD)
#include <sched.h>
#endif /* defined(_HF_ARCH_NETBSD) */
#if defined(__DragonFly__)
#include <pthread.h>
#include <pthread_np.h>
#endif /* defined(__DragonFly__) */
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#if defined(_HF_ARCH_LINUX)
#include <sys/prctl.h>
#endif /* defined(_HF_ARCH_LINUX) */
#if defined(__FreeBSD__)
#include <sys/procctl.h>
#endif /* defined(__FreeBSD__) */
#if defined(__sun)
#include <sys/pset.h>
#endif /* defined(__sun) */
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "files.h"
#include "log.h"

void util_ParentDeathSigIfAvail(int signo HF_ATTR_UNUSED) {
#if defined(__FreeBSD__)
    if (procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &signo) == -1) {
        PLOG_W("procctl(P_PID, PROC_PDEATHSIG_CTL, signo=%d (%s))", signo, util_sigName(signo));
    }
#endif /* defined(__FreeBSD__) */
#if defined(_HF_ARCH_LINUX)
    if (prctl(PR_SET_PDEATHSIG, (unsigned long)signo, 0UL, 0UL, 0UL) == -1) {
        PLOG_W("prctl(PR_SET_PDEATHSIG, signo=%d (%s))", signo, util_sigName(signo));
    }
#endif /* defined(_HF_ARCH_LINUX) */
}

bool util_PinThreadToCPUs(uint32_t threadno, uint32_t cpucnt) {
    if (cpucnt == 0) {
        return true;
    }

    long r = sysconf(_SC_NPROCESSORS_ONLN);
    if (r == -1) {
        PLOG_W("sysconf(_SC_NPROCESSORS_ONLN) failed");
        return false;
    }
    uint32_t num_cpus = (uint32_t)r;

    if (cpucnt > num_cpus) {
        LOG_W("Requested CPUs (%" PRIu32 ") > available CPUs (%" PRIu32 ") for thread #%" PRIu32,
            cpucnt, num_cpus, threadno);
        return false;
    }

    uint32_t start_cpu = (threadno * cpucnt) % num_cpus;
    uint32_t end_cpu   = (start_cpu + cpucnt - 1U) % num_cpus;
    LOG_D("Setting CPU affinity for the current thread #%" PRIu32 " to %" PRIu32
          " consecutive CPUs, (start:%" PRIu32 "-end:%" PRIu32 ") total_cpus:%" PRIu32,
        threadno, cpucnt, start_cpu, end_cpu, num_cpus);

#if defined(_HF_ARCH_LINUX) || defined(__FreeBSD__) || defined(_HF_ARCH_NETBSD) ||                 \
    defined(__DragonFly__)
#if defined(_HF_ARCH_LINUX) || defined(__DragonFly__)
    cpu_set_t set;
    CPU_ZERO(&set);
#endif /* defined(_HF_ARCH_LINUX) */
#if defined(__FreeBSD__)
    cpuset_t set;
    CPU_ZERO(&set);
#endif /* defined(__FreeBSD__) || defined(_HF_ARCH_NETBSD) */
#if defined(_HF_ARCH_NETBSD)
    cpuset_t* set = cpuset_create();
    defer {
        cpuset_destroy(set);
    };
#endif /* defined(_HF_ARCH_NETBSD) */

    for (uint32_t i = 0; i < cpucnt; i++) {
#if defined(_HF_ARCH_NETBSD)
        cpuset_set((start_cpu + i) % num_cpus, set);
#else  /* defined((_HF_ARCH_NETBSD) */
        CPU_SET((start_cpu + i) % num_cpus, &set);
#endif /* defined((_HF_ARCH_NETBSD) */
    }
#if defined(__ANDROID__)
    if (sched_setaffinity(getpid(), sizeof(set), &set) != 0) {
#elif defined(_HF_ARCH_NETBSD)
    if (pthread_setaffinity_np(pthread_self(), cpuset_size(set), set) != 0) {
#else  /* defined((_HF_ARCH_NETBSD) */
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
#endif /* defined((_HF_ARCH_NETBSD) */
        PLOG_W("pthread_setaffinity_np(thread=#%" PRIu32 "), failed", threadno);
        return false;
    }
    return true;
#elif defined(__sun)
    psetid_t set;
    pid_t    p;
    bool     ret = true;

    if (pset_create(&set) != 0) {
        PLOG_W("pset_create failed");
        return false;
    }

    for (uint32_t i = 0; i < cpucnt; i++) {
        if (pset_assign(set, ((start_cpu + i) % num_cpus), NULL) != 0) {
            PLOG_W("pset_assign(%" PRIu32 "), failed", i);
            pset_destroy(set);    // TODO: defer mechanism not yet supported
            return false;
        }
    }

    p = getpid();

    if (pset_bind(set, P_PID, p, NULL) != 0) {
        PLOG_W("pset_bind(%ld) failed", (long)p);
        ret = false;
    }

    pset_destroy(set);
    return ret;
#endif /* defined(_HF_ARCH_LINUX) || defined(__FreeBSD__) || defined(_HF_ARCH_NETBSD) */
    LOG_W("util_PinThreadToCPUs() not implemented for the current architecture");
    return false;
}

void* util_Malloc(size_t sz) {
    void* p = malloc(sz);
    if (p == NULL) {
        LOG_F("malloc(size='%zu')", sz);
    }
    return p;
}

void* util_Calloc(size_t sz) {
    void* p = util_Malloc(sz);
    memset(p, '\0', sz);
    return p;
}

void* util_AllocCopy(const uint8_t* ptr, size_t sz) {
    void* p = util_Malloc(sz);
    memcpy(p, ptr, sz);
    return p;
}

void* util_Realloc(void* ptr, size_t sz) {
    void* ret = realloc(ptr, sz);
    if (ret == NULL) {
        PLOG_W("realloc(%p, %zu)", ptr, sz);
        free(ptr);
        return NULL;
    }
    return ret;
}

void* util_MMap(size_t sz) {
    void* p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        LOG_F("mmap(size='%zu')", sz);
    }
    return p;
}

char* util_StrDup(const char* s) {
    char* ret = strdup(s);
    if (ret == NULL) {
        LOG_F("strdup(size=%zu)", strlen(s));
    }
    return ret;
}

static __thread bool     rndThreadOnce = false;
static __thread uint64_t rndState[4];

static void util_rndInitThread(void) {
    __attribute__((weak)) void arc4random_buf(void* buf, size_t nbytes);
    if (arc4random_buf) {
        arc4random_buf((void*)rndState, sizeof(rndState));
        return;
    }

    int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        PLOG_F("Couldn't open /dev/urandom for reading");
    }
    if (files_readFromFd(fd, (uint8_t*)rndState, sizeof(rndState)) != sizeof(rndState)) {
        PLOG_F("Couldn't read '%zu' bytes from /dev/urandom", sizeof(rndState));
    }
    close(fd);
}

static inline uint64_t __attribute__((const)) util_RotL(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

/*
 * xoroshiro256++ by David Blackman and Sebastiano Vigna
 */
static inline uint64_t util_InternalRnd64(void) {
    if (!rndThreadOnce) {
        rndThreadOnce = true;
        util_rndInitThread();
    }
    const uint64_t result = util_RotL(rndState[0] + rndState[3], 23) + rndState[0];

    const uint64_t t = rndState[1] << 17;
    rndState[2] ^= rndState[0];
    rndState[3] ^= rndState[1];
    rndState[1] ^= rndState[2];
    rndState[0] ^= rndState[3];
    rndState[2] ^= t;
    rndState[3] = util_RotL(rndState[3], 45);

    return result;
}

uint64_t util_rnd64(void) {
    return util_InternalRnd64();
}

uint64_t util_rndGet(uint64_t min, uint64_t max) {
    if (min > max) {
        LOG_F("min:%" PRIu64 " > max:%" PRIu64, min, max);
    }

    if (max == UINT64_MAX) {
        return util_rnd64();
    }

    return ((util_rnd64() % (max - min + 1)) + min);
}

/* Generate random printable ASCII */
uint8_t util_rndPrintable(void) {
    return util_rndGet(32, 126);
}

/* Turn one byte to a printable ASCII */
void util_turnToPrintable(uint8_t* buf, size_t sz) {
    for (size_t i = 0; i < sz; i++) {
        buf[i] = buf[i] % 95 + 32;
    }
}

void util_rndBufPrintable(uint8_t* buf, size_t sz) {
    for (size_t i = 0; i < sz; i++) {
        buf[i] = util_rndPrintable();
    }
}

void util_rndBuf(uint8_t* buf, size_t sz) {
    if (sz == 0) {
        return;
    }
    for (size_t i = 0; i < sz; i++) {
        buf[i] = (uint8_t)(util_InternalRnd64() >> 40);
    }
}

int util_vssnprintf(char* str, size_t size, const char* format, va_list ap) {
    size_t len = strlen(str);
    if (len >= size) {
        return len;
    }

    size_t left = size - len;
    return vsnprintf(&str[len], left, format, ap);
}

int util_ssnprintf(char* str, size_t size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = util_vssnprintf(str, size, format, args);
    va_end(args);

    return ret;
}

bool util_strStartsWith(const char* str, const char* tofind) {
    if (strncmp(str, tofind, strlen(tofind)) == 0) {
        return true;
    }
    return false;
}

void util_getLocalTime(const char* fmt, char* buf, size_t len, time_t tm) {
    struct tm ltime;
    localtime_r(&tm, &ltime);
    if (strftime(buf, len, fmt, &ltime) < 1) {
        snprintf(buf, len, "[date fetch error]");
    }
}

void util_closeStdio(bool close_stdin, bool close_stdout, bool close_stderr) {
    int fd = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR));
    if (fd == -1) {
        PLOG_E("Couldn't open '/dev/null'");
        return;
    }

    if (close_stdin) {
        TEMP_FAILURE_RETRY(dup2(fd, STDIN_FILENO));
    }
    if (close_stdout) {
        TEMP_FAILURE_RETRY(dup2(fd, STDOUT_FILENO));
    }
    if (close_stderr) {
        TEMP_FAILURE_RETRY(dup2(fd, STDERR_FILENO));
    }

    if (fd > STDERR_FILENO) {
        close(fd);
    }
}

/*
 * This is not a cryptographically secure hash
 */
uint64_t util_hash(const char* buf, size_t len) {
    uint64_t ret = 0;

    for (size_t i = 0; i < len; i++) {
        ret += buf[i];
        ret += (ret << 10);
        ret ^= (ret >> 6);
    }

    return ret;
}

int64_t util_timeNowUSecs(void) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        PLOG_F("gettimeofday()");
    }

    return (((int64_t)tv.tv_sec * 1000000) + (int64_t)tv.tv_usec);
}

void util_sleepForMSec(uint64_t msec) {
    if (msec == 0) {
        return;
    }
    struct timespec ts = {
        .tv_sec  = msec / 1000U,
        .tv_nsec = (msec % 1000U) * 1000000U,
    };
    TEMP_FAILURE_RETRY(nanosleep(&ts, &ts));
}

uint64_t util_getUINT32(const uint8_t* buf) {
    uint32_t r;
    util_memcpyInline(&r, buf, sizeof(r));
    return (uint64_t)r;
}

uint64_t util_getUINT64(const uint8_t* buf) {
    uint64_t r;
    util_memcpyInline(&r, buf, sizeof(r));
    return r;
}

void util_mutexLock(pthread_mutex_t* mutex, const char* func, int line) {
    if (pthread_mutex_lock(mutex)) {
        PLOG_F("%s():%d pthread_mutex_lock(%p)", func, line, (void*)mutex);
    }
}

void util_mutexUnlock(pthread_mutex_t* mutex, const char* func, int line) {
    if (pthread_mutex_unlock(mutex)) {
        PLOG_F("%s():%d pthread_mutex_unlock(%p)", func, line, (void*)mutex);
    }
}

void util_mutexRWLockRead(pthread_rwlock_t* mutex, const char* func, int line) {
    if (pthread_rwlock_rdlock(mutex)) {
        PLOG_F("%s():%d pthread_rwlock_rdlock(%p)", func, line, (void*)mutex);
    }
}

void util_mutexRWLockWrite(pthread_rwlock_t* mutex, const char* func, int line) {
    if (pthread_rwlock_wrlock(mutex)) {
        PLOG_F("%s():%d pthread_rwlock_wrlock(%p)", func, line, (void*)mutex);
    }
}

void util_mutexRWUnlock(pthread_rwlock_t* mutex, const char* func, int line) {
    if (pthread_rwlock_unlock(mutex)) {
        PLOG_F("%s():%d pthread_rwlock_unlock(%p)", func, line, (void*)mutex);
    }
}

int64_t fastArray64Search(uint64_t* array, size_t arraySz, uint64_t key) {
    size_t low  = 0;
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

bool util_isANumber(const char* s) {
    if (!isdigit((unsigned char)s[0])) {
        return false;
    }
    for (int i = 0; s[i]; s++) {
        if (!isdigit((unsigned char)s[i]) && s[i] != 'x') {
            return false;
        }
    }
    return true;
}

size_t util_decodeCString(char* s) {
    size_t o = 0;
    for (size_t i = 0; s[i] != '\0' && s[i] != '"'; i++, o++) {
        switch (s[i]) {
        case '\\': {
            i++;
            if (!s[i]) {
                continue;
            }
            switch (s[i]) {
            case 'a':
                s[o] = '\a';
                break;
            case 'r':
                s[o] = '\r';
                break;
            case 'n':
                s[o] = '\n';
                break;
            case 't':
                s[o] = '\t';
                break;
            case '0':
                s[o] = '\0';
                break;
            case 'x': {
                if (s[i + 1] && s[i + 2]) {
                    char hex[] = {s[i + 1], s[i + 2], 0};
                    s[o]       = strtoul(hex, NULL, 16);
                    i += 2;
                } else {
                    s[o] = s[i];
                }
                break;
            }
            default:
                s[o] = s[i];
                break;
            }
            break;
        }
        default: {
            s[o] = s[i];
            break;
        }
        }
    }
    s[o] = '\0';
    return o;
}

/* ISO 3309 CRC-64 Poly table */
static const uint64_t util_CRC64ISOPoly[] = {
    0x0000000000000000ULL,
    0x01B0000000000000ULL,
    0x0360000000000000ULL,
    0x02D0000000000000ULL,
    0x06C0000000000000ULL,
    0x0770000000000000ULL,
    0x05A0000000000000ULL,
    0x0410000000000000ULL,
    0x0D80000000000000ULL,
    0x0C30000000000000ULL,
    0x0EE0000000000000ULL,
    0x0F50000000000000ULL,
    0x0B40000000000000ULL,
    0x0AF0000000000000ULL,
    0x0820000000000000ULL,
    0x0990000000000000ULL,
    0x1B00000000000000ULL,
    0x1AB0000000000000ULL,
    0x1860000000000000ULL,
    0x19D0000000000000ULL,
    0x1DC0000000000000ULL,
    0x1C70000000000000ULL,
    0x1EA0000000000000ULL,
    0x1F10000000000000ULL,
    0x1680000000000000ULL,
    0x1730000000000000ULL,
    0x15E0000000000000ULL,
    0x1450000000000000ULL,
    0x1040000000000000ULL,
    0x11F0000000000000ULL,
    0x1320000000000000ULL,
    0x1290000000000000ULL,
    0x3600000000000000ULL,
    0x37B0000000000000ULL,
    0x3560000000000000ULL,
    0x34D0000000000000ULL,
    0x30C0000000000000ULL,
    0x3170000000000000ULL,
    0x33A0000000000000ULL,
    0x3210000000000000ULL,
    0x3B80000000000000ULL,
    0x3A30000000000000ULL,
    0x38E0000000000000ULL,
    0x3950000000000000ULL,
    0x3D40000000000000ULL,
    0x3CF0000000000000ULL,
    0x3E20000000000000ULL,
    0x3F90000000000000ULL,
    0x2D00000000000000ULL,
    0x2CB0000000000000ULL,
    0x2E60000000000000ULL,
    0x2FD0000000000000ULL,
    0x2BC0000000000000ULL,
    0x2A70000000000000ULL,
    0x28A0000000000000ULL,
    0x2910000000000000ULL,
    0x2080000000000000ULL,
    0x2130000000000000ULL,
    0x23E0000000000000ULL,
    0x2250000000000000ULL,
    0x2640000000000000ULL,
    0x27F0000000000000ULL,
    0x2520000000000000ULL,
    0x2490000000000000ULL,
    0x6C00000000000000ULL,
    0x6DB0000000000000ULL,
    0x6F60000000000000ULL,
    0x6ED0000000000000ULL,
    0x6AC0000000000000ULL,
    0x6B70000000000000ULL,
    0x69A0000000000000ULL,
    0x6810000000000000ULL,
    0x6180000000000000ULL,
    0x6030000000000000ULL,
    0x62E0000000000000ULL,
    0x6350000000000000ULL,
    0x6740000000000000ULL,
    0x66F0000000000000ULL,
    0x6420000000000000ULL,
    0x6590000000000000ULL,
    0x7700000000000000ULL,
    0x76B0000000000000ULL,
    0x7460000000000000ULL,
    0x75D0000000000000ULL,
    0x71C0000000000000ULL,
    0x7070000000000000ULL,
    0x72A0000000000000ULL,
    0x7310000000000000ULL,
    0x7A80000000000000ULL,
    0x7B30000000000000ULL,
    0x79E0000000000000ULL,
    0x7850000000000000ULL,
    0x7C40000000000000ULL,
    0x7DF0000000000000ULL,
    0x7F20000000000000ULL,
    0x7E90000000000000ULL,
    0x5A00000000000000ULL,
    0x5BB0000000000000ULL,
    0x5960000000000000ULL,
    0x58D0000000000000ULL,
    0x5CC0000000000000ULL,
    0x5D70000000000000ULL,
    0x5FA0000000000000ULL,
    0x5E10000000000000ULL,
    0x5780000000000000ULL,
    0x5630000000000000ULL,
    0x54E0000000000000ULL,
    0x5550000000000000ULL,
    0x5140000000000000ULL,
    0x50F0000000000000ULL,
    0x5220000000000000ULL,
    0x5390000000000000ULL,
    0x4100000000000000ULL,
    0x40B0000000000000ULL,
    0x4260000000000000ULL,
    0x43D0000000000000ULL,
    0x47C0000000000000ULL,
    0x4670000000000000ULL,
    0x44A0000000000000ULL,
    0x4510000000000000ULL,
    0x4C80000000000000ULL,
    0x4D30000000000000ULL,
    0x4FE0000000000000ULL,
    0x4E50000000000000ULL,
    0x4A40000000000000ULL,
    0x4BF0000000000000ULL,
    0x4920000000000000ULL,
    0x4890000000000000ULL,
    0xD800000000000000ULL,
    0xD9B0000000000000ULL,
    0xDB60000000000000ULL,
    0xDAD0000000000000ULL,
    0xDEC0000000000000ULL,
    0xDF70000000000000ULL,
    0xDDA0000000000000ULL,
    0xDC10000000000000ULL,
    0xD580000000000000ULL,
    0xD430000000000000ULL,
    0xD6E0000000000000ULL,
    0xD750000000000000ULL,
    0xD340000000000000ULL,
    0xD2F0000000000000ULL,
    0xD020000000000000ULL,
    0xD190000000000000ULL,
    0xC300000000000000ULL,
    0xC2B0000000000000ULL,
    0xC060000000000000ULL,
    0xC1D0000000000000ULL,
    0xC5C0000000000000ULL,
    0xC470000000000000ULL,
    0xC6A0000000000000ULL,
    0xC710000000000000ULL,
    0xCE80000000000000ULL,
    0xCF30000000000000ULL,
    0xCDE0000000000000ULL,
    0xCC50000000000000ULL,
    0xC840000000000000ULL,
    0xC9F0000000000000ULL,
    0xCB20000000000000ULL,
    0xCA90000000000000ULL,
    0xEE00000000000000ULL,
    0xEFB0000000000000ULL,
    0xED60000000000000ULL,
    0xECD0000000000000ULL,
    0xE8C0000000000000ULL,
    0xE970000000000000ULL,
    0xEBA0000000000000ULL,
    0xEA10000000000000ULL,
    0xE380000000000000ULL,
    0xE230000000000000ULL,
    0xE0E0000000000000ULL,
    0xE150000000000000ULL,
    0xE540000000000000ULL,
    0xE4F0000000000000ULL,
    0xE620000000000000ULL,
    0xE790000000000000ULL,
    0xF500000000000000ULL,
    0xF4B0000000000000ULL,
    0xF660000000000000ULL,
    0xF7D0000000000000ULL,
    0xF3C0000000000000ULL,
    0xF270000000000000ULL,
    0xF0A0000000000000ULL,
    0xF110000000000000ULL,
    0xF880000000000000ULL,
    0xF930000000000000ULL,
    0xFBE0000000000000ULL,
    0xFA50000000000000ULL,
    0xFE40000000000000ULL,
    0xFFF0000000000000ULL,
    0xFD20000000000000ULL,
    0xFC90000000000000ULL,
    0xB400000000000000ULL,
    0xB5B0000000000000ULL,
    0xB760000000000000ULL,
    0xB6D0000000000000ULL,
    0xB2C0000000000000ULL,
    0xB370000000000000ULL,
    0xB1A0000000000000ULL,
    0xB010000000000000ULL,
    0xB980000000000000ULL,
    0xB830000000000000ULL,
    0xBAE0000000000000ULL,
    0xBB50000000000000ULL,
    0xBF40000000000000ULL,
    0xBEF0000000000000ULL,
    0xBC20000000000000ULL,
    0xBD90000000000000ULL,
    0xAF00000000000000ULL,
    0xAEB0000000000000ULL,
    0xAC60000000000000ULL,
    0xADD0000000000000ULL,
    0xA9C0000000000000ULL,
    0xA870000000000000ULL,
    0xAAA0000000000000ULL,
    0xAB10000000000000ULL,
    0xA280000000000000ULL,
    0xA330000000000000ULL,
    0xA1E0000000000000ULL,
    0xA050000000000000ULL,
    0xA440000000000000ULL,
    0xA5F0000000000000ULL,
    0xA720000000000000ULL,
    0xA690000000000000ULL,
    0x8200000000000000ULL,
    0x83B0000000000000ULL,
    0x8160000000000000ULL,
    0x80D0000000000000ULL,
    0x84C0000000000000ULL,
    0x8570000000000000ULL,
    0x87A0000000000000ULL,
    0x8610000000000000ULL,
    0x8F80000000000000ULL,
    0x8E30000000000000ULL,
    0x8CE0000000000000ULL,
    0x8D50000000000000ULL,
    0x8940000000000000ULL,
    0x88F0000000000000ULL,
    0x8A20000000000000ULL,
    0x8B90000000000000ULL,
    0x9900000000000000ULL,
    0x98B0000000000000ULL,
    0x9A60000000000000ULL,
    0x9BD0000000000000ULL,
    0x9FC0000000000000ULL,
    0x9E70000000000000ULL,
    0x9CA0000000000000ULL,
    0x9D10000000000000ULL,
    0x9480000000000000ULL,
    0x9530000000000000ULL,
    0x97E0000000000000ULL,
    0x9650000000000000ULL,
    0x9240000000000000ULL,
    0x93F0000000000000ULL,
    0x9120000000000000ULL,
    0x9090000000000000ULL,
};

uint64_t util_CRC64(const uint8_t* buf, size_t len) {
    uint64_t res = 0ULL;

    for (size_t i = 0; i < len; i++) {
        res = util_CRC64ISOPoly[(uint8_t)res ^ buf[i]] ^ (res >> 8);
    }

    return res;
}

uint64_t util_CRC64Rev(const uint8_t* buf, size_t len) {
    uint64_t res = 0ULL;

    for (ssize_t i = (ssize_t)len - 1; i >= 0; i--) {
        res = util_CRC64ISOPoly[(uint8_t)res ^ buf[i]] ^ (res >> 8);
    }

    return res;
}

static const struct {
    const int         signo;
    const char* const signame;
} sigNames[] = {
#if defined(SIGHUP)
    {SIGHUP, "SIGHUP"},
#endif
#if defined(SIGINT)
    {SIGINT, "SIGINT"},
#endif
#if defined(SIGQUIT)
    {SIGQUIT, "SIGQUIT"},
#endif
#if defined(SIGILL)
    {SIGILL, "SIGILL"},
#endif
#if defined(SIGTRAP)
    {SIGTRAP, "SIGTRAP"},
#endif
#if defined(SIGABRT)
    {SIGABRT, "SIGABRT"},
#endif
#if defined(SIGIOT)
    {SIGIOT, "SIGIOT"},
#endif
#if defined(SIGBUS)
    {SIGBUS, "SIGBUS"},
#endif
#if defined(SIGFPE)
    {SIGFPE, "SIGFPE"},
#endif
#if defined(SIGKILL)
    {SIGKILL, "SIGKILL"},
#endif
#if defined(SIGUSR1)
    {SIGUSR1, "SIGUSR1"},
#endif
#if defined(SIGSEGV)
    {SIGSEGV, "SIGSEGV"},
#endif
#if defined(SIGUSR2)
    {SIGUSR2, "SIGUSR2"},
#endif
#if defined(SIGPIPE)
    {SIGPIPE, "SIGPIPE"},
#endif
#if defined(SIGALRM)
    {SIGALRM, "SIGALRM"},
#endif
#if defined(SIGTERM)
    {SIGTERM, "SIGTERM"},
#endif
#if defined(SIGSTKFLT)
    {SIGSTKFLT, "SIGSTKFLT"},
#endif
#if defined(SIGCHLD)
    {SIGCHLD, "SIGCHLD"},
#endif
#if defined(SIGCONT)
    {SIGCONT, "SIGCONT"},
#endif
#if defined(SIGSTOP)
    {SIGSTOP, "SIGSTOP"},
#endif
#if defined(SIGTSTP)
    {SIGTSTP, "SIGTSTP"},
#endif
#if defined(SIGTTIN)
    {SIGTTIN, "SIGTTIN"},
#endif
#if defined(SIGTTOU)
    {SIGTTOU, "SIGTTOU"},
#endif
#if defined(SIGURG)
    {SIGURG, "SIGURG"},
#endif
#if defined(SIGXCPU)
    {SIGXCPU, "SIGXCPU"},
#endif
#if defined(SIGXFSZ)
    {SIGXFSZ, "SIGXFSZ"},
#endif
#if defined(SIGVTALRM)
    {SIGVTALRM, "SIGVTALRM"},
#endif
#if defined(SIGPROF)
    {SIGPROF, "SIGPROF"},
#endif
#if defined(SIGWINCH)
    {SIGWINCH, "SIGWINCH"},
#endif
#if defined(SIGIO)
    {SIGIO, "SIGIO"},
#endif
#if defined(SIGPOLL)
    {SIGPOLL, "SIGPOLL"},
#endif
#if defined(SIGLOST)
    {SIGLOST, "SIGLOST"},
#endif
#if defined(SIGPWR)
    {SIGPWR, "SIGPWR"},
#endif
#if defined(SIGSYS)
    {SIGSYS, "SIGSYS"},
#endif
#if defined(SIGTHR)
    {SIGTHR, "SIGTHR"},
#endif
#if defined(SIGEMT)
    {SIGEMT, "SIGEMT"},
#endif
#if defined(SIGINFO)
    {SIGINFO, "SIGINFO"},
#endif
#if defined(SIGLIBRT)
    {SIGLIBRT, "SIGLIBRT"},
#endif
};

const char* util_sigName(int signo) {
    static __thread char signame[32];
    for (size_t i = 0; i < ARRAYSIZE(sigNames); i++) {
        if (signo == sigNames[i].signo) {
            return sigNames[i].signame;
        }
    }
#if defined(SIGRTMIN) && defined(SIGRTMAX)
    if (signo >= SIGRTMIN && signo <= SIGRTMAX) {
        snprintf(signame, sizeof(signame), "SIG%d-RTMIN+%d", signo, signo - SIGRTMIN);
        return signame;
    }
#endif /* defined(SIGRTMIN) && defined(SIGRTMAX) */
    snprintf(signame, sizeof(signame), "UNKNOWN-%d", signo);
    return signame;
}

/*
 * Should we use the more complex algorithm of collecting (once) known 32/64-bit values in RO
 * sections and then search through them, or shall we simply search through the process' VM?
 *
 * 'false' for now, in order to estimate effectiveness of both methods.
 */
#if !defined(_HF_COMMON_BIN_COLLECT_VALS)
#define _HF_COMMON_BIN_COLLECT_VALS false
#endif /* !defined(_HF_COMMON_BIN_COLLECT_VALS) */

#if !defined(_HF_ARCH_DARWIN) && !defined(__CYGWIN__) && !defined(__APPLE__)
static int addrStatic_cb(struct dl_phdr_info* info, size_t size HF_ATTR_UNUSED, void* data) {
    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_LOAD) {
            continue;
        }
        uintptr_t addr_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        uintptr_t addr_end =
            addr_start + HF_MIN(info->dlpi_phdr[i].p_memsz, info->dlpi_phdr[i].p_filesz);
        if (((uintptr_t)data >= addr_start) && ((uintptr_t)data < addr_end)) {
            if ((info->dlpi_phdr[i].p_flags & PF_W) == 0) {
                return LHFC_ADDR_RO;
            } else {
                return LHFC_ADDR_RW;
            }
        }
    }
    return LHFC_ADDR_NOTFOUND;
}

lhfc_addr_t util_getProgAddr(const void* addr) {
    return (lhfc_addr_t)dl_iterate_phdr(addrStatic_cb, (void*)addr);
}
static uint64_t* values64InBinary      = NULL;
static size_t    values64InBinary_size = 0;
static size_t    values64InBinary_cap  = 0;

static uint32_t* values32InBinary      = NULL;
static size_t    values32InBinary_size = 0;
static size_t    values32InBinary_cap  = 0;

static int cmp_u64(const void* pa, const void* pb) {
    uint64_t a = *(uint64_t*)pa;
    uint64_t b = *(uint64_t*)pb;
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

static int cmp_u32(const void* pa, const void* pb) {
    uint32_t a = *(uint32_t*)pa;
    uint32_t b = *(uint32_t*)pb;
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

static int check32_cb(struct dl_phdr_info* info, void* data, unsigned elf_flags) {
    const uint32_t v = *(const uint32_t*)data;

    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        /* Look only in the actual binary, and not in libraries */
        if (info->dlpi_name[0] != '\0') {
            continue;
        }
        if (info->dlpi_phdr[i].p_type != PT_LOAD) {
            continue;
        }
        if ((info->dlpi_phdr[i].p_flags & elf_flags) != elf_flags) {
            continue;
        }
        uint32_t* start = (uint32_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        uint32_t* end =
            (uint32_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr +
                        HF_MIN(info->dlpi_phdr[i].p_memsz, info->dlpi_phdr[i].p_filesz));
        /* Assume that the 32bit value looked for is also 32bit aligned */
        for (; start < end; start++) {
            if (*start == v) {
                return 1;
            }
        }
    }
    return 0;
}

static int check64_cb(struct dl_phdr_info* info, void* data, unsigned elf_flags) {
    const uint64_t v = *(const uint64_t*)data;

    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        /* Look only in the actual binary, and not in libraries */
        if (info->dlpi_name[0] != '\0') {
            continue;
        }
        if (info->dlpi_phdr[i].p_type != PT_LOAD) {
            continue;
        }
        if ((info->dlpi_phdr[i].p_flags & elf_flags) != elf_flags) {
            continue;
        }
        uint64_t* start = (uint64_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        uint64_t* end =
            (uint64_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr +
                        HF_MIN(info->dlpi_phdr[i].p_memsz, info->dlpi_phdr[i].p_filesz));
        /* Assume that the 64bit value looked for is also 64bit aligned */
        for (; start < end; start++) {
            if (*start == v) {
                return 1;
            }
        }
    }
    return 0;
}

static int check32_cb_r(struct dl_phdr_info* info, size_t size HF_ATTR_UNUSED, void* data) {
    return check32_cb(info, data, PF_R);
}

static int check64_cb_r(struct dl_phdr_info* info, size_t size HF_ATTR_UNUSED, void* data) {
    return check64_cb(info, data, PF_R);
}

static int check32_cb_w(struct dl_phdr_info* info, size_t size HF_ATTR_UNUSED, void* data) {
    return check32_cb(info, data, PF_W);
}

static int check64_cb_w(struct dl_phdr_info* info, size_t size HF_ATTR_UNUSED, void* data) {
    return check64_cb(info, data, PF_W);
}

static int collectValuesInBinary_cb(
    struct dl_phdr_info* info, size_t size HF_ATTR_UNUSED, void* data HF_ATTR_UNUSED) {
    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        /* Look only in the actual binary, and not in libraries */
        if (info->dlpi_name[0] != '\0') {
            continue;
        }
        if (info->dlpi_phdr[i].p_type != PT_LOAD) {
            continue;
        }
        // collect values from readonly segments
        if ((!(info->dlpi_phdr[i].p_flags & PF_R)) || (info->dlpi_phdr[i].p_flags & PF_W)) {
            continue;
        }
        uint32_t* start_32 = (uint32_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        uint32_t* end_32 =
            (uint32_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr +
                        HF_MIN(info->dlpi_phdr[i].p_memsz, info->dlpi_phdr[i].p_filesz));

        for (; start_32 < end_32; start_32++) {
            if (*start_32 == 0 || *start_32 == (uint32_t)-1) continue;
            // make enough capcity
            if (values32InBinary_size > values32InBinary_cap) {
                LOG_F("32values size(%zu) > cap(%zu)", values32InBinary_size, values32InBinary_cap);
            }
            if (values32InBinary_size == values32InBinary_cap) {
                if (values32InBinary_cap == 0) {
                    values32InBinary_cap = 1024;
                }
                values32InBinary_cap *= 2;
                values32InBinary =
                    util_Realloc(values32InBinary, values32InBinary_cap * sizeof(uint32_t));
            }
            values32InBinary[values32InBinary_size++] = *start_32;
        }

        uint64_t* start_64 = (uint64_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        uint64_t* end_64 =
            (uint64_t*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr +
                        HF_MIN(info->dlpi_phdr[i].p_memsz, info->dlpi_phdr[i].p_filesz));

        for (; start_64 < end_64; start_64++) {
            if (*start_64 == 0 || *start_64 == (uint64_t)-1) continue;
            // make enough capcity
            if (values64InBinary_size > values64InBinary_cap) {
                LOG_F("64values size(%zu) > cap(%zu)", values64InBinary_size, values64InBinary_cap);
            }
            if (values64InBinary_size == values64InBinary_cap) {
                if (values64InBinary_cap == 0) {
                    values64InBinary_cap = 1024;
                }
                values64InBinary_cap *= 2;
                values64InBinary =
                    util_Realloc(values64InBinary, values64InBinary_cap * sizeof(uint64_t));
            }
            values64InBinary[values64InBinary_size++] = *start_64;
        }
    }

    return 0;
}

static void collectValuesInBinary() {
    // collect values
    dl_iterate_phdr(collectValuesInBinary_cb, NULL);

    // sort values
    qsort(values32InBinary, values32InBinary_size, sizeof(uint32_t), cmp_u32);
    qsort(values64InBinary, values64InBinary_size, sizeof(uint64_t), cmp_u64);

    // remove duplicated values
    if (values32InBinary_size) {
        uint32_t previous_value = values32InBinary[0];
        size_t   new_size       = 1;
        for (size_t i = 1; i < values32InBinary_size; i++) {
            uint32_t current_value = values32InBinary[i];
            if (current_value != previous_value) {
                // a new non-duplicated value
                values32InBinary[new_size++] = current_value;
            }
            previous_value = current_value;
        }
        values32InBinary_size = new_size;
    }
    if (values64InBinary_size) {
        uint64_t previous_value = values64InBinary[0];
        size_t   new_size       = 1;
        for (size_t i = 1; i < values64InBinary_size; i++) {
            uint64_t current_value = values64InBinary[i];
            if (current_value != previous_value) {
                // a new non-duplicated value
                values64InBinary[new_size++] = current_value;
            }
            previous_value = current_value;
        }
        values64InBinary_size = new_size;
    }

    // reduce memory
    values32InBinary_cap = values32InBinary_size;
    values32InBinary     = util_Realloc(values32InBinary, values32InBinary_cap * sizeof(uint32_t));
    values64InBinary_cap = values64InBinary_size;
    values64InBinary     = util_Realloc(values64InBinary, values64InBinary_cap * sizeof(uint64_t));
}

static pthread_once_t collectValuesInBinary_InitOnce = PTHREAD_ONCE_INIT;

bool util_32bitValInBinary(uint32_t v) {
    if (!(_HF_COMMON_BIN_COLLECT_VALS)) {
        return (dl_iterate_phdr(check32_cb_r, &v) == 1);
    }

    pthread_once(&collectValuesInBinary_InitOnce, collectValuesInBinary);
    // check if it in read-only values
    if (values32InBinary_size != 0) {
        size_t l = 0, r = values32InBinary_size - 1;
        // binary search
        while (l != r) {
            size_t mid = (l + r) / 2;
            if (values32InBinary[mid] < v) {
                l = mid + 1;
            } else {
                r = mid;
            }
        }
        if (values32InBinary[l] == v) return true;
    }
    // check if it's in writable values
    return (dl_iterate_phdr(check32_cb_w, &v) == 1);
}

bool util_64bitValInBinary(uint64_t v) {
    if (!(_HF_COMMON_BIN_COLLECT_VALS)) {
        return (dl_iterate_phdr(check64_cb_r, &v) == 1);
    }

    pthread_once(&collectValuesInBinary_InitOnce, collectValuesInBinary);
    // check if it in read-only values
    if (values64InBinary_size != 0) {
        size_t l = 0, r = values64InBinary_size - 1;
        // binary search
        while (l != r) {
            size_t mid = (l + r) / 2;
            if (values64InBinary[mid] < v) {
                l = mid + 1;
            } else {
                r = mid;
            }
        }
        if (values64InBinary[l] == v) return true;
    }
    // check if it's in writable values
    return (dl_iterate_phdr(check64_cb_w, &v) == 1);
}
#else  /* !defined(_HF_ARCH_DARWIN) && !defined(__CYGWIN__) */
/* Darwin doesn't use ELF file format for binaries, so dl_iterate_phdr() cannot be used there */
lhfc_addr_t util_getProgAddr(const void* addr HF_ATTR_UNUSED) {
    return LHFC_ADDR_NOTFOUND;
}
bool util_32bitValInBinary(uint32_t v HF_ATTR_UNUSED) {
    return false;
}
bool util_64bitValInBinary(uint64_t v HF_ATTR_UNUSED) {
    return false;
}
#endif /* !defined(_HF_ARCH_DARWIN) && !defined(__CYGWIN__) */
