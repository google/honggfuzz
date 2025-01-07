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

#ifndef _HF_COMMON_UTIL_H_
#define _HF_COMMON_UTIL_H_

#include <pthread.h>
#include <stdarg.h>
#ifdef __clang__
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/*
 * Go-style defer scoped implementation
 *
 * If compiled with clang, use: -fblocks -lBlocksRuntime
 *
 * Example of use:
 *
 * {
 *   int fd = open(fname, O_RDONLY);
 *   if (fd == -1) {
 *     error(....);
 *     return;
 *   }
 *   defer { close(fd); };
 *   ssize_t sz = read(fd, buf, sizeof(buf));
 *   ...
 *   ...
 * }
 *
 */

#define __STRMERGE(a, b) a##b
#define _STRMERGE(a, b)  __STRMERGE(a, b)
#ifdef __clang__
#if __has_extension(blocks)
static void __attribute__((unused)) __clang_cleanup_func(void (^*dfunc)(void)) {
    (*dfunc)();
}

#define defer                                                                                      \
    void (^_STRMERGE(__defer_f_, __COUNTER__))(void)                                               \
        __attribute__((cleanup(__clang_cleanup_func))) __attribute__((unused)) = ^

#else /* __has_extension(blocks) */
#define defer UNIMPLEMENTED - NO - SUPPORT - FOR - BLOCKS - IN - YOUR - CLANG - ENABLED
#endif /*  __has_extension(blocks) */
#else  /* !__clang__, e.g.: gcc */

#define __block
#define _DEFER(a, count)                                                                            \
    auto void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)));               \
    int       _STRMERGE(__defer_var_, count) __attribute__((cleanup(_STRMERGE(__defer_f_, count)))) \
    __attribute__((unused));                                                                        \
    void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)))
#define defer _DEFER(a, __COUNTER__)
#endif /* ifdef __clang__ */

/* Block scoped mutexes */
#define MX_SCOPED_LOCK(m)                                                                          \
    MX_LOCK(m);                                                                                    \
    defer {                                                                                        \
        MX_UNLOCK(m);                                                                              \
    }

#define MX_SCOPED_RWLOCK_READ(m)                                                                   \
    MX_RWLOCK_READ(m);                                                                             \
    defer {                                                                                        \
        MX_RWLOCK_UNLOCK(m);                                                                       \
    }
#define MX_SCOPED_RWLOCK_WRITE(m)                                                                  \
    MX_RWLOCK_WRITE(m);                                                                            \
    defer {                                                                                        \
        MX_RWLOCK_UNLOCK(m);                                                                       \
    }

#define HF_STR_LEN         8192
#define HF_STR_LEN_MINUS_1 8191

#define MX_LOCK(m)          util_mutexLock(m, __func__, __LINE__)
#define MX_UNLOCK(m)        util_mutexUnlock(m, __func__, __LINE__)
#define MX_RWLOCK_READ(m)   util_mutexRWLockRead(m, __func__, __LINE__)
#define MX_RWLOCK_WRITE(m)  util_mutexRWLockWrite(m, __func__, __LINE__)
#define MX_RWLOCK_UNLOCK(m) util_mutexRWUnlock(m, __func__, __LINE__)

#define LIKELY(cond)   __builtin_expect(!!(cond), true)
#define UNLIKELY(cond) __builtin_expect(!!(cond), false)

#if !defined(__has_builtin)
#define __has_builtin(b) 0
#endif

#if !__has_builtin(__builtin_memcpy_inline)
#define util_memcpyInline(x, y, s)                                                                 \
    do {                                                                                           \
        _Static_assert(                                                                            \
            __builtin_choose_expr(__builtin_constant_p(s), 1, 0), "len must be a constant");       \
        __builtin_memcpy(x, y, s);                                                                 \
    } while (0)
#else
#define util_memcpyInline(x, y, s) __builtin_memcpy_inline(x, y, s)
#endif

#if !__has_builtin(__builtin_memset_inline)
#define util_memsetInline(x, y, s)                                                                 \
    do {                                                                                           \
        _Static_assert(                                                                            \
            __builtin_choose_expr(__builtin_constant_p(s), 1, 0), "len must be a constant");       \
        __builtin_memset(x, y, s);                                                                 \
    } while (0)
#else
#define util_memsetInline(x, y, s) __builtin_memset_inline(x, y, s)
#endif

/* Atomics */
#define ATOMIC_GET(x)     __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define ATOMIC_SET(x, y)  __atomic_store_n(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_CLEAR(x)   __atomic_store_n(&(x), 0, __ATOMIC_RELAXED)
#define ATOMIC_XCHG(x, y) __atomic_exchange_n(&(x), y, __ATOMIC_RELAXED)

#define ATOMIC_PRE_INC(x)  __atomic_add_fetch(&(x), 1, __ATOMIC_RELAXED)
#define ATOMIC_POST_INC(x) __atomic_fetch_add(&(x), 1, __ATOMIC_RELAXED)

#define ATOMIC_PRE_DEC(x)  __atomic_sub_fetch(&(x), 1, __ATOMIC_RELAXED)
#define ATOMIC_POST_DEC(x) __atomic_fetch_sub(&(x), 1, __ATOMIC_RELAXED)

#define ATOMIC_PRE_ADD(x, y)  __atomic_add_fetch(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_POST_ADD(x, y) __atomic_fetch_add(&(x), y, __ATOMIC_RELAXED)

#define ATOMIC_PRE_SUB(x, y)  __atomic_sub_fetch(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_POST_SUB(x, y) __atomic_fetch_sub(&(x), y, __ATOMIC_RELAXED)

#define ATOMIC_PRE_AND(x, y)  __atomic_and_fetch(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_POST_AND(x, y) __atomic_fetch_and(&(x), y, __ATOMIC_RELAXED)

#define ATOMIC_PRE_OR(x, y)  __atomic_or_fetch(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_POST_OR(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)

__attribute__((always_inline)) static inline bool ATOMIC_BITMAP_SET(uint8_t* addr, size_t offset) {
    addr += (offset / 8);
    uint8_t mask = (1U << (offset % 8));

    if (ATOMIC_GET(*addr) & mask) {
        return true;
    }

#if defined(__x86_64__) || defined(__i386__)
    bool old;
    __asm__ __volatile__("lock bts %2, %0\n\t"
                         "sbb %1, %1\n\t"
        : "+m"(*addr), "=r"(old)
        : "Ir"(offset % 8));
    return old;
#else  /* defined(__x86_64__) || defined(__i386__) */
    return (ATOMIC_POST_OR(*addr, mask) & mask);
#endif /* defined(__x86_64__) || defined(__i386__) */
}

#define HF_MAX(x, y)    ((x > y) ? x : y)
#define HF_MIN(x, y)    ((x < y) ? x : y)
#define HF_CAP(v, x, y) HF_MAX(x, HF_MIN(y, v))
#define util_Log2(v)    ((sizeof(unsigned int) * 8) - __builtin_clz((unsigned int)v) - 1)

typedef enum {
    LHFC_ADDR_NOTFOUND = 0,
    LHFC_ADDR_RO       = 1,
    LHFC_ADDR_RW       = 2,
} lhfc_addr_t;

extern void util_ParentDeathSigIfAvail(int signo);
extern bool util_PinThreadToCPUs(uint32_t startcpu, uint32_t cpucnt);

extern void* util_Malloc(size_t sz) __attribute__((__malloc__));
extern void* util_Calloc(size_t sz) __attribute__((__malloc__));
extern void* util_AllocCopy(const uint8_t* ptr, size_t sz) __attribute__((__malloc__));
extern void* util_MMap(size_t sz) __attribute__((__malloc__));
extern void* util_Realloc(void* ptr, size_t sz);

extern uint64_t util_rndGet(uint64_t min, uint64_t max);
extern void     util_rndBuf(uint8_t* buf, size_t sz);
extern void     util_rndBufPrintable(uint8_t* buf, size_t sz);
extern uint64_t util_rnd64(void);
extern uint8_t  util_rndPrintable(void);

extern char* util_StrDup(const char* s) __attribute__((__malloc__));
extern int   util_ssnprintf(char* str, size_t size, const char* format, ...)
    __attribute__((format(printf, 3, 4)));
extern int         util_vssnprintf(char* str, size_t size, const char* format, va_list ap);
extern bool        util_strStartsWith(const char* str, const char* tofind);
extern bool        util_isANumber(const char* s);
extern size_t      util_decodeCString(char* s);
extern void        util_getLocalTime(const char* fmt, char* buf, size_t len, time_t tm);
extern const char* util_sigName(int signo);
extern void        util_turnToPrintable(uint8_t* buf, size_t sz);

extern void util_closeStdio(bool close_stdin, bool close_stdout, bool close_stderr);

extern lhfc_addr_t util_getProgAddr(const void* addr);
extern bool        util_32bitValInBinary(uint32_t v);
extern bool        util_64bitValInBinary(uint64_t v);

extern uint64_t util_hash(const char* buf, size_t len);
extern int64_t  fastArray64Search(uint64_t* array, size_t arraySz, uint64_t key);

extern int64_t util_timeNowUSecs(void);
extern void    util_sleepForMSec(uint64_t msec);

extern uint64_t util_getUINT32(const uint8_t* buf);
extern uint64_t util_getUINT64(const uint8_t* buf);

extern void util_mutexLock(pthread_mutex_t* mutex, const char* func, int line);
extern void util_mutexUnlock(pthread_mutex_t* mutex, const char* func, int line);

extern void util_mutexRWLockRead(pthread_rwlock_t* mutex, const char* func, int line);
extern void util_mutexRWLockWrite(pthread_rwlock_t* mutex, const char* func, int line);
extern void util_mutexRWUnlock(pthread_rwlock_t* mutex, const char* func, int line);

extern uint64_t util_CRC64(const uint8_t* buf, size_t len);
extern uint64_t util_CRC64Rev(const uint8_t* buf, size_t len);

#endif /* ifndef _HF_COMMON_UTIL_H_ */
