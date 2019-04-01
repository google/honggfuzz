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

#define MX_LOCK(m) util_mutexLock(m, __func__, __LINE__)
#define MX_UNLOCK(m) util_mutexUnlock(m, __func__, __LINE__)
#define MX_RWLOCK_READ(m) util_mutexRWLockRead(m, __func__, __LINE__)
#define MX_RWLOCK_WRITE(m) util_mutexRWLockWrite(m, __func__, __LINE__)
#define MX_RWLOCK_UNLOCK(m) util_mutexRWUnlock(m, __func__, __LINE__)

/* Atomics */
#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_SEQ_CST)
#define ATOMIC_CLEAR(x) __atomic_store_n(&(x), 0, __ATOMIC_SEQ_CST)
#define ATOMIC_XCHG(x, y) __atomic_exchange_n(&(x), y, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_INC(x) __atomic_add_fetch(&(x), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_INC(x) __atomic_fetch_add(&(x), 1, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_DEC(x) __atomic_sub_fetch(&(x), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_DEC(x) __atomic_fetch_sub(&(x), 1, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_ADD(x, y) __atomic_add_fetch(&(x), y, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_ADD(x, y) __atomic_fetch_add(&(x), y, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_SUB(x, y) __atomic_sub_fetch(&(x), y, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_SUB(x, y) __atomic_fetch_sub(&(x), y, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_AND(x, y) __atomic_and_fetch(&(x), y, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_AND(x, y) __atomic_fetch_and(&(x), y, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_OR(x, y) __atomic_or_fetch(&(x), y, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_OR(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_SEQ_CST)

#define ATOMIC_PRE_INC_RELAXED(x) __atomic_add_fetch(&(x), 1, __ATOMIC_RELAXED)
#define ATOMIC_POST_OR_RELAXED(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)

__attribute__((always_inline)) static inline uint8_t ATOMIC_BTS(uint8_t* addr, size_t offset) {
    uint8_t oldbit;
    addr += (offset / 8);
    oldbit = ATOMIC_POST_OR_RELAXED(*addr, ((uint8_t)1U << (offset % 8)));
    return oldbit;
}

extern void* util_Malloc(size_t sz);

extern void* util_Calloc(size_t sz);

extern void* util_MMap(size_t sz);

extern void* util_Realloc(void* ptr, size_t sz);

extern char* util_StrDup(const char* s);

extern uint64_t util_rndGet(uint64_t min, uint64_t max);

extern void util_rndBuf(uint8_t* buf, size_t sz);

extern void util_rndBufPrintable(uint8_t* buf, size_t sz);

extern uint64_t util_rnd64(void);

extern uint8_t util_rndPrintable(void);

extern void util_turnToPrintable(uint8_t* buf, size_t sz);

extern int util_ssnprintf(char* str, size_t size, const char* format, ...)
    __attribute__((format(printf, 3, 4)));

extern int util_vssnprintf(char* str, size_t size, const char* format, va_list ap);

extern bool util_strStartsWith(const char* str, const char* tofind);

extern void util_getLocalTime(const char* fmt, char* buf, size_t len, time_t tm);

extern void util_closeStdio(bool close_stdin, bool close_stdout, bool close_stderr);

extern uint64_t util_hash(const char* buf, size_t len);

extern int64_t util_timeNowMillis(void);
extern void util_sleepForMSec(uint64_t msec);

extern uint64_t util_getUINT32(const uint8_t* buf);
extern uint64_t util_getUINT64(const uint8_t* buf);

extern void util_mutexLock(pthread_mutex_t* mutex, const char* func, int line);
extern void util_mutexUnlock(pthread_mutex_t* mutex, const char* func, int line);

extern void util_mutexRWLockRead(pthread_rwlock_t* mutex, const char* func, int line);
extern void util_mutexRWLockWrite(pthread_rwlock_t* mutex, const char* func, int line);
extern void util_mutexRWUnlock(pthread_rwlock_t* mutex, const char* func, int line);

extern int64_t fastArray64Search(uint64_t* array, size_t arraySz, uint64_t key);

extern bool util_isANumber(const char* s);

extern size_t util_decodeCString(char* s);

extern uint64_t util_CRC64(const uint8_t* buf, size_t len);
extern uint64_t util_CRC64Rev(const uint8_t* buf, size_t len);

#endif /* ifndef _HF_COMMON_UTIL_H_ */
