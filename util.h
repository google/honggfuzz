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

#ifndef _HF_UTIL_H_
#define _HF_UTIL_H_

#include <stdarg.h>
#include <stdint.h>

#define MX_LOCK(m) util_mutexLock(m, __func__, __LINE__)
#define MX_UNLOCK(m) util_mutexUnlock(m, __func__, __LINE__)
#define MX_SCOPED_LOCK(m) MX_LOCK(m); defer { MX_UNLOCK(m); }

extern void *util_Malloc(size_t sz);

extern void *util_Calloc(size_t sz);

extern void *util_MMap(size_t sz);

extern char *util_StrDup(const char *s);

extern uint64_t util_rndGet(uint64_t min, uint64_t max);

extern void util_rndBuf(uint8_t * buf, size_t sz);

extern int util_ssnprintf(char *str, size_t size, const char *format, ...);

extern int util_vssnprintf(char *str, size_t size, const char *format, va_list ap);

extern void util_getLocalTime(const char *fmt, char *buf, size_t len, time_t tm);

extern void util_nullifyStdio(void);

extern bool util_redirectStdin(const char *inputFile);

extern uint64_t util_hash(const char *buf, size_t len);

extern int64_t util_timeNowMillis(void);

extern uint64_t util_getUINT32(const uint8_t * buf);
extern uint64_t util_getUINT64(const uint8_t * buf);

extern void util_mutexLock(pthread_mutex_t * mutex, const char *func, int line);
extern void util_mutexUnlock(pthread_mutex_t * mutex, const char *func, int line);

extern int64_t fastArray64Search(uint64_t * array, size_t arraySz, uint64_t key);

extern bool util_isANumber(const char *s);

#endif
