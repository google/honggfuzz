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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdarg.h>
#include <stdint.h>

extern uint64_t util_rndGet(uint64_t min, uint64_t max);

extern void util_rndBuf(uint8_t * buf, size_t sz);

extern int util_ssnprintf(char *str, size_t size, const char *format, ...);

extern int util_vssnprintf(char *str, size_t size, const char *format, va_list ap);

extern void util_getLocalTime(const char *fmt, char *buf, size_t len, time_t tm);

extern void util_nullifyStdio(void);

extern bool util_redirectStdin(char *inputFile);

extern void util_recoverStdio(void);

extern uint64_t util_hash(const char *buf, size_t len);

extern int64_t util_timeNowMillis(void);

extern uint16_t util_ToFromBE16(uint16_t val);
extern uint16_t util_ToFromLE16(uint16_t val);
extern uint32_t util_ToFromBE32(uint32_t val);
extern uint32_t util_ToFromLE32(uint32_t val);

extern void MX_LOCK(pthread_mutex_t * mutex);
extern void MX_UNLOCK(pthread_mutex_t * mutex);

#endif
