/*
 *
 * honggfuzz - compiler instrumentation
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

#ifndef _HF_LIBHFUZZ_INSTRUMENT_H_
#define _HF_LIBHFUZZ_INSTRUMENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern void     instrument8BitCountersCount(void);
extern void     instrumentResetLocalCovFeedback(void);
extern unsigned instrumentThreadNo(void);
extern bool     instrumentUpdateCmpMap(uintptr_t addr, uint32_t v);
extern void     instrumentClearNewCov();
extern void     instrumentAddConstMem(const void* m, size_t len, bool check_if_ro);
extern void     instrumentAddConstStr(const char* s);
extern void     instrumentAddConstStrN(const char* s, size_t n);
extern bool     instrumentConstAvail();

#endif /* ifdef _HF_LIBHFUZZ_INSTRUMENT_H_ */
