/*
 *
 * honggfuzz - core macros and helpers
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2017 by Google Inc. All Rights Reserved.
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

#ifndef _HF_COMMON_H_
#define _HF_COMMON_H_

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>

#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif

/* Go-style defer implementation */
#define __STRMERGE(a, b) a##b
#define _STRMERGE(a, b) __STRMERGE(a, b)
#ifdef __clang__
#if __has_extension(blocks)
static void __attribute__ ((unused)) __clang_cleanup_func(void (^*dfunc) (void))
{
    (*dfunc) ();
}

#define defer void (^_STRMERGE(__defer_f_, __COUNTER__))(void) __attribute__((cleanup(__clang_cleanup_func))) __attribute__((unused)) = ^
#else                           /* __has_extension(blocks) */
#define defer UNIMPLEMENTED - NO - SUPPORT - FOR - BLOCKS - IN - YOUR - CLANG - ENABLED
#endif                          /*  __has_extension(blocks) */
#else                           /* __clang */
#define __block
#define _DEFER(a, count)                                                                                               \
    auto void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)));                                  \
    int _STRMERGE(__defer_var_, count) __attribute__((cleanup(_STRMERGE(__defer_f_, count)))) __attribute__((unused)); \
    void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)))
#define defer _DEFER(a, __COUNTER__)
#endif                          /* __clang */

#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))

/* Memory barriers */
#define rmb() __asm__ __volatile__("" :: \
                                       : "memory")
#define wmb() __sync_synchronize()

#endif                          /* ifndef _HF_COMMON_H_ */
