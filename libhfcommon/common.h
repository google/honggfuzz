/*
 *
 * honggfuzz - core macros and helpers
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

#ifndef _HF_COMMON_COMMON_H_
#define _HF_COMMON_COMMON_H_

#include <stdlib.h>
#include <unistd.h>

/* Stringify */
#define HF__XSTR(x) #x
#define HF_XSTR(x) HF__XSTR(x)

#define HF_ATTR_UNUSED __attribute__((unused))

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))
#endif /* ifndef ARRAYSIZE */

/* Memory barriers */
#define rmb() __asm__ __volatile__("" ::: "memory")
#define wmb() __sync_synchronize()

/* TEMP_FAILURE_RETRY, but for all OSes */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(exp)                \
    ({                                         \
        __typeof(exp) _rc;                     \
        do {                                   \
            _rc = (exp);                       \
        } while (_rc == -1 && errno == EINTR); \
        _rc;                                   \
    })
#endif /* ifndef TEMP_FAILURE_RETRY */

#define HF_ATTR_NO_SANITIZE_ADDRESS
#ifdef __has_feature
#if __has_feature(address_sanitizer)
#undef HF_ATTR_NO_SANITIZE_ADDRESS
#define HF_ATTR_NO_SANITIZE_ADDRESS __attribute__((no_sanitize("address")))
#endif /* if __has_feature(address_sanitizer) */
#endif /* ifdef __has_feature */

#define HF_ATTR_NO_SANITIZE_MEMORY
#ifdef __has_feature
#if __has_feature(memory_sanitizer)
#undef HF_ATTR_NO_SANITIZE_MEMORY
#define HF_ATTR_NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
#endif /* if __has_feature(memory_sanitizer) */
#endif /* ifdef __has_feature */

#endif /* ifndef _HF_COMMON_COMMON_H_ */
