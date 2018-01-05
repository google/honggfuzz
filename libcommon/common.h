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
#endif /* ifndef UNUSED */

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
        typeof(exp) _rc;                       \
        do {                                   \
            _rc = (exp);                       \
        } while (_rc == -1 && errno == EINTR); \
        _rc;                                   \
    })
#endif /* ifndef TEMP_FAILURE_RETRY */

#endif /* ifndef _HF_COMMON_H_ */
