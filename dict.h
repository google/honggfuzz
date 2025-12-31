/*
 *
 * honggfuzz - dictionary utilities
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

#ifndef _HF_COMMON_DICT_H_
#define _HF_COMMON_DICT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "honggfuzz.h"

/*
 * Add a dictionary entry with duplicate checking.
 * Returns true if the entry was added, false if it was a duplicate or dict is full.
 */
extern bool dict_add(honggfuzz_t* hfuzz, const uint8_t* data, size_t len);

/*
 * Add a null-terminated string to the dictionary with duplicate checking.
 * Returns true if the entry was added, false if it was a duplicate or dict is full.
 */
extern bool dict_addString(honggfuzz_t* hfuzz, const char* str);

/*
 * Check if a dictionary entry already exists.
 * Returns true if the entry exists.
 */
extern bool dict_exists(honggfuzz_t* hfuzz, const uint8_t* data, size_t len);

/*
 * Get current dictionary count.
 */
extern size_t dict_count(honggfuzz_t* hfuzz);

/*
 * Check if dictionary is full.
 */
extern bool dict_isFull(honggfuzz_t* hfuzz);

/*
 * Get count of duplicates that were skipped.
 */
extern size_t dict_getDuplicateCount(void);

/*
 * Log dictionary statistics (entries count, duplicates skipped).
 */
extern void dict_logStats(honggfuzz_t* hfuzz);

#endif /* _HF_COMMON_DICT_H_ */
