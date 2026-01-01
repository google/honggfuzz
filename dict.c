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

#include "dict.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"

/* Mutex for thread-safe dictionary operations */
static pthread_mutex_t dict_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Statistics */
static size_t dict_duplicatesSkipped = 0;

/*
 * Simple hash function for dictionary entries (FNV-1a)
 */
static inline uint32_t dict_hash(const uint8_t* data, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

/*
 * Hash table for fast duplicate lookups.
 * Uses open addressing with linear probing.
 * Size is 64K to keep load factor low for large dictionaries.
 */
#define DICT_HASH_SIZE 65536
#define DICT_HASH_MASK (DICT_HASH_SIZE - 1)

/* Hash table entries: index into dictionary array, 0 means empty, index+1 stored */
static uint16_t dict_hashTable[DICT_HASH_SIZE];

/*
 * Check if entry exists in dictionary.
 * Caller must hold dict_mutex.
 */
static bool dict_existsLocked(honggfuzz_t* hfuzz, const uint8_t* data, size_t len) {
    if (len == 0 || len > sizeof(hfuzz->mutate.dictionary[0].val)) {
        return false;
    }

    uint32_t hash  = dict_hash(data, len);
    uint32_t idx   = hash & DICT_HASH_MASK;
    uint32_t start = idx;

    do {
        uint16_t entry = dict_hashTable[idx];
        if (entry == 0) {
            /* Empty slot - not found */
            return false;
        }

        /* entry is index+1, so actual index is entry-1 */
        size_t dictIdx = entry - 1;
        if (dictIdx < hfuzz->mutate.dictionaryCnt) {
            if (hfuzz->mutate.dictionary[dictIdx].len == len &&
                memcmp(hfuzz->mutate.dictionary[dictIdx].val, data, len) == 0) {
                return true;
            }
        }

        /* Linear probing */
        idx = (idx + 1) & DICT_HASH_MASK;
    } while (idx != start);

    return false;
}

/*
 * Insert entry into hash table.
 * Caller must hold dict_mutex.
 */
static void dict_hashInsert(const uint8_t* data, size_t len, size_t dictIdx) {
    uint32_t hash  = dict_hash(data, len);
    uint32_t idx   = hash & DICT_HASH_MASK;
    uint32_t start = idx;

    do {
        if (dict_hashTable[idx] == 0) {
            dict_hashTable[idx] = (uint16_t)(dictIdx + 1);
            return;
        }
        idx = (idx + 1) & DICT_HASH_MASK;
    } while (idx != start);

    /* Hash table full - should not happen with proper sizing */
}

bool dict_exists(honggfuzz_t* hfuzz, const uint8_t* data, size_t len) {
    MX_SCOPED_LOCK(&dict_mutex);
    return dict_existsLocked(hfuzz, data, len);
}

bool dict_add(honggfuzz_t* hfuzz, const uint8_t* data, size_t len) {
    if (len < 1 || len > sizeof(hfuzz->mutate.dictionary[0].val)) {
        return false;
    }

    MX_SCOPED_LOCK(&dict_mutex);

    /* Check if dictionary is full */
    if (hfuzz->mutate.dictionaryCnt >= ARRAYSIZE(hfuzz->mutate.dictionary)) {
        LOG_D("Dictionary full, cannot add entry of len=%zu", len);
        return false;
    }

    /* Check for duplicates */
    if (dict_existsLocked(hfuzz, data, len)) {
        dict_duplicatesSkipped++;
        LOG_D("Skipping duplicate dictionary entry '%.*s' (len=%zu, total dups=%zu)", (int)len,
            data, len, dict_duplicatesSkipped);
        return false;
    }

    /* Add to dictionary */
    size_t idx = hfuzz->mutate.dictionaryCnt++;
    memcpy(hfuzz->mutate.dictionary[idx].val, data, len);
    hfuzz->mutate.dictionary[idx].len = len;

    /* Add to hash table */
    dict_hashInsert(data, len, idx);

    LOG_D("Added dictionary entry #%zu '%.*s' (len=%zu)", idx, (int)len, data, len);

    return true;
}

bool dict_addString(honggfuzz_t* hfuzz, const char* str) {
    if (!str) {
        return false;
    }
    size_t len = strlen(str);
    return dict_add(hfuzz, (const uint8_t*)str, len);
}

size_t dict_count(honggfuzz_t* hfuzz) {
    return hfuzz->mutate.dictionaryCnt;
}

bool dict_isFull(honggfuzz_t* hfuzz) {
    return hfuzz->mutate.dictionaryCnt >= ARRAYSIZE(hfuzz->mutate.dictionary);
}

size_t dict_getDuplicateCount(void) {
    return dict_duplicatesSkipped;
}

void dict_logStats(honggfuzz_t* hfuzz) {
    LOG_I("Dictionary stats: %zu entries, %zu duplicates skipped", hfuzz->mutate.dictionaryCnt,
        dict_duplicatesSkipped);
}
