/*
 *
 * honggfuzz - fuzzer->dynamicFilefer mangling routines
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
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

#include "common.h"
#include "mangle.h"

#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

static inline void mangle_Overwrite(fuzzer_t * fuzzer, const uint8_t * src, size_t off, size_t sz)
{
    size_t maxToCopy = fuzzer->dynamicFileSz - off;
    if (sz > maxToCopy) {
        sz = maxToCopy;
    }

    memcpy(&fuzzer->dynamicFile[off], src, sz);
}

static inline void mangle_Move(fuzzer_t * fuzzer, size_t off_from, size_t off_to, size_t len)
{
    if (off_from >= fuzzer->dynamicFileSz) {
        return;
    }
    if (off_to >= fuzzer->dynamicFileSz) {
        return;
    }

    ssize_t len_from = (ssize_t) fuzzer->dynamicFileSz - off_from - 1;
    ssize_t len_to = (ssize_t) fuzzer->dynamicFileSz - off_to - 1;

    if ((ssize_t) len > len_from) {
        len = len_from;
    }
    if ((ssize_t) len > len_to) {
        len = len_to;
    }

    memmove(&fuzzer->dynamicFile[off_to], &fuzzer->dynamicFile[off_from], len);
}

static void mangle_Inflate(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, size_t off, size_t len)
{
    if (fuzzer->dynamicFileSz >= hfuzz->maxFileSz) {
        return;
    }
    if (len > (hfuzz->maxFileSz - fuzzer->dynamicFileSz)) {
        len = hfuzz->maxFileSz - fuzzer->dynamicFileSz;
    }

    fuzzer->dynamicFileSz += len;
    mangle_Move(fuzzer, off, off + len, fuzzer->dynamicFileSz);
}

static void mangle_MemMove(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off_from = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t off_to = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t len = util_rndGet(0, fuzzer->dynamicFileSz);

    mangle_Move(fuzzer, off_from, off_to, len);
}

static void mangle_Byte(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    fuzzer->dynamicFile[off] = (uint8_t) util_rndGet(0, UINT8_MAX);
}

static void mangle_Bytes(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    uint32_t val = (uint32_t) util_rndGet(0, UINT32_MAX);

    /* Overwrite with random 2,3,4-byte values */
    size_t toCopy = util_rndGet(2, 4);
    mangle_Overwrite(fuzzer, (uint8_t *) & val, off, toCopy);
}

static void mangle_Bit(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    fuzzer->dynamicFile[off] ^= (uint8_t) (1U << util_rndGet(0, 7));
}

static void mangle_DictionaryInsert(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->dictionaryCnt == 0) {
        mangle_Bit(hfuzz, fuzzer);
        return;
    }

    uint64_t choice = util_rndGet(0, hfuzz->dictionaryCnt - 1);
    struct strings_t *str = TAILQ_FIRST(&hfuzz->dictq);
    for (uint64_t i = 0; i < choice; i++) {
        str = TAILQ_NEXT(str, pointers);
    }

    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    mangle_Inflate(hfuzz, fuzzer, off, str->len);
    mangle_Move(fuzzer, off, off + str->len, str->len);
    mangle_Overwrite(fuzzer, (uint8_t *) str->s, off, str->len);
}

static void mangle_Dictionary(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->dictionaryCnt == 0) {
        mangle_Bit(hfuzz, fuzzer);
        return;
    }

    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);

    uint64_t choice = util_rndGet(0, hfuzz->dictionaryCnt - 1);
    struct strings_t *str = TAILQ_FIRST(&hfuzz->dictq);
    for (uint64_t i = 0; i < choice; i++) {
        str = TAILQ_NEXT(str, pointers);
    }

    mangle_Overwrite(fuzzer, (uint8_t *) str->s, off, str->len);
}

static void mangle_Magic(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    /*  *INDENT-OFF* */
    static const struct {
        const uint8_t val[8];
        const size_t size;
    } mangleMagicVals[] = {
        /* 1B - No endianness */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x08\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x0C\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x10\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x20\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x40\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x7E\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x7F\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x81\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\xC0\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\xFE\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\xFF\x00\x00\x00\x00\x00\x00\x00", 1},
        /* 2B - NE */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x01\x01\x00\x00\x00\x00\x00\x00", 2},
        { "\x80\x80\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\xFF\x00\x00\x00\x00\x00\x00", 2},
        /* 2B - BE */
        { "\x00\x01\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x02\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x03\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x04\x00\x00\x00\x00\x00\x00", 2},
        { "\x7E\xFF\x00\x00\x00\x00\x00\x00", 2},
        { "\x7F\xFF\x00\x00\x00\x00\x00\x00", 2},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x80\x01\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\xFE\x00\x00\x00\x00\x00\x00", 2},
        /* 2B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\x7E\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\x7F\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x80\x00\x00\x00\x00\x00\x00", 2},
        { "\x01\x80\x00\x00\x00\x00\x00\x00", 2},
        { "\xFE\xFF\x00\x00\x00\x00\x00\x00", 2},
        /* 4B - NE */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x01\x01\x01\x01\x00\x00\x00\x00", 4},
        { "\x80\x80\x80\x80\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        /* 4B - BE */
        { "\x00\x00\x00\x01\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x02\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x03\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x04\x00\x00\x00\x00", 4},
        { "\x7E\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        { "\x7F\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x80\x00\x00\x01\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\xFE\x00\x00\x00\x00", 4},
        /* 4B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\x7E\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\x7F\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x80\x00\x00\x00\x00", 4},
        { "\x01\x00\x00\x80\x00\x00\x00\x00", 4},
        { "\xFE\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        /* 8B - NE */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x01\x01\x01\x01\x01\x01\x01\x01", 8},
        { "\x80\x80\x80\x80\x80\x80\x80\x80", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
        /* 8B - BE */
        { "\x00\x00\x00\x00\x00\x00\x00\x01", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x02", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x03", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x04", 8},
        { "\x7E\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
        { "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x80\x00\x00\x00\x00\x00\x00\x01", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE", 8},
        /* 8B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7E", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x80", 8},
        { "\x01\x00\x00\x00\x00\x00\x00\x80", 8},
        { "\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
    };
    /*  *INDENT-ON* */

    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleMagicVals) - 1);
    mangle_Overwrite(fuzzer, mangleMagicVals[choice].val, off, mangleMagicVals[choice].size);
}

static void mangle_MemSet(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t sz = util_rndGet(1, fuzzer->dynamicFileSz - off);
    int val = (int)util_rndGet(0, UINT8_MAX);

    memset(&fuzzer->dynamicFile[off], val, sz);
}

static void mangle_Random(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t len = util_rndGet(1, fuzzer->dynamicFileSz - off);
    util_rndBuf(&fuzzer->dynamicFile[off], len);
}

static void mangle_AddSub(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);

    /* 1,2,4 */
    uint64_t varLen = 1ULL << util_rndGet(0, 2);
    if ((fuzzer->dynamicFileSz - off) < varLen) {
        varLen = 1;
    }

    int delta = (int)util_rndGet(0, 8192);
    delta -= 4096;

    switch (varLen) {
    case 1:
        {
            fuzzer->dynamicFile[off] += delta;
            return;
            break;
        }
    case 2:
        {
            int16_t val = *((uint16_t *) & fuzzer->dynamicFile[off]);
            if (util_rndGet(0, 1) == 0) {
                val += delta;
            } else {
                /* Foreign endianess */
                val = __builtin_bswap16(val);
                val += delta;
                val = __builtin_bswap16(val);
            }
            mangle_Overwrite(fuzzer, (uint8_t *) & val, off, varLen);
            return;
            break;
        }
    case 4:
        {
            int32_t val = *((uint32_t *) & fuzzer->dynamicFile[off]);
            if (util_rndGet(0, 1) == 0) {
                val += delta;
            } else {
                /* Foreign endianess */
                val = __builtin_bswap32(val);
                val += delta;
                val = __builtin_bswap32(val);
            }
            mangle_Overwrite(fuzzer, (uint8_t *) & val, off, varLen);
            return;
            break;
        }
    default:
        {
            LOG_F("Unknown variable length size: %" PRIu64, varLen);
            break;
        }
    }
}

static void mangle_IncByte(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    fuzzer->dynamicFile[off] += (uint8_t) 1UL;
}

static void mangle_DecByte(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    fuzzer->dynamicFile[off] -= (uint8_t) 1UL;
}

static void mangle_NegByte(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    fuzzer->dynamicFile[off] = ~(fuzzer->dynamicFile[off]);
}

static void mangle_CloneByte(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off1 = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t off2 = util_rndGet(0, fuzzer->dynamicFileSz - 1);

    uint8_t tmp = fuzzer->dynamicFile[off1];
    fuzzer->dynamicFile[off1] = fuzzer->dynamicFile[off2];
    fuzzer->dynamicFile[off2] = tmp;
}

static void mangle_Resize(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    fuzzer->dynamicFileSz = util_rndGet(1, hfuzz->maxFileSz);
}

static void mangle_Expand(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t len = util_rndGet(1, fuzzer->dynamicFileSz - off);

    mangle_Inflate(hfuzz, fuzzer, off, len);
    mangle_Move(fuzzer, off, off + len, fuzzer->dynamicFileSz);
    memset(fuzzer->dynamicFile, '\0', len);
}

static void mangle_Shrink(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    if (fuzzer->dynamicFileSz <= 1U) {
        return;
    }

    size_t len = util_rndGet(1, fuzzer->dynamicFileSz - 1);
    size_t off = util_rndGet(0, len);

    mangle_Move(fuzzer, off + len, off, fuzzer->dynamicFileSz);
    fuzzer->dynamicFileSz -= len;
}

static void mangle_InsertRnd(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer)
{
    size_t off = util_rndGet(0, fuzzer->dynamicFileSz - 1);
    size_t len = util_rndGet(1, fuzzer->dynamicFileSz - off);

    mangle_Inflate(hfuzz, fuzzer, off, len);
    mangle_Move(fuzzer, off, off + len, fuzzer->dynamicFileSz);
    util_rndBuf(&fuzzer->dynamicFile[off], len);
}

void mangle_mangleContent(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (fuzzer->flipRate == 0.0f) {
        return;
    }

    static void (*const mangleFuncs[]) (honggfuzz_t * hfuzz, fuzzer_t * fuzzer) = {
    /*  *INDENT-OFF* */
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bytes,
        mangle_Magic,
        mangle_IncByte,
        mangle_DecByte,
        mangle_NegByte,
        mangle_AddSub,
        mangle_Dictionary,
        mangle_DictionaryInsert,
        mangle_MemMove,
        mangle_MemSet,
        mangle_Random,
        mangle_CloneByte,
        mangle_Expand,
        mangle_Shrink,
        mangle_InsertRnd,
        mangle_Resize,
    /* *INDENT-ON* */
    };

    uint64_t changesCnt = fuzzer->dynamicFileSz * fuzzer->flipRate;
    if (changesCnt < 3ULL) {
        /* Mini-max number of changes is 3 */
        changesCnt = 3;
    }
    changesCnt = util_rndGet(1, changesCnt);

    for (uint64_t x = 0; x < changesCnt; x++) {
        uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleFuncs) - 1);
        mangleFuncs[choice] (hfuzz, fuzzer);
    }
}
