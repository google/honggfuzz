/*
 *
 * honggfuzz - buffer mangling routines
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

static void mangle_Byte(uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] = (uint8_t) util_rndGet(0, UINT8_MAX);
    return;
/* Ignore buffer size */
    if (bufSz == 0) {
        return;
    }
}

static void mangle_Bit(uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] ^= ((uint8_t) 1 << util_rndGet(0, 7));
    return;
/* Ignore buffer size */
    if (bufSz == 0) {
        return;
    }
}

static void mangle_Magic(uint8_t * buf, size_t bufSz, size_t off)
{
/*  *INDENT-OFF* */
    const struct {
        const uint8_t val[8];
        const size_t size;
    } mangleMagicVals[] = {
        /* 1B - No endianess */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x7F\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\xFF\x00\x00\x00\x00\x00\x00\x00", 1},
        /* 2B - NE */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\xFF\x00\x00\x00\x00\x00\x00", 2},
        /* 2B - BE */
        { "\x00\x01\x00\x00\x00\x00\x00\x00", 2},
        { "\x7F\xFF\x00\x00\x00\x00\x00\x00", 2},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 2},
        /* 2B - LE */
        { "\x00\x01\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\x7F\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x80\x00\x00\x00\x00\x00\x00", 2},
        /* 4B - NE */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        /* 4B - BE */
        { "\x00\x00\x00\x01\x00\x00\x00\x00", 4},
        { "\x7F\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 4},
        /* 4B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\x7F\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x80\x00\x00\x00\x00", 4},
        /* 8B - NE */
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
        /* 8B - BE */
        { "\x00\x00\x00\x00\x00\x00\x00\x01", 8},
        { "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 8},
        /* 8B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x80", 8},
    };
/*  *INDENT-ON* */

    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleMagicVals) - 1);

    size_t toCopy = mangleMagicVals[choice].size;
    size_t maxToCopy = bufSz - off;
    if (toCopy > maxToCopy) {
        toCopy = maxToCopy;
    }

    memcpy(&buf[off], mangleMagicVals[choice].val, toCopy);
}

static void mangle_Shift(uint8_t * buf, size_t bufSz, size_t off)
{
    uint64_t mangleTo = util_rndGet(0, bufSz - 1);

    uint64_t mangleSzFrom = util_rndGet(1, bufSz - off);
    uint64_t mangleSzTo = util_rndGet(1, bufSz - mangleTo);
    uint64_t mangleSz = mangleSzFrom < mangleSzTo ? mangleSzFrom : mangleSzTo;

    memmove(&buf[mangleTo], &buf[off], mangleSz);
}

void mangle_mangleContent(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
/*  *INDENT-OFF* */
    void (*const mangleFuncs[]) (uint8_t * buf, size_t bufSz, size_t off) = {
        mangle_Byte,
        mangle_Bit,
        mangle_Magic,
	mangle_Shift,
    };
/*  *INDENT-ON* */

    /*
     * Minimal number of changes is 1
     */
    uint64_t changesCnt = bufSz * hfuzz->flipRate;
    if (changesCnt == 0ULL) {
        changesCnt = 1;
    }
    changesCnt = util_rndGet(1, changesCnt);

    for (uint64_t x = 0; x < changesCnt; x++) {
        size_t offset = util_rndGet(0, bufSz - 1);
        uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleFuncs) - 1);
        mangleFuncs[choice] (buf, bufSz, offset);
    }
}

size_t mangle_resize(honggfuzz_t * hfuzz, uint8_t ** buf, size_t bufSz)
{
    if (!hfuzz) {
        return 0LL;
    }
    if (!buf) {
        return 0UL;
    }
    if (bufSz == 0) {
        return 0UL;
    }

    return bufSz;
}
