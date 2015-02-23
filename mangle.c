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
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

static void mangle_Overwrite(uint8_t * dst, const uint8_t * src, size_t dstSz, size_t off,
                             size_t sz)
{
    size_t maxToCopy = dstSz - off;
    if (sz > maxToCopy) {
        sz = maxToCopy;
    }

    memcpy(&dst[off], &src, sz);
}

static void mangle_Byte(uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] = (uint8_t) util_rndGet(0, UINT8_MAX);
    return;
/* Ignore buffer size */
    if (bufSz == 0) {
        return;
    }
}

static void mangle_Bytes(uint8_t * buf, size_t bufSz, size_t off)
{
    uint32_t val = (uint32_t) util_rndGet(0, UINT32_MAX);

    /* Overwrite with random 2,3,4-byte values */
    size_t toCopy = util_rndGet(2, 4);
    mangle_Overwrite(&buf[off], (uint8_t *) & val, bufSz, off, toCopy);
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
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x7F\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 1},
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
        { "\x7F\xFF\x00\x00\x00\x00\x00\x00", 2},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 2},
        /* 2B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\x7F\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x80\x00\x00\x00\x00\x00\x00", 2},
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
        { "\x7F\xFF\xFF\xFF\x00\x00\x00\x00", 4},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 4},
        /* 4B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\x7F\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x80\x00\x00\x00\x00", 4},
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
        { "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 8},
        /* 8B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x80", 8},
    };
/*  *INDENT-ON* */

    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleMagicVals) - 1);
    mangle_Overwrite(&buf[off], mangleMagicVals[choice].val, bufSz, off,
                     mangleMagicVals[choice].size);
}

static void mangle_Shift(uint8_t * buf, size_t bufSz, size_t off)
{
    uint64_t mangleTo = util_rndGet(0, bufSz - 1);
    uint64_t mangleSzTo = bufSz - mangleTo;

    uint64_t mangleSzFrom = util_rndGet(1, bufSz - off);
    uint64_t mangleSz = mangleSzFrom < mangleSzTo ? mangleSzFrom : mangleSzTo;

    memmove(&buf[mangleTo], &buf[off], mangleSz);
}

void mangle_mangleContent(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
/*  *INDENT-OFF* */
    void (*const mangleFuncs[]) (uint8_t * buf, size_t bufSz, size_t off) = {
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Byte,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bit,
        mangle_Bytes,
        mangle_Bytes,
        mangle_Magic,
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

/* Gauss-like distribution */
bool mangle_Resize(honggfuzz_t * hfuzz, uint8_t ** buf, size_t * bufSz)
{
    const uint64_t chance_one_in_x = 10;
    if (util_rndGet(1, chance_one_in_x) != 1) {
        return true;
    }

    int64_t choice = (int64_t) util_rndGet(1, UINT32_MAX);
    double delta = 1.0L / (double)choice;

    if (util_rndGet(0, 1) == 0) {
        delta = pow(delta, 0.25L);
    } else {
        delta = -pow(delta, 0.25L);
    }

    int64_t newSz = (int64_t) * bufSz;
    if (delta > 0.0L) {
        newSz = (int64_t) * bufSz + (int64_t) ((double)(hfuzz->maxFileSz - *bufSz) * delta);
    }
    if (delta < 0.0L) {
        newSz = (int64_t) * bufSz + (int64_t) ((double)*bufSz * delta);
    }

    if (newSz > (int64_t) hfuzz->maxFileSz) {
        newSz = (int64_t) hfuzz->maxFileSz;
    }
    if (newSz < 1LL) {
        newSz = 1LL;
    }

    LOGMSG(l_DEBUG, "DELTA: %lf, CUR: %zu, MAX: %zu, CHOSEN: %zu", delta, *bufSz,
           hfuzz->maxFileSz, newSz);

    if (buf == NULL) {
        *bufSz = (size_t) newSz;
        return true;
    }

    void *newBuf = mremap(buf, _HF_PAGE_ALIGN_UP(bufSz), _HF_PAGE_ALIGN_UP(newSz), MREMAP_MAYMOVE);
    if (newBuf == MAP_FAILED) {
        LOGMSG_P(l_ERROR, "mremap() failed");
        return false;
    }

    *buf = newBuf;
    *bufSz = (size_t) newSz;
    return true;
}
