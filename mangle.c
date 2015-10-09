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

    memcpy(&dst[off], src, sz);
}

static void mangle_Byte(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] = (uint8_t) util_rndGet(0, UINT8_MAX);
    return;
    /* Ignore buffer size */
    if (bufSz == 0) {
        return;
    }
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_Bytes(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    uint32_t val = (uint32_t) util_rndGet(0, UINT32_MAX);

    /* Overwrite with random 2,3,4-byte values */
    size_t toCopy = util_rndGet(2, 4);
    mangle_Overwrite(buf, (uint8_t *) & val, bufSz, off, toCopy);
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_Bit(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] ^= ((uint8_t) 1 << util_rndGet(0, 7));
    return;
    /* Ignore buffer size */
    if (bufSz == 0) {
        return;
    }
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_Dictionary(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    if (hfuzz->dictionaryCnt == 0) {
        mangle_Bit(hfuzz, buf, bufSz, off);
        return;
    }

    uint64_t choice = util_rndGet(0, hfuzz->dictionaryCnt - 1);
    mangle_Overwrite(buf, (uint8_t *) hfuzz->dictionary[choice], bufSz, off,
                     strlen(hfuzz->dictionary[choice]));
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_Magic(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
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
        { "\x7E\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x7F\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x80\x00\x00\x00\x00\x00\x00\x00", 1},
        { "\x81\x00\x00\x00\x00\x00\x00\x00", 1},
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
        /* 2B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\x7E\x00\x00\x00\x00\x00\x00", 2},
        { "\xFF\x7F\x00\x00\x00\x00\x00\x00", 2},
        { "\x00\x80\x00\x00\x00\x00\x00\x00", 2},
        { "\x01\x80\x00\x00\x00\x00\x00\x00", 2},
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
        /* 4B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\x7E\x00\x00\x00\x00", 4},
        { "\xFF\xFF\xFF\x7F\x00\x00\x00\x00", 4},
        { "\x00\x00\x00\x80\x00\x00\x00\x00", 4},
        { "\x01\x00\x00\x80\x00\x00\x00\x00", 4},
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
        /* 8B - LE */
        { "\x01\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x02\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x03\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\x04\x00\x00\x00\x00\x00\x00\x00", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7E", 8},
        { "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 8},
        { "\x00\x00\x00\x00\x00\x00\x00\x80", 8},
        { "\x01\x00\x00\x00\x00\x00\x00\x80", 8},
    };
    /*  *INDENT-ON* */

    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleMagicVals) - 1);
    mangle_Overwrite(buf, mangleMagicVals[choice].val, bufSz, off, mangleMagicVals[choice].size);
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_MemSet(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    uint64_t sz = util_rndGet(1, bufSz - off);
    int val = (int)util_rndGet(0, UINT8_MAX);

    memset(&buf[off], val, sz);
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_MemMove(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    uint64_t mangleTo = util_rndGet(0, bufSz - 1);
    uint64_t mangleSzTo = bufSz - mangleTo;

    uint64_t mangleSzFrom = util_rndGet(1, bufSz - off);
    uint64_t mangleSz = mangleSzFrom < mangleSzTo ? mangleSzFrom : mangleSzTo;

    memmove(&buf[mangleTo], &buf[off], mangleSz);
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_Random(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    uint64_t sz = util_rndGet(1, bufSz - off);
    util_rndBuf(&buf[off], sz);
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_AddSub(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    /* 1,2,4 */
    uint64_t varLen = 1ULL << util_rndGet(0, 2);
    if ((bufSz - off) < varLen) {
        varLen = 1;
    }

    int delta = (int)util_rndGet(0, 64);
    delta -= 32;

    switch (varLen) {
    case 1:
        {
            buf[off] += delta;
            return;
            break;
        }
    case 2:
        {
            uint16_t val = *((uint16_t *) & buf[off]);
            if (util_rndGet(0, 1) == 0) {
                /* BE */
                val = util_ToFromBE16(val);
                val += delta;
                val = util_ToFromBE16(val);
            } else {
                /* LE */
                val = util_ToFromLE16(val);
                val += delta;
                val = util_ToFromLE16(val);
            }
            mangle_Overwrite(buf, (uint8_t *) & val, bufSz, off, varLen);
            return;
            break;
        }
    case 4:
        {
            uint32_t val = *((uint32_t *) & buf[off]);
            if (util_rndGet(0, 1) == 0) {
                /* BE */
                val = util_ToFromBE32(val);
                val += delta;
                val = util_ToFromBE32(val);
            } else {
                /* LE */
                val = util_ToFromLE32(val);
                val += delta;
                val = util_ToFromLE32(val);
            }
            mangle_Overwrite(buf, (uint8_t *) & val, bufSz, off, varLen);
            return;
            break;
        }
    default:
        {
            LOG_F("Unknown variable length size: %" PRId64, varLen);
            break;
        }
    }
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_IncByte(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] += (uint8_t) 1UL;
    return;
    /* bufSz is unused */
    if (bufSz == 0) {
        return;
    }
    if (hfuzz == NULL) {
        return;
    }
}

static void mangle_DecByte(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off)
{
    buf[off] -= (uint8_t) 1UL;
    return;
    /* bufSz is unused */
    if (bufSz == 0) {
        return;
    }
    if (hfuzz == NULL) {
        return;
    }
}

void mangle_mangleContent(honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz)
{
    /*  *INDENT-OFF* */
    void (*const mangleFuncs[]) (honggfuzz_t * hfuzz, uint8_t * buf, size_t bufSz, size_t off) = {
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
        mangle_IncByte,
        mangle_IncByte,
        mangle_DecByte,
        mangle_DecByte,
        mangle_AddSub,
        mangle_AddSub,
        mangle_Dictionary,
        mangle_Dictionary,
        mangle_MemMove,
        mangle_MemSet,
        mangle_Random,
    };
    /*  *INDENT-ON* */

    /* if -r 0.0 then just return */
    if (hfuzz->flipRate == 0.0L) {
        return;
    }
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
        mangleFuncs[choice] (hfuzz, buf, bufSz, offset);
    }
}

static double mangle_ExpDist(void)
{
    double rnd = (double)util_rndGet(1, UINT32_MAX) / (double)(UINT32_MAX);
    return pow(rnd, 4.0L);
}

/* Gauss-like distribution */
bool mangle_Resize(honggfuzz_t * hfuzz, uint8_t * buf, size_t * bufSz)
{
    const uint64_t chance_one_in_x = 5;
    if (util_rndGet(1, chance_one_in_x) != 1) {
        return true;
    }
    ssize_t newSz = *bufSz;
    int delta = 0;
    unsigned int val = (unsigned int)util_rndGet(1, 64);
    switch (val) {
    case 1 ... 16:
        delta = -val;
        break;
    case 17 ... 32:
        delta = val - 16;
        break;
    case 33 ... 48:
        delta += (int)(mangle_ExpDist() * (double)((hfuzz->maxFileSz - *bufSz)));
        break;
    case 49 ... 64:
        delta -= (int)(mangle_ExpDist() * (double)(*bufSz));
        break;
    default:
        LOG_F("Random value out of scope %u", val);
        break;
    }

    newSz += delta;

    if (newSz < 1) {
        newSz = 1;
    }
    if (newSz > (ssize_t) hfuzz->maxFileSz) {
        newSz = (ssize_t) hfuzz->maxFileSz;
    }

    if ((size_t) newSz > *bufSz) {
        util_rndBuf(&buf[*bufSz], newSz - *bufSz);
    }

    LOG_D("Current size: %zu, Maximal size: %zu, New Size: %zu, Delta: %d", *bufSz,
          hfuzz->maxFileSz, newSz, delta);

    *bufSz = (size_t) newSz;
    return true;
}
