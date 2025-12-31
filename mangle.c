/*
 *
 * honggfuzz - run->dynfile->datafer mangling routines
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
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

#include "mangle.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "input.h"
#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

typedef enum {
    MANGLE_SHRINK = 0,
    MANGLE_EXPAND,
    MANGLE_BIT,
    MANGLE_INC_BYTE,
    MANGLE_DEC_BYTE,
    MANGLE_NEG_BYTE,
    MANGLE_ADD_SUB,
    MANGLE_ARITH8,
    MANGLE_MEM_SET,
    MANGLE_MEM_CLR,
    MANGLE_MEM_SWAP,
    MANGLE_MEM_COPY,
    MANGLE_BLOCK_MOVE,
    MANGLE_BLOCK_REPEAT,
    MANGLE_BLOCK_SWAP,
    MANGLE_CHUNK_SHUFFLE,
    MANGLE_BYTES,
    MANGLE_BYTE_REPEAT,
    MANGLE_RANDOM_BUF,
    MANGLE_INTERESTING_VALUES,
    MANGLE_ASCII_NUM,
    MANGLE_ASCII_NUM_CHANGE,
    MANGLE_MAGIC,
    MANGLE_STATIC_DICT,
    MANGLE_CONST_FEEDBACK_DICT,
    MANGLE_CMP_SOLVE,
    MANGLE_SPLICE,
    MANGLE_CROSS_OVER,
    MANGLE_SPECIAL_STRINGS,
    MANGLE_TLV_MUTATE,
    MANGLE_TOKEN_SHUFFLE,
    MANGLE_GRADIENT_CMP,
    MANGLE_ARITH_CONST,
    MANGLE_HAVOC,
    MANGLE_COUNT
} mangle_t;

static inline size_t mangle_LenLeft(run_t* run, size_t off) {
    if (off >= run->dynfile->size) {
        LOG_F("Offset is too large: off:%zu >= len:%zu", off, run->dynfile->size);
    }
    return (run->dynfile->size - off - 1);
}

/*
 * Get a random value <1:max>, but prefer smaller ones
 * Based on an idea by https://twitter.com/gamozolabs
 */
static inline size_t mangle_getLen(size_t max) {
    if (max > _HF_INPUT_MAX_SIZE) {
        LOG_F("max (%zu) > _HF_INPUT_MAX_SIZE (%zu)", max, (size_t)_HF_INPUT_MAX_SIZE);
    }
    if (max == 0) {
        LOG_F("max == 0");
    }
    if (max == 1) {
        return 1;
    }

    /* Give 50% chance the the uniform distribution */
    if (util_rnd64() & 1) {
        return (size_t)util_rndGet(1, max);
    }

    /* effectively exprand() */
    return (size_t)util_rndGet(1, util_rndGet(1, max));
}

/* Prefer smaller values here, so use mangle_getLen() */
static inline size_t mangle_getOffSet(run_t* run) {
    return mangle_getLen(run->dynfile->size) - 1;
}

/* Offset which can be equal to the file size */
static inline size_t mangle_getOffSetPlus1(run_t* run) {
    size_t reqlen = HF_MIN(run->dynfile->size + 1, _HF_INPUT_MAX_SIZE);
    return mangle_getLen(reqlen) - 1;
}

static inline void mangle_Move(run_t* run, size_t off_from, size_t off_to, size_t len) {
    if (off_from >= run->dynfile->size) {
        return;
    }
    if (off_to >= run->dynfile->size) {
        return;
    }
    if (off_from == off_to) {
        return;
    }

    size_t len_from = run->dynfile->size - off_from;
    len             = HF_MIN(len, len_from);

    size_t len_to = run->dynfile->size - off_to;
    len           = HF_MIN(len, len_to);

    memmove(&run->dynfile->data[off_to], &run->dynfile->data[off_from], len);
}

static inline void mangle_Overwrite(
    run_t* run, size_t off, const uint8_t* src, size_t len, bool printable) {
    if (len == 0) {
        return;
    }
    size_t maxToCopy = run->dynfile->size - off;
    if (len > maxToCopy) {
        len = maxToCopy;
    }

    memmove(&run->dynfile->data[off], src, len);
    if (printable) {
        util_turnToPrintable(&run->dynfile->data[off], len);
    }
}

static inline size_t mangle_Inflate(run_t* run, size_t off, size_t len, bool printable) {
    if (run->dynfile->size >= run->global->mutate.maxInputSz) {
        return 0;
    }
    if (len > (run->global->mutate.maxInputSz - run->dynfile->size)) {
        len = run->global->mutate.maxInputSz - run->dynfile->size;
    }

    input_setSize(run, run->dynfile->size + len);
    mangle_Move(run, off, off + len, run->dynfile->size);
    if (printable) {
        memset(&run->dynfile->data[off], ' ', len);
    }

    return len;
}

static inline void mangle_Insert(
    run_t* run, size_t off, const uint8_t* val, size_t len, bool printable) {
    len = mangle_Inflate(run, off, len, printable);
    mangle_Overwrite(run, off, val, len, printable);
}

static inline void mangle_UseValue(run_t* run, const uint8_t* val, size_t len, bool printable) {
    if (util_rnd64() & 1) {
        mangle_Overwrite(run, mangle_getOffSet(run), val, len, printable);
    } else {
        mangle_Insert(run, mangle_getOffSetPlus1(run), val, len, printable);
    }
}

static inline void mangle_UseValueAt(
    run_t* run, size_t off, const uint8_t* val, size_t len, bool printable) {
    if (util_rnd64() & 1) {
        mangle_Overwrite(run, off, val, len, printable);
    } else {
        mangle_Insert(run, off, val, len, printable);
    }
}

static void mangle_MemSwap(run_t* run, bool printable HF_ATTR_UNUSED) {
    /* No big deal if those two are overlapping */
    size_t off1    = mangle_getOffSet(run);
    size_t maxlen1 = run->dynfile->size - off1;
    size_t off2    = mangle_getOffSet(run);
    size_t maxlen2 = run->dynfile->size - off2;
    size_t len     = mangle_getLen(HF_MIN(maxlen1, maxlen2));

    if (off1 == off2) {
        return;
    }

    for (size_t i = 0; i < (len / 2); i++) {
        /*
         * First - from the head, next from the tail. Don't worry about layout of the overlapping
         * part - there's no good solution to that, and it can be left somewhat scrambled,
         * while still preserving the entropy
         */
        const uint8_t tmp1                       = run->dynfile->data[off2 + i];
        run->dynfile->data[off2 + i]             = run->dynfile->data[off1 + i];
        run->dynfile->data[off1 + i]             = tmp1;
        const uint8_t tmp2                       = run->dynfile->data[off2 + (len - 1) - i];
        run->dynfile->data[off2 + (len - 1) - i] = run->dynfile->data[off1 + (len - 1) - i];
        run->dynfile->data[off1 + (len - 1) - i] = tmp2;
    }
}

static void mangle_BlockMove(run_t* run, bool printable HF_ATTR_UNUSED) {
    size_t off_from = mangle_getOffSet(run);
    size_t off_to   = mangle_getOffSet(run);
    size_t len      = mangle_getLen(run->dynfile->size);
    mangle_Move(run, off_from, off_to, len);
}

static void mangle_MemCopy(run_t* run, bool printable HF_ATTR_UNUSED) {
    size_t off = mangle_getOffSet(run);
    size_t len = mangle_getLen(run->dynfile->size - off);

    /* Use a temp buf, as Insert/Inflate can change source bytes */
    uint8_t* tmpbuf = (uint8_t*)util_Malloc(len);
    defer {
        free(tmpbuf);
    };
    memmove(tmpbuf, &run->dynfile->data[off], len);

    mangle_UseValue(run, tmpbuf, len, printable);
}

static void mangle_Bytes(run_t* run, bool printable) {
    uint16_t buf;
    if (printable) {
        util_rndBufPrintable((uint8_t*)&buf, sizeof(buf));
    } else {
        buf = util_rnd64();
    }

    /* Overwrite with random 1-2-byte values */
    size_t toCopy = util_rndGet(1, 2);
    mangle_UseValue(run, (const uint8_t*)&buf, toCopy, printable);
}

static void mangle_ByteRepeat(run_t* run, bool printable) {
    size_t off     = mangle_getOffSet(run);
    size_t destOff = off + 1;
    size_t maxSz   = run->dynfile->size - destOff;

    /* No space to repeat */
    if (!maxSz) {
        mangle_Bytes(run, printable);
        return;
    }

    size_t len = mangle_getLen(maxSz);
    if (util_rnd64() & 0x1) {
        len = mangle_Inflate(run, destOff, len, printable);
    }
    memset(&run->dynfile->data[destOff], run->dynfile->data[off], len);
}

static void mangle_Bit(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    run->dynfile->data[off] ^= (uint8_t)(1U << util_rndGet(0, 7));
    if (printable) {
        util_turnToPrintable(&(run->dynfile->data[off]), 1);
    }
}

static const struct {
#if __has_attribute(nonstring)
    const uint8_t val[8] __attribute__((nonstring));
#else
    const uint8_t val[8];
#endif /* __has_attribute(nonstring) */
    const size_t size;
} mangleMagicVals[] = {
    /* 1B - No endianness */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x01\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x02\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x03\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x04\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x05\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x06\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x07\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x08\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x09\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x0A\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x0B\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x0C\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x0D\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x0E\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x0F\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x10\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x20\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x40\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x7E\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x7F\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\x81\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\xC0\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\xFE\x00\x00\x00\x00\x00\x00\x00", 1},
    {"\xFF\x00\x00\x00\x00\x00\x00\x00", 1},
    /* 2B - NE */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x01\x01\x00\x00\x00\x00\x00\x00", 2},
    {"\x80\x80\x00\x00\x00\x00\x00\x00", 2},
    {"\xFF\xFF\x00\x00\x00\x00\x00\x00", 2},
    /* 2B - BE */
    {"\x00\x01\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x02\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x03\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x04\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x05\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x06\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x07\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x08\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x09\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x0A\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x0B\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x0C\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x0D\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x0E\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x0F\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x10\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x20\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x40\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x7E\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x7F\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x80\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x81\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\xC0\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\xFE\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\xFF\x00\x00\x00\x00\x00\x00", 2},
    {"\x7E\xFF\x00\x00\x00\x00\x00\x00", 2},
    {"\x7F\xFF\x00\x00\x00\x00\x00\x00", 2},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x80\x01\x00\x00\x00\x00\x00\x00", 2},
    {"\xFF\xFE\x00\x00\x00\x00\x00\x00", 2},
    /* 2B - LE */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x01\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x02\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x03\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x04\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x05\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x06\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x07\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x08\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x09\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x0A\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x0B\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x0C\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x0D\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x0E\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x0F\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x10\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x20\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x40\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x7E\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x7F\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\x81\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\xC0\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\xFE\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\xFF\x00\x00\x00\x00\x00\x00\x00", 2},
    {"\xFF\x7E\x00\x00\x00\x00\x00\x00", 2},
    {"\xFF\x7F\x00\x00\x00\x00\x00\x00", 2},
    {"\x00\x80\x00\x00\x00\x00\x00\x00", 2},
    {"\x01\x80\x00\x00\x00\x00\x00\x00", 2},
    {"\xFE\xFF\x00\x00\x00\x00\x00\x00", 2},
    /* 4B - NE */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x01\x01\x01\x01\x00\x00\x00\x00", 4},
    {"\x80\x80\x80\x80\x00\x00\x00\x00", 4},
    {"\xFF\xFF\xFF\xFF\x00\x00\x00\x00", 4},
    /* 4B - BE */
    {"\x00\x00\x00\x01\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x02\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x03\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x04\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x05\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x06\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x07\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x08\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x09\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x0A\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x0B\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x0C\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x0D\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x0E\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x0F\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x10\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x20\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x40\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x7E\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x7F\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x80\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x81\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\xC0\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\xFE\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\xFF\x00\x00\x00\x00", 4},
    {"\x7E\xFF\xFF\xFF\x00\x00\x00\x00", 4},
    {"\x7F\xFF\xFF\xFF\x00\x00\x00\x00", 4},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x80\x00\x00\x01\x00\x00\x00\x00", 4},
    {"\xFF\xFF\xFF\xFE\x00\x00\x00\x00", 4},
    /* 4B - LE */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x01\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x02\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x03\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x04\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x05\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x06\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x07\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x08\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x09\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x0A\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x0B\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x0C\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x0D\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x0E\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x0F\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x10\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x20\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x40\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x7E\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x7F\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\x81\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\xC0\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\xFE\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\xFF\x00\x00\x00\x00\x00\x00\x00", 4},
    {"\xFF\xFF\xFF\x7E\x00\x00\x00\x00", 4},
    {"\xFF\xFF\xFF\x7F\x00\x00\x00\x00", 4},
    {"\x00\x00\x00\x80\x00\x00\x00\x00", 4},
    {"\x01\x00\x00\x80\x00\x00\x00\x00", 4},
    {"\xFE\xFF\xFF\xFF\x00\x00\x00\x00", 4},
    /* 8B - NE */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x01\x01\x01\x01\x01\x01\x01\x01", 8},
    {"\x80\x80\x80\x80\x80\x80\x80\x80", 8},
    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
    /* 8B - BE */
    {"\x00\x00\x00\x00\x00\x00\x00\x01", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x02", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x03", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x04", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x05", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x06", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x07", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x08", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x09", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x0A", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x0B", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x0C", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x0D", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x0E", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x0F", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x10", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x20", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x40", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x7E", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x7F", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x80", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x81", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\xC0", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\xFE", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\xFF", 8},
    {"\x7E\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
    {"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x80\x00\x00\x00\x00\x00\x00\x01", 8},
    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE", 8},
    /* 8B - LE */
    {"\x00\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x01\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x02\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x03\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x04\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x05\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x06\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x07\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x08\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x09\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x0A\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x0B\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x0C\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x0D\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x0E\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x0F\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x10\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x20\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x40\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x7E\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x7F\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x80\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\x81\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\xC0\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\xFE\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\xFF\x00\x00\x00\x00\x00\x00\x00", 8},
    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7E", 8},
    {"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 8},
    {"\x00\x00\x00\x00\x00\x00\x00\x80", 8},
    {"\x01\x00\x00\x00\x00\x00\x00\x80", 8},
    {"\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8},
};

static void mangle_Magic(run_t* run, bool printable) {
    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleMagicVals) - 1);
    mangle_UseValue(run, mangleMagicVals[choice].val, mangleMagicVals[choice].size, printable);
}

static void mangle_StaticDict(run_t* run, bool printable) {
    if (run->global->mutate.dictionaryCnt == 0) {
        mangle_Bytes(run, printable);
        return;
    }
    uint64_t choice = util_rndGet(0, run->global->mutate.dictionaryCnt - 1);
    mangle_UseValue(run, run->global->mutate.dictionary[choice].val,
        run->global->mutate.dictionary[choice].len, printable);
}

static inline const uint8_t* mangle_FeedbackDict(run_t* run, size_t* len) {
    if (!run->global->feedback.cmpFeedback) {
        return NULL;
    }
    cmpfeedback_t* cmpf = run->global->feedback.cmpFeedbackMap;
    uint32_t       cnt  = ATOMIC_GET(cmpf->cnt);
    if (cnt == 0) {
        return NULL;
    }
    if (cnt > ARRAYSIZE(cmpf->valArr)) {
        cnt = ARRAYSIZE(cmpf->valArr);
    }
    uint32_t choice = util_rndGet(0, cnt - 1);
    *len            = (size_t)ATOMIC_GET(cmpf->valArr[choice].len);
    if (*len == 0) {
        return NULL;
    }
    return cmpf->valArr[choice].val;
}

static void mangle_ConstFeedbackDict(run_t* run, bool printable) {
    size_t         len;
    const uint8_t* val = mangle_FeedbackDict(run, &len);
    if (val == NULL) {
        mangle_Bytes(run, printable);
        return;
    }
    mangle_UseValue(run, val, len, printable);
}

static void mangle_MemSet(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    size_t len = mangle_getLen(run->dynfile->size - off);
    int    val = printable ? (int)util_rndPrintable() : (int)util_rndGet(0, UINT8_MAX);

    if (util_rnd64() & 1) {
        len = mangle_Inflate(run, off, len, printable);
    }

    memset(&run->dynfile->data[off], val, len);
}

static void mangle_MemClr(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    size_t len = mangle_getLen(run->dynfile->size - off);
    int    val = printable ? ' ' : 0;

    if (util_rnd64() & 1) {
        len = mangle_Inflate(run, off, len, printable);
    }

    memset(&run->dynfile->data[off], val, len);
}

static void mangle_RandomBuf(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    size_t len = mangle_getLen(run->dynfile->size - off);

    if (util_rnd64() & 1) {
        len = mangle_Inflate(run, off, len, printable);
    }

    if (printable) {
        util_rndBufPrintable(&run->dynfile->data[off], len);
    } else {
        util_rndBuf(&run->dynfile->data[off], len);
    }
}

static inline void mangle_AddSubWithRange(
    run_t* run, size_t off, size_t varLen, uint64_t range, bool printable) {
    int64_t delta = (int64_t)util_rndGet(0, range * 2) - (int64_t)range;

    switch (varLen) {
    case 1: {
        run->dynfile->data[off] += delta;
        break;
    }
    case 2: {
        int16_t val;
        util_memcpyInline(&val, &run->dynfile->data[off], sizeof(val));
        if (util_rnd64() & 0x1) {
            val += delta;
        } else {
            /* Foreign endianess */
            val = __builtin_bswap16(val);
            val += delta;
            val = __builtin_bswap16(val);
        }
        mangle_Overwrite(run, off, (uint8_t*)&val, varLen, printable);
        break;
    }
    case 4: {
        int32_t val;
        util_memcpyInline(&val, &run->dynfile->data[off], sizeof(val));
        if (util_rnd64() & 0x1) {
            val += delta;
        } else {
            /* Foreign endianess */
            val = __builtin_bswap32(val);
            val += delta;
            val = __builtin_bswap32(val);
        }
        mangle_Overwrite(run, off, (uint8_t*)&val, varLen, printable);
        break;
    }
    case 8: {
        int64_t val;
        util_memcpyInline(&val, &run->dynfile->data[off], sizeof(val));
        if (util_rnd64() & 0x1) {
            val += delta;
        } else {
            /* Foreign endianess */
            val = __builtin_bswap64(val);
            val += delta;
            val = __builtin_bswap64(val);
        }
        mangle_Overwrite(run, off, (uint8_t*)&val, varLen, printable);
        break;
    }
    default: {
        LOG_F("Unknown variable length size: %zu", varLen);
    }
    }
}

static void mangle_AddSub(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);

    /* 1,2,4,8 */
    size_t varLen = 1U << util_rndGet(0, 3);
    if ((run->dynfile->size - off) < varLen) {
        varLen = 1;
    }

    /* Ranges relative to the width of the type */
    const uint64_t range8Bit  = 16;
    const uint64_t range16Bit = 4096;
    const uint64_t range32Bit = 1048576;
    const uint64_t range64Bit = 268435456;

    uint64_t range;
    switch (varLen) {
    case 1:
        range = range8Bit;
        break;
    case 2:
        range = range16Bit;
        break;
    case 4:
        range = range32Bit;
        break;
    case 8:
        range = range64Bit;
        break;
    default:
        LOG_F("Invalid operand size: %zu", varLen);
    }

    mangle_AddSubWithRange(run, off, varLen, range, printable);
}

static void mangle_IncByte(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    if (printable) {
        run->dynfile->data[off] = (run->dynfile->data[off] - 32 + 1) % 95 + 32;
    } else {
        run->dynfile->data[off] += (uint8_t)1UL;
    }
}

static void mangle_DecByte(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    if (printable) {
        run->dynfile->data[off] = (run->dynfile->data[off] - 32 + 94) % 95 + 32;
    } else {
        run->dynfile->data[off] -= (uint8_t)1UL;
    }
}

static void mangle_NegByte(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    if (printable) {
        run->dynfile->data[off] = 94 - (run->dynfile->data[off] - 32) + 32;
    } else {
        run->dynfile->data[off] = ~(run->dynfile->data[off]);
    }
}

static void mangle_Expand(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    size_t len;
    if (util_rnd64() % 16) {
        len = mangle_getLen(HF_MIN(16, run->global->mutate.maxInputSz - off));
    } else {
        len = mangle_getLen(run->global->mutate.maxInputSz - off);
    }

    mangle_Inflate(run, off, len, printable);
}

static void mangle_Shrink(run_t* run, bool printable HF_ATTR_UNUSED) {
    if (run->dynfile->size <= 2U) {
        return;
    }

    size_t off_start = mangle_getOffSet(run);
    size_t len       = mangle_LenLeft(run, off_start);
    if (len == 0) {
        return;
    }
    if (util_rnd64() % 16) {
        len = mangle_getLen(HF_MIN(16, len));
    } else {
        len = mangle_getLen(len);
    }
    size_t off_end     = off_start + len;
    size_t len_to_move = run->dynfile->size - off_end;

    mangle_Move(run, off_end, off_start, len_to_move);
    input_setSize(run, run->dynfile->size - len);
}

static void mangle_ASCIINum(run_t* run, bool printable) {
    size_t len = util_rndGet(2, 8);

    char buf[20];
    snprintf(buf, sizeof(buf), "%-19" PRId64, (int64_t)util_rnd64());

    mangle_UseValue(run, (const uint8_t*)buf, len, printable);
}

static void mangle_ASCIINumChange(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);

    /* Find a digit */
    for (; off < run->dynfile->size; off++) {
        if (isdigit(run->dynfile->data[off])) {
            break;
        }
    }
    size_t left = run->dynfile->size - off;
    if (left == 0) {
        return;
    }

    size_t   len = 0;
    uint64_t val = 0;
    /* 20 is maximum lenght of a string representing a 64-bit unsigned value */
    for (len = 0; (len < 20) && (len < left); len++) {
        char c = run->dynfile->data[off + len];
        if (!isdigit(c)) {
            break;
        }
        val *= 10;
        val += (c - '0');
    }

    enum { OP_INC = 0, OP_DEC, OP_MUL, OP_DIV, OP_RND, OP_ADD_RND, OP_SUB_RND, OP_NOT, OP_COUNT };

    switch (util_rndGet(0, OP_COUNT - 1)) {
    case OP_INC:
        val++;
        break;
    case OP_DEC:
        val--;
        break;
    case OP_MUL:
        val *= 2;
        break;
    case OP_DIV:
        val /= 2;
        break;
    case OP_RND:
        val = util_rnd64();
        break;
    case OP_ADD_RND:
        val += util_rndGet(1, 256);
        break;
    case OP_SUB_RND:
        val -= util_rndGet(1, 256);
        break;
    case OP_NOT:
        val = ~(val);
        break;
    default:
        LOG_F("Invalid choice");
    };

    char buf[64];
    snprintf(buf, sizeof(buf), "%" PRIu64, val);
    size_t new_len = strlen(buf);

    if (util_rnd64() & 1) {
        mangle_Insert(run, off, (const uint8_t*)buf, new_len, printable);
    } else {
        if (new_len == len) {
            mangle_Overwrite(run, off, (const uint8_t*)buf, new_len, printable);
        } else if (new_len > len) {
            mangle_Inflate(run, off + len, new_len - len, printable);
            mangle_Overwrite(run, off, (const uint8_t*)buf, new_len, printable);
        } else {
            mangle_Overwrite(run, off, (const uint8_t*)buf, new_len, printable);
            mangle_Move(run, off + len, off + new_len, run->dynfile->size - (off + len));
            input_setSize(run, run->dynfile->size - (len - new_len));
        }
    }
}

static void mangle_Splice(run_t* run, bool printable) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        mangle_Bytes(run, printable);
        return;
    }

    size_t         sz  = 0;
    const uint8_t* buf = input_getRandomInputAsBuf(run, &sz);
    if (!buf) {
        LOG_E("input_getRandomInputAsBuf() returned no input");
        mangle_Bytes(run, printable);
        return;
    }
    if (!sz) {
        mangle_Bytes(run, printable);
        return;
    }

    size_t remoteOff = mangle_getLen(sz) - 1;
    size_t len       = mangle_getLen(sz - remoteOff);
    mangle_UseValue(run, &buf[remoteOff], len, printable);
}

static void mangle_Resize(run_t* run, bool printable) {
    ssize_t oldsz = run->dynfile->size;
    ssize_t newsz = 0;

    /* Probability distribution (out of 32)
     *   0:     arbitrary size (1/32)
     *   1-4:   small increase (4/32)
     *   5:     large increase (1/32)
     *   6-9:   small decrease (4/32)
     *   10:    large decrease (1/32)
     *   11-32: no change (21/32)
     */
    uint64_t choice = util_rndGet(0, 32);
    switch (choice) {
    case 0: /* Set new size arbitrarily */
        newsz = (ssize_t)util_rndGet(1, run->global->mutate.maxInputSz);
        break;
    case 1 ... 4: /* Increase size by a small value */
        newsz = oldsz + (ssize_t)util_rndGet(0, 8);
        break;
    case 5: /* Increase size by a larger value */
        newsz = oldsz + (ssize_t)util_rndGet(9, 128);
        break;
    case 6 ... 9: /* Decrease size by a small value */
        newsz = oldsz - (ssize_t)util_rndGet(0, 8);
        break;
    case 10: /* Decrease size by a larger value */
        newsz = oldsz - (ssize_t)util_rndGet(9, 128);
        break;
    default: /* Do nothing */
        newsz = oldsz;
        break;
    }
    if (newsz < 1) {
        newsz = 1;
    }
    if (newsz > (ssize_t)run->global->mutate.maxInputSz) {
        newsz = run->global->mutate.maxInputSz;
    }

    input_setSize(run, (size_t)newsz);
    if (newsz > oldsz) {
        if (printable) {
            memset(&run->dynfile->data[oldsz], ' ', newsz - oldsz);
        }
    }
}

static void mangle_BlockRepeat(run_t* run, bool printable) {
    size_t off = mangle_getOffSet(run);
    size_t len = mangle_getLen(run->dynfile->size - off);

    len = HF_MIN(len, 1024);

    uint8_t* tmp = util_Malloc(len);
    defer {
        free(tmp);
    };
    memcpy(tmp, run->dynfile->data + off, len);

    size_t repeats = 0;
    /* 1/16 chance to repeat a LOT - useful for buffer overflows */
    if (util_rnd64() % 16 == 0) {
        repeats = util_rndGet(16, 256);
    } else {
        repeats = util_rndGet(1, 16);
    }

    size_t total_add = len * repeats;
    size_t added     = mangle_Inflate(run, off + len, total_add, printable);

    for (size_t i = 0; i < added; i += len) {
        size_t copy_len = HF_MIN(len, added - i);
        memcpy(run->dynfile->data + off + len + i, tmp, copy_len);
    }
}

static void mangle_BlockSwap(run_t* run, bool printable HF_ATTR_UNUSED) {
    if (run->dynfile->size < 8) return;

    size_t max_len = run->dynfile->size / 4;
    if (max_len < 1) return;
    size_t len = util_rndGet(1, HF_MIN(max_len, 256));

    size_t space = run->dynfile->size - len * 2;
    if (space < 1) return;

    size_t off1 = util_rndGet(0, space);
    size_t gap  = run->dynfile->size - off1 - len * 2;
    size_t off2 = off1 + len + (gap > 0 ? util_rndGet(0, gap) : 0);

    if (off2 + len > run->dynfile->size) return;

    uint8_t* tmp = util_Malloc(len);
    defer {
        free(tmp);
    };

    memcpy(tmp, run->dynfile->data + off1, len);
    memmove(run->dynfile->data + off1, run->dynfile->data + off2, len);
    memcpy(run->dynfile->data + off2, tmp, len);
}

static void mangle_CmpSolve(run_t* run, bool printable) {
    if (!run->global->feedback.cmpFeedback) {
        mangle_ConstFeedbackDict(run, printable);
        return;
    }

    cmpfeedback_t* cmpf = run->global->feedback.cmpFeedbackMap;
    uint32_t       cnt  = ATOMIC_GET(cmpf->cnt);
    if (cnt == 0) {
        mangle_Magic(run, printable);
        return;
    }

    if (cnt > ARRAYSIZE(cmpf->valArr)) {
        cnt = ARRAYSIZE(cmpf->valArr);
    }

    uint32_t choice  = util_rndGet(0, cnt - 1);
    size_t   cmp_len = (size_t)ATOMIC_GET(cmpf->valArr[choice].len);
    if (cmp_len == 0 || cmp_len > 32) {
        mangle_Magic(run, printable);
        return;
    }

    uint8_t cmp_val[32];
    memcpy(cmp_val, cmpf->valArr[choice].val, cmp_len);

    /* Find partial match in input */
    for (size_t off = 0; off + cmp_len <= run->dynfile->size; off++) {
        size_t matches = 0;
        for (size_t i = 0; i < cmp_len; i++) {
            if (run->dynfile->data[off + i] == cmp_val[i]) matches++;
        }

        if (matches > 0 && matches < cmp_len) {
            /* Gradient - 50% exact, 25% val+1, 25% val-1 */
            uint64_t r = util_rndGet(0, 3);
            if (r == 1 && cmp_len <= 8) {
                /* Increment as little-endian integer */
                for (size_t i = 0; i < cmp_len; i++) {
                    if (++cmp_val[i] != 0) break;
                }
            } else if (r == 2 && cmp_len <= 8) {
                /* Decrement as little-endian integer */
                for (size_t i = 0; i < cmp_len; i++) {
                    if (cmp_val[i]-- != 0) break;
                }
            }
            mangle_Overwrite(run, off, cmp_val, cmp_len, printable);
            return;
        }
    }

    mangle_UseValue(run, cmp_val, cmp_len, printable);
}

static void mangle_InterestingValues(run_t* run, bool printable) {
    static const struct {
        const uint8_t val[8];
        const size_t  len;
    } interestingVals[] = {
        /* 8-bit */
        {{0x00}, 1},
        {{0x01}, 1},
        {{0x7f}, 1},
        {{0x80}, 1},
        {{0xff}, 1},

        /* 16-bit */
        {{0x7f, 0xff}, 2},
        {{0x80, 0x00}, 2},
        {{0xff, 0xff}, 2},
        {{0x00, 0x01}, 2},
        {{0x00, 0x00}, 2},

        /* 32-bit */
        {{0x7f, 0xff, 0xff, 0xff}, 4},
        {{0x80, 0x00, 0x00, 0x00}, 4},
        {{0xff, 0xff, 0xff, 0xff}, 4},
        {{0x00, 0x00, 0x00, 0x01}, 4},
        {{0x00, 0x00, 0x00, 0x00}, 4},

        /* 64-bit */
        {{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 8},
        {{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 8},
        {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 8},
        {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 8},
        {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 8},
    };

    size_t choice = util_rndGet(0, ARRAYSIZE(interestingVals) - 1);
    mangle_UseValue(run, interestingVals[choice].val, interestingVals[choice].len, printable);
}

static void mangle_SpecialStrings(run_t* run, bool printable) {
    static const char* const strings[] = {
        /* Format strings */
        "%s",
        "%n",
        "%x",
        "%p",
        "%9999999s",
        "%08x",
        /* SQL Injection / Quote imbalance */
        "'",
        "\"",
        "`",
        "1=1",
        "--",
        "/*",
        "*/",
        " OR ",
        " AND ",
        "UNION SELECT",
        /* Path */
        "../",
        "..\\",
        "../../../../../../../../etc/passwd",
        "boot.ini",
        "/bin/sh",
        /* XML/HTML */
        "<",
        ">",
        "<script>",
        "javascript:",
        "CDATA",
        "<!--",
        "-->",
        /* JSON/Misc */
        "null",
        "true",
        "false",
        "NaN",
        "Infinity",
        "undefined",
        "{}",
        "[]",
        /* Command Injection */
        "|",
        ";",
        "`",
        "$(",
        "&&",
        "||",
        /* Terminator/Separators */
        "\n",
        "\r\n",
        "\x00",
        "\xff",
    };

    const char* val = strings[util_rndGet(0, ARRAYSIZE(strings) - 1)];
    mangle_UseValue(run, (const uint8_t*)val, strlen(val), printable);
}

static void mangle_ChunkShuffle(run_t* run, bool printable HF_ATTR_UNUSED) {
    if (run->dynfile->size < 8) return;

    size_t chunk_size = util_rndGet(1, 4);
    size_t num_chunks = run->dynfile->size / chunk_size;
    if (num_chunks < 2) return;

    size_t max_swaps = num_chunks / 2;
    if (max_swaps < 1) max_swaps = 1;
    size_t swaps = util_rndGet(1, max_swaps);
    for (size_t s = 0; s < swaps; s++) {
        size_t i = util_rndGet(0, num_chunks - 1);
        size_t j = util_rndGet(0, num_chunks - 1);
        if (i == j) continue;

        for (size_t k = 0; k < chunk_size; k++) {
            uint8_t tmp                            = run->dynfile->data[i * chunk_size + k];
            run->dynfile->data[i * chunk_size + k] = run->dynfile->data[j * chunk_size + k];
            run->dynfile->data[j * chunk_size + k] = tmp;
        }
    }
}

static void mangle_Arith8(run_t* run, bool printable) {
    size_t off              = mangle_getOffSet(run);
    int8_t delta            = (int8_t)util_rndGet(1, 35) * (util_rnd64() & 1 ? 1 : -1);
    run->dynfile->data[off] = (uint8_t)((int8_t)run->dynfile->data[off] + delta);
    if (printable) {
        util_turnToPrintable(&run->dynfile->data[off], 1);
    }
}

/*
 * TLV (Tag-Length-Value) mutation - detects length fields and mutates them
 * Common in binary protocols, ASN.1, network packets, file formats
 */
static void mangle_TlvMutate(run_t* run, bool printable) {
    if (run->dynfile->size < 4) {
        mangle_Bytes(run, printable);
        return;
    }

    /* Scan for potential length fields: byte that matches distance to some boundary */
    /* Limit scan to first 4KB or 10% of file to avoid O(N) penalty on large inputs */
    size_t scan_limit = HF_MIN(run->dynfile->size - 2, 4096);
    if (run->dynfile->size > 40960) {
        scan_limit = HF_MAX(scan_limit, run->dynfile->size / 10);
    }

    for (size_t off = 0; off < scan_limit; off++) {
        uint8_t  b1       = run->dynfile->data[off];
        uint16_t b2       = 0;
        size_t   len_size = 1;

        if (off + 1 < run->dynfile->size) {
            b2       = (uint16_t)run->dynfile->data[off] << 8 | run->dynfile->data[off + 1];
            len_size = 2;
        }

        /* Check if b1 or b2 could be a length field pointing within remaining data */
        size_t remaining = run->dynfile->size - off - 1;
        bool   found     = false;

        if (b1 > 0 && b1 <= remaining) {
            /* 1-byte length field candidate */
            found    = true;
            len_size = 1;
        } else if (len_size == 2 && b2 > 0 && b2 <= remaining && b2 < run->dynfile->size) {
            /* 2-byte length field candidate (big-endian) */
            found = true;
        }

        /* Found a candidate - mutate it with 1/8 probability */
        if (found && util_rnd64() % 8 == 0) {
            /* Mutate the length field */
            uint8_t mutations[] = {
                0x00,                              /* Zero length */
                0x01,                              /* Minimal */
                0x7f,                              /* Max signed byte */
                0x80,                              /* Min negative as signed */
                0xff,                              /* Max byte */
                (uint8_t)(remaining & 0xff),       /* Exact remaining */
                (uint8_t)((remaining + 1) & 0xff), /* Off by one */
                (uint8_t)((remaining * 2) & 0xff), /* Double */
            };
            uint8_t new_len         = mutations[util_rndGet(0, ARRAYSIZE(mutations) - 1)];
            run->dynfile->data[off] = new_len;
            if (printable) {
                util_turnToPrintable(&run->dynfile->data[off], 1);
            }
            return;
        }
    }

    /* Fallback: insert a TLV-like structure */
    uint8_t tlv[4] = {
        (uint8_t)util_rndGet(0, 255), /* Tag */
        (uint8_t)util_rndGet(1, 16),  /* Length */
        (uint8_t)util_rndGet(0, 255), /* Value byte 1 */
        (uint8_t)util_rndGet(0, 255), /* Value byte 2 */
    };
    mangle_UseValue(run, tlv, sizeof(tlv), printable);
}

/*
 * Token-based mutation - split on common delimiters and shuffle/modify tokens
 * Effective for text protocols, config files, command lines
 */
static void mangle_TokenShuffle(run_t* run, bool printable HF_ATTR_UNUSED) {
    if (run->dynfile->size < 4) return;

    /* Find delimiter positions */
    static const char delims[] = " \t\n\r,;:|/\\=&?";
    size_t            token_starts[64];
    size_t            token_cnt = 0;

    token_starts[token_cnt++] = 0;
    for (size_t i = 0; i < run->dynfile->size && token_cnt < ARRAYSIZE(token_starts) - 1; i++) {
        for (size_t d = 0; d < sizeof(delims) - 1; d++) {
            if (run->dynfile->data[i] == (uint8_t)delims[d]) {
                if (i + 1 < run->dynfile->size) {
                    token_starts[token_cnt++] = i + 1;
                }
                break;
            }
        }
    }

    if (token_cnt < 2) return;

    /* Swap two random tokens */
    size_t idx1 = util_rndGet(0, token_cnt - 2);
    size_t idx2 = util_rndGet(idx1 + 1, token_cnt - 1);

    size_t start1 = token_starts[idx1];
    size_t end1   = token_starts[idx1 + 1];
    size_t start2 = token_starts[idx2];
    size_t end2   = (idx2 + 1 < token_cnt) ? token_starts[idx2 + 1] : run->dynfile->size;

    size_t len1 = end1 - start1;
    size_t len2 = end2 - start2;

    if (len1 == 0 || len2 == 0 || len1 > 256 || len2 > 256) return;

    /* Simple swap: copy both tokens, then write back swapped */
    uint8_t* tmp1 = util_Malloc(len1);
    defer {
        free(tmp1);
    };
    uint8_t* tmp2 = util_Malloc(len2);
    defer {
        free(tmp2);
    };

    memcpy(tmp1, &run->dynfile->data[start1], len1);
    memcpy(tmp2, &run->dynfile->data[start2], len2);

    /* If same length, simple swap */
    if (len1 == len2) {
        memcpy(&run->dynfile->data[start1], tmp2, len2);
        memcpy(&run->dynfile->data[start2], tmp1, len1);
    }
    /* Different lengths - move middle block then insert tokens */
    else {
        /*
         * Layout: [Prefix][Token1][Middle][Token2][Suffix]
         * Want:   [Prefix][Token2][Middle][Token1][Suffix]
         *
         * 1. Copy Token2 to Start1
         * 2. Move Middle from End1 to Start1+Len2
         * 3. Copy Token1 to Start1+Len2+MiddleLen
         */

        size_t mid_len = start2 - end1;

        /* Step 2: Move Middle first (using memmove for safety) */
        /* Dest: start1 + len2. Src: end1 (which is start1+len1). Len: mid_len */
        memmove(&run->dynfile->data[start1 + len2], &run->dynfile->data[end1], mid_len);

        /* Step 1: Copy Token2 */
        memcpy(&run->dynfile->data[start1], tmp2, len2);

        /* Step 3: Copy Token1 */
        /* Dest: start1 + len2 + mid_len */
        memcpy(&run->dynfile->data[start1 + len2 + mid_len], tmp1, len1);
    }
}

/*
 * Gradient-guided CMP mutation - focus mutations on bytes that differ in comparisons
 */
static void mangle_GradientCmp(run_t* run, bool printable) {
    if (!run->global->feedback.cmpFeedback) {
        mangle_Bytes(run, printable);
        return;
    }

    cmpfeedback_t* cmpf = run->global->feedback.cmpFeedbackMap;
    uint32_t       cnt  = ATOMIC_GET(cmpf->cnt);
    if (cnt == 0) {
        mangle_Magic(run, printable);
        return;
    }

    if (cnt > ARRAYSIZE(cmpf->valArr)) {
        cnt = ARRAYSIZE(cmpf->valArr);
    }

    uint32_t choice  = util_rndGet(0, cnt - 1);
    size_t   cmp_len = (size_t)ATOMIC_GET(cmpf->valArr[choice].len);
    if (cmp_len == 0 || cmp_len > 32) {
        mangle_Magic(run, printable);
        return;
    }

    uint8_t cmp_val[32];
    memcpy(cmp_val, cmpf->valArr[choice].val, cmp_len);

    /* Find partial match and identify differing bytes */
    for (size_t off = 0; off + cmp_len <= run->dynfile->size; off++) {
        size_t  matches    = 0;
        size_t  first_diff = cmp_len;
        uint8_t diff_mask  = 0;

        for (size_t i = 0; i < cmp_len; i++) {
            if (run->dynfile->data[off + i] == cmp_val[i]) {
                matches++;
            } else if (first_diff == cmp_len) {
                first_diff = i;
                diff_mask  = run->dynfile->data[off + i] ^ cmp_val[i];
            }
        }

        /* If we have partial progress, focus on the differing byte */
        if (matches > 0 && matches < cmp_len && first_diff < cmp_len) {
            size_t target_off = off + first_diff;

            /* Gradient strategies */
            uint64_t strategy = util_rndGet(0, 5);
            switch (strategy) {
            case 0: /* Set to expected value */
                run->dynfile->data[target_off] = cmp_val[first_diff];
                break;
            case 1: /* Flip differing bits */
                run->dynfile->data[target_off] ^= diff_mask;
                break;
            case 2: /* Increment toward target */
                if (run->dynfile->data[target_off] < cmp_val[first_diff]) {
                    run->dynfile->data[target_off]++;
                } else {
                    run->dynfile->data[target_off]--;
                }
                break;
            case 3: /* Binary search toward target */
                run->dynfile->data[target_off] =
                    (run->dynfile->data[target_off] + cmp_val[first_diff]) / 2;
                break;
            case 4: /* Set entire comparison value */
                mangle_Overwrite(run, off, cmp_val, cmp_len, printable);
                return;
            case 5: /* Flip single bit in differing byte */
                run->dynfile->data[target_off] ^= (1U << util_rndGet(0, 7));
                break;
            }

            if (printable) {
                util_turnToPrintable(&run->dynfile->data[target_off], 1);
            }
            return;
        }
    }

    /* No partial match found - insert the value */
    mangle_UseValue(run, cmp_val, cmp_len, printable);
}

/*
 * Arithmetic mutations on discovered constants from CMP feedback
 */
static void mangle_ArithConst(run_t* run, bool printable) {
    if (!run->global->feedback.cmpFeedback) {
        mangle_AddSub(run, printable);
        return;
    }

    cmpfeedback_t* cmpf = run->global->feedback.cmpFeedbackMap;
    uint32_t       cnt  = ATOMIC_GET(cmpf->cnt);
    if (cnt == 0) {
        mangle_AddSub(run, printable);
        return;
    }

    if (cnt > ARRAYSIZE(cmpf->valArr)) {
        cnt = ARRAYSIZE(cmpf->valArr);
    }

    uint32_t choice  = util_rndGet(0, cnt - 1);
    size_t   val_len = (size_t)ATOMIC_GET(cmpf->valArr[choice].len);
    if (val_len == 0 || val_len > 8) {
        mangle_AddSub(run, printable);
        return;
    }

    /* Extract value as integer */
    uint64_t val = 0;
    for (size_t i = 0; i < val_len; i++) {
        val |= ((uint64_t)cmpf->valArr[choice].val[i]) << (i * 8);
    }

    /* Apply arithmetic mutation */
    uint64_t op = util_rndGet(0, 7);
    switch (op) {
    case 0:
        val += 1;
        break;
    case 1:
        val -= 1;
        break;
    case 2:
        val *= 2;
        break;
    case 3:
        val /= 2;
        break;
    case 4:
        val ^= 0xff;
        break; /* Flip low byte */
    case 5:
        val = ~val;
        break; /* Bitwise NOT */
    case 6:
        val = __builtin_bswap64(val) >> ((8 - val_len) * 8);
        break; /* Byte swap */
    case 7:
        val += util_rndGet(1, 256);
        break;
    }

    /* Convert back to bytes */
    uint8_t result[8];
    for (size_t i = 0; i < val_len; i++) {
        result[i] = (uint8_t)(val >> (i * 8));
    }

    mangle_UseValue(run, result, val_len, printable);
}

/*
 * Havoc mode - used when fuzzing is stagnating to escape local minima
 */
static void mangle_Havoc(run_t* run, bool printable) {
    /* Number of mutations: 16-128 */
    size_t num_mutations = util_rndGet(16, 128);

    for (size_t i = 0; i < num_mutations; i++) {
        /* Pick a random simple mutation */
        uint64_t choice = util_rndGet(0, 15);
        switch (choice) {
        case 0:
            mangle_Bit(run, printable);
            break;
        case 1:
            mangle_IncByte(run, printable);
            break;
        case 2:
            mangle_DecByte(run, printable);
            break;
        case 3:
            mangle_NegByte(run, printable);
            break;
        case 4:
            mangle_Bytes(run, printable);
            break;
        case 5:
            mangle_Magic(run, printable);
            break;
        case 6:
            mangle_AddSub(run, printable);
            break;
        case 7:
            mangle_MemSet(run, printable);
            break;
        case 8:
            mangle_MemSwap(run, printable);
            break;
        case 9:
            mangle_MemCopy(run, printable);
            break;
        case 10:
            mangle_Expand(run, printable);
            break;
        case 11:
            mangle_Shrink(run, printable);
            break;
        case 12:
            mangle_Arith8(run, printable);
            break;
        case 13:
            mangle_BlockMove(run, printable);
            break;
        case 14:
            mangle_ByteRepeat(run, printable);
            break;
        case 15:
            mangle_RandomBuf(run, printable);
            break;
        }
    }
}

static void mangle_CrossOver(run_t* run, bool printable) {
    if (run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE) {
        mangle_Bytes(run, printable);
        return;
    }

    if (run->dynfile->size < 2) {
        mangle_Bytes(run, printable);
        return;
    }

    /* Use diverse input selection for better coverage combination */
    size_t         other_sz = 0;
    const uint8_t* other    = input_getDiverseInputAsBuf(run, &other_sz);
    if (!other || other_sz == 0) {
        mangle_Bytes(run, printable);
        return;
    }

    size_t crossover_point = util_rndGet(1, run->dynfile->size - 1);
    size_t other_point     = util_rndGet(0, other_sz - 1);
    size_t copy_len        = HF_MIN(run->dynfile->size - crossover_point, other_sz - other_point);

    if (copy_len > 0) {
        mangle_Overwrite(run, crossover_point, &other[other_point], copy_len, printable);
    }
}

/*
 * Mutation scheduling
 */

typedef enum { TIER_DATA = 0, TIER_ARITH = 1, TIER_SPLICE = 2, TIER_OTHER = 3 } tier_t;

/* Mutation tier arrays - shared between picker and stagnation booster */
static const mangle_t tierData[] = {
    MANGLE_INTERESTING_VALUES,
    MANGLE_MAGIC,
    MANGLE_STATIC_DICT,
    MANGLE_CONST_FEEDBACK_DICT,
    MANGLE_CMP_SOLVE,
    MANGLE_SPECIAL_STRINGS,
    MANGLE_GRADIENT_CMP,
    MANGLE_ARITH_CONST,
};

static const mangle_t tierArith[] = {
    MANGLE_BIT,
    MANGLE_INC_BYTE,
    MANGLE_DEC_BYTE,
    MANGLE_NEG_BYTE,
    MANGLE_ADD_SUB,
    MANGLE_ARITH8,
};

static const mangle_t tierSplice[] = {MANGLE_SPLICE, MANGLE_CROSS_OVER};

static const mangle_t tierStructure[] = {
    MANGLE_CHUNK_SHUFFLE,
    MANGLE_BLOCK_REPEAT,
    MANGLE_BLOCK_SWAP,
    MANGLE_BLOCK_MOVE,
    MANGLE_TLV_MUTATE,
    MANGLE_TOKEN_SHUFFLE,
};

static inline mangle_t mangle_pickFromList(const mangle_t* list, size_t cnt) {
    return cnt > 0 ? list[util_rndGet(0, cnt - 1)] : (mangle_t)util_rndGet(0, MANGLE_COUNT - 1);
}

static inline mangle_t mangle_sanitize(run_t* run, mangle_t m) {
    if ((unsigned)m >= MANGLE_COUNT) {
        return (mangle_t)util_rndGet(0, MANGLE_COUNT - 1);
    }

    static const struct {
        const uint8_t  needs;
        const mangle_t fallback;
    } reqs[MANGLE_COUNT] = {
        [MANGLE_STATIC_DICT]         = {1, MANGLE_MAGIC},
        [MANGLE_CONST_FEEDBACK_DICT] = {2, MANGLE_MAGIC},
        [MANGLE_CMP_SOLVE]           = {2, MANGLE_MAGIC},
        [MANGLE_SPLICE]              = {4, MANGLE_RANDOM_BUF},
        [MANGLE_CROSS_OVER]          = {4, MANGLE_BYTES},
        [MANGLE_GRADIENT_CMP]        = {2, MANGLE_MAGIC},
        [MANGLE_ARITH_CONST]         = {2, MANGLE_ADD_SUB},
    };

    uint8_t need = reqs[m].needs;
    if (!need) return m;

    if ((need & 1) && run->global->mutate.dictionaryCnt == 0) return reqs[m].fallback;
    if ((need & 2) && !run->global->feedback.cmpFeedback) return reqs[m].fallback;
    if ((need & 4) && run->global->feedback.dynFileMethod == _HF_DYNFILE_NONE)
        return reqs[m].fallback;

    return m;
}

static mangle_t mangle_pickWeighted(run_t* run, uint8_t* tier_out) {
    /*
     * Adaptive weights - start with defaults, adjust based on success rate.
     * Use a simplified momentum-like approach where recent success bumps the weight
     */
    uint8_t w[4] = {40, 25, 20, 15};

    for (int i = 0; i < 4; i++) {
        uint64_t tries = ATOMIC_GET(run->global->mutate.stats[i].tries);
        if (tries < 500) {
            continue; /* Not enough data yet */
        }

        uint64_t hits = ATOMIC_GET(run->global->mutate.stats[i].successes);
        uint64_t rate = (hits * 10000) / tries; /* x10000 for precision */

        /*
         * Baseline success rate is low (fuzzing is hard), so even small rates are good.
         * Adjust weights proportionally to performance relative to others.
         */
        if (rate > 50) {                  /* > 0.5% success rate is very good. */
            w[i] = HF_MIN(w[i] + 15, 90); /* Increased boost. */
        } else if (rate > 10) {           /* > 0.1% */
            w[i] = HF_MIN(w[i] + 5, 70);
        } else if (rate < 1) { /* < 0.01% */
            w[i] = HF_MAX(w[i] / 2, 5);
        }
    }

    /* Roll weighted random */
    uint16_t sum  = w[0] + w[1] + w[2] + w[3];
    uint8_t  roll = util_rndGet(0, sum - 1);

    mangle_t choice;
    uint8_t  tier;

    if (roll < w[0]) {
        choice = mangle_pickFromList(tierData, ARRAYSIZE(tierData));
        tier   = TIER_DATA;
    } else if (roll < w[0] + w[1]) {
        choice = mangle_pickFromList(tierArith, ARRAYSIZE(tierArith));
        tier   = TIER_ARITH;
    } else if (roll < w[0] + w[1] + w[2]) {
        choice = mangle_pickFromList(tierSplice, ARRAYSIZE(tierSplice));
        tier   = TIER_SPLICE;
    } else {
        choice = (mangle_t)util_rndGet(0, MANGLE_COUNT - 1);
        tier   = TIER_OTHER;
    }

    *tier_out = tier;
    return mangle_sanitize(run, choice);
}

/* Dispatch table - enum -> function pointer */
static void (*const mangleFuncs[MANGLE_COUNT])(run_t*, bool) = {
    [MANGLE_SHRINK]              = mangle_Shrink,
    [MANGLE_EXPAND]              = mangle_Expand,
    [MANGLE_BIT]                 = mangle_Bit,
    [MANGLE_INC_BYTE]            = mangle_IncByte,
    [MANGLE_DEC_BYTE]            = mangle_DecByte,
    [MANGLE_NEG_BYTE]            = mangle_NegByte,
    [MANGLE_ADD_SUB]             = mangle_AddSub,
    [MANGLE_ARITH8]              = mangle_Arith8,
    [MANGLE_MEM_SET]             = mangle_MemSet,
    [MANGLE_MEM_CLR]             = mangle_MemClr,
    [MANGLE_MEM_SWAP]            = mangle_MemSwap,
    [MANGLE_MEM_COPY]            = mangle_MemCopy,
    [MANGLE_BLOCK_MOVE]          = mangle_BlockMove,
    [MANGLE_BLOCK_REPEAT]        = mangle_BlockRepeat,
    [MANGLE_BLOCK_SWAP]          = mangle_BlockSwap,
    [MANGLE_CHUNK_SHUFFLE]       = mangle_ChunkShuffle,
    [MANGLE_BYTES]               = mangle_Bytes,
    [MANGLE_BYTE_REPEAT]         = mangle_ByteRepeat,
    [MANGLE_RANDOM_BUF]          = mangle_RandomBuf,
    [MANGLE_INTERESTING_VALUES]  = mangle_InterestingValues,
    [MANGLE_ASCII_NUM]           = mangle_ASCIINum,
    [MANGLE_ASCII_NUM_CHANGE]    = mangle_ASCIINumChange,
    [MANGLE_MAGIC]               = mangle_Magic,
    [MANGLE_STATIC_DICT]         = mangle_StaticDict,
    [MANGLE_CONST_FEEDBACK_DICT] = mangle_ConstFeedbackDict,
    [MANGLE_CMP_SOLVE]           = mangle_CmpSolve,
    [MANGLE_SPLICE]              = mangle_Splice,
    [MANGLE_CROSS_OVER]          = mangle_CrossOver,
    [MANGLE_SPECIAL_STRINGS]     = mangle_SpecialStrings,
    [MANGLE_TLV_MUTATE]          = mangle_TlvMutate,
    [MANGLE_TOKEN_SHUFFLE]       = mangle_TokenShuffle,
    [MANGLE_GRADIENT_CMP]        = mangle_GradientCmp,
    [MANGLE_ARITH_CONST]         = mangle_ArithConst,
    [MANGLE_HAVOC]               = mangle_Havoc,
};

static inline void mangle_dispatch(run_t* run, mangle_t m, bool printable) {
    mangleFuncs[mangle_sanitize(run, m)](run, printable);
}

void mangle_mangleContent(run_t* run) {
    if (run->mutationsPerRun == 0U) {
        return;
    }

    bool printable = run->global->cfg.only_printable;

    if (run->dynfile->size == 0U) {
        mangle_Resize(run, printable);
    }

    time_t   stagnation = time(NULL) - ATOMIC_GET(run->global->timing.lastCovUpdate);
    uint64_t base       = run->mutationsPerRun;
    bool     haveCmp    = run->global->feedback.cmpFeedback;

    run->mutationTiers = 0;

    const time_t timeStagnated = 10;
    const time_t timeStuck     = 60;
    const time_t timeGivenUp   = 300;

    /* Scale mutation count with stagnation */
    uint8_t mult = 1, cap = 16, min = 1;
    if (stagnation > timeGivenUp) {
        mult = 4;
        cap  = 64;
        min  = 2;
    } else if (stagnation > timeStuck) {
        mult = 2;
        cap  = 32;
    }

    uint64_t count = util_rndGet(min, HF_MIN(base * mult, cap));

    /*
     * Extra mutations when stagnating.
     * If we are stuck, we want to try more specific strategies (dictionaries, splices)
     */
    if (stagnation > timeStagnated) {
        if (haveCmp && util_rnd64() % 3 == 0) {
            run->mutationTiers |= (1 << TIER_DATA);
            mangle_dispatch(run, MANGLE_CMP_SOLVE, printable);
        }
        if (util_rnd64() % 2 == 0) {
            run->mutationTiers |= (1 << TIER_SPLICE);
            mangle_dispatch(run, MANGLE_SPLICE, printable);
        }
        /* Try gradient-guided CMP mutations */
        if (haveCmp && util_rnd64() % 4 == 0) {
            run->mutationTiers |= (1 << TIER_DATA);
            mangle_dispatch(run, MANGLE_GRADIENT_CMP, printable);
        }
    }
    if (stagnation > timeStuck && util_rnd64() % 3 == 0) {
        run->mutationTiers |= (1 << TIER_SPLICE);
        mangle_dispatch(run, MANGLE_CROSS_OVER, printable);
    }
    if (stagnation > timeGivenUp && util_rnd64() % 8 == 0) {
        run->mutationTiers |= (1 << TIER_OTHER);
        mangle_dispatch(
            run, mangle_pickFromList(tierStructure, ARRAYSIZE(tierStructure)), printable);
    }
    /* Havoc mode - when extremely stuck, go wild */
    if (stagnation > timeGivenUp * 2 && util_rnd64() % 16 == 0) {
        run->mutationTiers |= (1 << TIER_OTHER);
        mangle_dispatch(run, MANGLE_HAVOC, printable);
        return; /* Havoc does many mutations internally */
    }

    /* Main mutation loop */
    for (uint64_t i = 0; i < count; i++) {
        uint8_t  tier;
        mangle_t m = mangle_pickWeighted(run, &tier);

        /*
         * Boost data mutations when stagnating - if stuck for >30s,
         * 25% chance to force a data mutation (dictionaries, magic values)
         */
        if (stagnation > (timeStuck / 2) && util_rnd64() % 4 == 0) {
            m    = mangle_sanitize(run, mangle_pickFromList(tierData, ARRAYSIZE(tierData)));
            tier = TIER_DATA;
        }

        run->mutationTiers |= (1 << tier);
        ATOMIC_POST_INC(run->global->mutate.stats[tier].tries);
        mangle_dispatch(run, m, printable);
    }
}
