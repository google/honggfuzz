/*
 *
 * honggfuzz - Intel PT decoder
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2016 by Google Inc. All Rights Reserved.
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

#include "../common.h"
#include "pt.h"

#include <linux/perf_event.h>
#include <inttypes.h>

#include "../log.h"
#include "../util.h"

#ifdef _HF_LINUX_INTEL_PT_LIB

#include <intel-pt.h>

/*
 * Copyright (c) 2013-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Keeping track of the last-ip in Intel PT packets. */
struct pt_last_ip {
    /* The last IP. */
    uint64_t ip;

    /* Flags governing the handling of IP updates and queries:
     *
     * - we have seen an IP update.
     */
    uint32_t have_ip:1;
    /* - the IP has been suppressed in the last update. */
    uint32_t suppressed:1;
};

inline static void pt_last_ip_init(struct pt_last_ip *last_ip)
{
    if (!last_ip)
        return;

    last_ip->ip = 0ull;
    last_ip->have_ip = 0;
    last_ip->suppressed = 0;
}

inline static int pt_last_ip_query(uint64_t * ip, const struct pt_last_ip *last_ip)
{
    if (!last_ip)
        return -pte_invalid;

    if (!last_ip->have_ip) {
        if (ip)
            *ip = 0ull;
        return -pte_noip;
    }

    if (last_ip->suppressed) {
        if (ip)
            *ip = 0ull;
        return -pte_ip_suppressed;
    }

    if (ip)
        *ip = last_ip->ip;

    return 0;
}

/* Sign-extend a uint64_t value. */
inline static uint64_t sext(uint64_t val, uint8_t sign)
{
    uint64_t signbit, mask;

    signbit = 1ull << (sign - 1);
    mask = ~0ull << sign;

    return val & signbit ? val | mask : val & ~mask;
}

inline static int pt_last_ip_update_ip(struct pt_last_ip *last_ip,
                                       const struct pt_packet_ip *packet,
                                       const struct pt_config *config)
{
    (void)config;

    if (!last_ip || !packet)
        return -pte_invalid;

    switch (packet->ipc) {
    case pt_ipc_suppressed:
        last_ip->suppressed = 1;
        return 0;

    case pt_ipc_sext_48:
        last_ip->ip = sext(packet->ip, 48);
        last_ip->have_ip = 1;
        last_ip->suppressed = 0;
        return 0;

    case pt_ipc_update_16:
        last_ip->ip = (last_ip->ip & ~0xffffull)
            | (packet->ip & 0xffffull);
        last_ip->have_ip = 1;
        last_ip->suppressed = 0;
        return 0;

    case pt_ipc_update_32:
        last_ip->ip = (last_ip->ip & ~0xffffffffull)
            | (packet->ip & 0xffffffffull);
        last_ip->have_ip = 1;
        last_ip->suppressed = 0;
        return 0;

    case pt_ipc_update_48:
        last_ip->ip = (last_ip->ip & ~0xffffffffffffull)
            | (packet->ip & 0xffffffffffffull);
        last_ip->have_ip = 1;
        last_ip->suppressed = 0;
        return 0;

    case pt_ipc_full:
        last_ip->ip = packet->ip;
        last_ip->have_ip = 1;
        last_ip->suppressed = 0;
        return 0;
    }

    return -pte_bad_packet;
}

inline static void perf_ptAnalyzePkt(honggfuzz_t * hfuzz, fuzzer_t * fuzzer,
                                     struct pt_packet *packet, struct pt_config *ptc,
                                     struct pt_last_ip *last_ip)
{
    switch (packet->type) {
    case ppt_tip:
    case ppt_fup:
    case ppt_tip_pge:
    case ppt_tip_pgd:
        break;
    default:
        return;
    }

    int errcode = pt_last_ip_update_ip(last_ip, &(packet->payload.ip), ptc);
    if (errcode < 0) {
        LOG_F("pt_last_ip_update_ip() failed: %s", pt_errstr(errcode));
    }

    /* Update only on TIP, other packets don't indicate a branch */
    if (packet->type == ppt_tip) {
        uint64_t ip;
        errcode = pt_last_ip_query(&ip, last_ip);
        if (errcode == 0) {
            ip &= _HF_PERF_BITMAP_BITSZ_MASK;
            register uint8_t prev = ATOMIC_BTS(hfuzz->feedback->bbMapPc, ip);
            if (!prev) {
                fuzzer->linux.hwCnts.newBBCnt++;
            }
        }
    }
    return;
}

void arch_ptAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    struct perf_event_mmap_page *pem = (struct perf_event_mmap_page *)fuzzer->linux.perfMmapBuf;

    uint64_t aux_tail = ATOMIC_GET(pem->aux_tail);
    uint64_t aux_head = ATOMIC_GET(pem->aux_head);

    struct pt_config ptc;
    pt_config_init(&ptc);
    ptc.begin = &fuzzer->linux.perfMmapAux[aux_tail];
    ptc.end = &fuzzer->linux.perfMmapAux[aux_head - 1];

    int errcode = pt_cpu_errata(&ptc.errata, &ptc.cpu);
    if (errcode < 0) {
        LOG_F("pt_errata() failed: %s", pt_errstr(errcode));
    }

    struct pt_packet_decoder *ptd = pt_pkt_alloc_decoder(&ptc);
    if (ptd == NULL) {
        LOG_F("pt_pkt_alloc_decoder() failed");
    }
    defer {
        pt_pkt_free_decoder(ptd);
    };

    errcode = pt_pkt_sync_forward(ptd);
    if (errcode < 0) {
        LOG_W("pt_pkt_sync_forward() failed: %s", pt_errstr(errcode));
        return;
    }

    struct pt_last_ip last_ip;
    pt_last_ip_init(&last_ip);
    for (;;) {
        struct pt_packet packet;
        errcode = pt_pkt_next(ptd, &packet, sizeof(packet));
        if (errcode == -pte_eos) {
            break;
        }
        if (errcode < 0) {
            LOG_W("pt_pkt_next() failed: %s", pt_errstr(errcode));
            break;
        }
        perf_ptAnalyzePkt(hfuzz, fuzzer, &packet, &ptc, &last_ip);
    }
}

#else                           /* _HF_LINUX_INTEL_PT_LIB */

void arch_ptAnalyze(honggfuzz_t * hfuzz UNUSED, fuzzer_t * fuzzer UNUSED)
{
    LOG_F
        ("The program has not been linked against the Intel's Processor Trace Library (libipt.so)");
}

#endif                          /* _HF_LINUX_INTEL_PT_LIB */
