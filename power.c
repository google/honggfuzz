/*
 *
 * honggfuzz - power schedule calculation
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2025 by Google Inc. All Rights Reserved.
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

#include "power.h"

#include <time.h>

#include "libhfcommon/common.h"
#include "libhfcommon/util.h"

/*
 * 0 = no entropy (single byte value), 100 = maximum entropy (uniform distribution).
 * Approximation of Shannon entropy.
 */
static unsigned power_ComputeEntropy(const uint8_t* data, size_t len) {
    if (len == 0) {
        return 0;
    }

    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    /* Count unique bytes and find max count */
    unsigned unique = 0;
    uint32_t maxCnt = 0;
    for (unsigned i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            unique++;
            if (counts[i] > maxCnt) {
                maxCnt = counts[i];
            }
        }
    }

    if (unique <= 1) {
        return 0;
    }

    /*
     * * log2(unique) gives theoretical max entropy for this alphabet (0-8)
     * * Uniformity factor penalizes skewed distributions
     * Scaled to 0-100 range.
     */
    unsigned log2_unique = util_Log2(unique); /* 1-8 for unique 2-256 */
    unsigned log2_len    = len > 1 ? util_Log2(len) : 1;

    /* Uniformity: ratio of average count to max count (scaled by 100) */
    uint32_t avgCnt     = (uint32_t)(len / unique);
    unsigned uniformity = (avgCnt * 100) / maxCnt; /* 0-100, higher = more uniform */

    /* Combine: entropy_score = log2(unique) * uniformity / 8 */
    /* log2_unique is 0-8, uniformity is 0-100, result scaled to 0-100 */
    unsigned entropy = (log2_unique * uniformity) / 8;

    /* Boost if we're using a good portion of the alphabet relative to length */
    if (log2_unique >= log2_len && log2_len > 0) {
        entropy = HF_MIN(entropy + 10, 100);
    }

    return HF_MIN(entropy, 100);
}

uint64_t power_calculateEnergy(run_t* run, dynfile_t* dynfile) {
    const uint64_t energyMax     = 32768;
    const time_t   freshTimeSec  = 60;
    const time_t   recentTimeSec = 300;
    const time_t   staleTimeSec  = 3600;

    uint64_t energy = POWER_BASE_ENERGY;
    time_t   now    = time(NULL);

    /* Phase-aware energy - dry-run phase explores more, main phase exploits */
    fuzzState_t phase = run->global->feedback.state;
    if (phase == _HF_STATE_DYNAMIC_DRY_RUN) {
        /* During dry-run, favor smaller/faster inputs for quick exploration */
        if (dynfile->size < 256) {
            energy = (energy * 3) / 2;
        }
    }

    /*
     * Novelty - inputs that discovered new edges explore unknown territory.
     * Decay novelty bonus over time - edges discovered 10+ minutes ago are less novel.
     */
    if (dynfile->newEdges > 0) {
        time_t   age_mins = (now - dynfile->timeAdded) / 60;
        uint32_t decay    = (age_mins < 10) ? 0 : HF_MIN(age_mins / 10, 6);
        uint32_t boost    = HF_MIN(dynfile->newEdges, 8);
        if (boost > decay) {
            energy <<= (boost - decay);
        }
    }

    /* Density - inputs with high coverage per byte are efficient */
    if (dynfile->size > 0 && dynfile->cov[0] > 0) {
        /* coverage / size * 100 */
        uint64_t density = (dynfile->cov[0] * 100) / dynfile->size;
        /* Heuristic - >50% instructions/bytes is good (small dense loops), >200% is amazing */
        if (density > 50) energy = (energy * 3) / 2;
        if (density > 200) energy <<= 1;
    }

    /* Speed - faster inputs allow more mutations per second */
    uint64_t mutations = ATOMIC_GET(run->global->cnts.mutationsCnt);
    if (mutations > 0) {
        uint64_t elapsed   = (uint64_t)(now - run->global->timing.timeStart);
        uint64_t avg_usecs = elapsed > 0 ? (elapsed * 1000000ULL) / mutations : 1000;
        avg_usecs          = HF_CAP(avg_usecs, 100ULL, 10000000ULL);

        uint64_t exec_usecs  = HF_CAP(dynfile->timeExecUSecs, 100ULL, 10000000ULL);
        uint64_t speed_ratio = HF_CAP((avg_usecs * 16) / exec_usecs, 1ULL, 256ULL);
        energy               = (energy * speed_ratio) / 16;
    }

    /* Fertility - inputs that produced children are in promising regions */
    uint32_t refs = ATOMIC_GET(dynfile->refs);
    if (refs > 0) {
        /* Logarithmic boost for fertility */
        energy = (energy * (8 + HF_MIN(util_Log2(refs + 1), 8))) / 8;
    }

    /* Freshness - time-based, newer inputs haven't been fully explored */
    time_t age_secs = now - dynfile->timeAdded;
    if (age_secs < freshTimeSec) {
        energy <<= 2; /* added in last 60s - 4x */
    } else if (age_secs < recentTimeSec) {
        energy <<= 1; /* added in last 5 minutes - 2x */
    } else if (age_secs > staleTimeSec && refs == 0) {
        energy >>= 1; /* older than 60 min with no children - 0.5x */
    }

    /* Size - smaller inputs are faster and easier to analyze */
    if (dynfile->size > 1024) {
        uint32_t log_size = util_Log2(dynfile->size);
        if (log_size > 10) energy >>= HF_MIN(log_size - 10, 4);
    }

    /*
     * Stack depth - deeper execution paths suggest complex logic/recursion.
     * Boost energy for inputs causing deep stack usage.
     */
    if (dynfile->stackDepth > (1024 * 16)) { /* > 16KB */
        uint32_t stack_log = util_Log2(dynfile->stackDepth / 1024);
        if (stack_log > 4) {
            /* Boost factor - 16KB->1x, 32KB->1.5x, 64KB->2x, 1MB->4x */
            energy = (energy * HF_MIN(stack_log - 2, 8)) / 2;
        }
    }

    /* Execution path diversity - boost inputs with unique execution paths */
    if (dynfile->pathHash != 0) {
        uint64_t uniquePaths = ATOMIC_GET(run->global->feedback.uniquePaths);
        if (uniquePaths > 0 && uniquePaths < 1000) {
            /* More boost when we have fewer unique paths (early exploration) */
            energy = (energy * 5) / 4;
        }
    }

    /* CMP progress - inputs making progress on comparisons are valuable */
    if (dynfile->cmpProgress > 0) {
        uint32_t cmp_boost = HF_MIN(dynfile->cmpProgress / 8, 4);
        if (cmp_boost > 0) {
            energy = (energy * (4 + cmp_boost)) / 4;
        }
    }

    /* Rare edge bonus - inputs hitting edges seen by few corpus entries */
    if (dynfile->rareEdgeCnt > 0) {
        uint32_t rare_boost = HF_MIN(dynfile->rareEdgeCnt, 8);
        energy              = (energy * (8 + rare_boost)) / 8;
    }

    /* Diminishing returns - inputs selected many times yield less */
    uint32_t selectCnt = ATOMIC_GET(dynfile->selectCnt);
    if (selectCnt > 100) {
        uint32_t penalty = HF_MIN(util_Log2(selectCnt / 100), 3);
        energy >>= penalty;
    }

    /*
     * Depth - deeply derived inputs may be over-specialized.
     * Progressive penalty - starts at depth 4, increases logarithmically.
     */
    if (dynfile->depth > 8) { /* Relaxed from 4 to 8 */
        uint32_t depth_penalty = HF_MIN(util_Log2(dynfile->depth - 7), 3);
        energy >>= depth_penalty;
    }

    /* Stagnation - focus on best inputs when stuck */
    time_t stagnation = now - ATOMIC_GET(run->global->timing.lastCovUpdate);
    if (stagnation > 60) {
        uint64_t maxCov = ATOMIC_GET(run->global->feedback.maxCov[0]);
        if (maxCov > 0 && dynfile->cov[0] > 0) {
            uint64_t pct = (dynfile->cov[0] * 100) / maxCov;
            if (pct >= 80)
                energy <<= 2; /* Boost high coverage */
            else if (pct < 10)
                energy >>= 2; /* Penalize very low coverage */
        }
    }

    /* Entropy - penalize random blobs, boost structured data */
    if (dynfile->size > 0) {
        unsigned entropy = power_ComputeEntropy(dynfile->data, dynfile->size);
        if (entropy > 93) {
            energy /= 2; /* High entropy (compressed/encrypted/random) - likely harder to fuzz */
        } else if (entropy < 25) {
            energy /= 2; /* Very low entropy (sparse/zeros) - likely uninteresting */
        } else if (entropy < 62) {
            energy = (energy * 3) / 2; /* Text/Structured data - boost */
        }
    }

    /* Timeout - heavy penalty for timeout-causing inputs */
    if (dynfile->timedout) {
        energy >>= 5;
    }

    /* Convert energy to skip factor */
    energy = HF_CAP(energy, 1ULL, energyMax);

    return energy;
}
