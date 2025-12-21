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

uint64_t power_calculateEnergy(run_t* run, dynfile_t* dynfile) {
    const uint64_t energyMax     = 65536;
    const time_t   freshTimeSec  = 60;
    const time_t   recentTimeSec = 300;
    const time_t   staleTimeSec  = 3600;

    uint64_t energy = POWER_BASE_ENERGY;
    time_t   now    = time(NULL);

    /* Novelty - inputs that discovered new edges explore unknown territory.
     * Decay novelty bonus over time - edges discovered 10+ minutes ago are less novel. */
    if (dynfile->newEdges > 0) {
        time_t   age_mins = (now - dynfile->timeAdded) / 60;
        uint32_t decay    = (age_mins < 10) ? 0 : HF_MIN(age_mins / 10, 6);
        uint32_t boost    = HF_MIN(dynfile->newEdges, 8);
        if (boost > decay) {
            energy <<= (boost - decay);
        }
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
        energy = (energy * (8 + HF_MIN(1 + util_Log2(refs + 1), 6))) / 8;
    }

    /* Freshness - time-based, newer inputs haven't been fully explored */
    time_t age_secs = now - dynfile->timeAdded;
    if (age_secs < freshTimeSec) {
        energy <<= 2; /* added in last minute - 4x */
    } else if (age_secs < recentTimeSec) {
        energy <<= 1; /* added in last 5 minutes - 2x */
    } else if (age_secs > staleTimeSec && refs == 0) {
        energy >>= 1; /* older than 1 hour with no children - 0.5x */
    }

    /* Size - smaller inputs are faster and easier to analyze */
    if (dynfile->size > 1024) {
        uint32_t log_size = util_Log2(dynfile->size);
        if (log_size > 10) energy >>= HF_MIN(log_size - 10, 4);
    }

    /* Depth - deeply derived inputs may be over-specialized */
    if (dynfile->depth > 8) {
        energy = (energy * 7) / 8;
    }

    /* Stagnation - focus on best inputs when stuck */
    time_t stagnation = now - ATOMIC_GET(run->global->timing.lastCovUpdate);
    if (stagnation > 60) {
        uint64_t maxCov = ATOMIC_GET(run->global->feedback.maxCov[0]);
        if (maxCov > 0 && dynfile->cov[0] > 0) {
            uint64_t pct = (dynfile->cov[0] * 100) / maxCov;
            if (pct >= 90)
                energy <<= 2;
            else if (pct < 50)
                energy >>= 2;
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
