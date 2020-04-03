#include "libhfuzz/performance.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#define HF_USEC_PER_SEC 1000000
#define HF_CHECK_INTERVAL_USECS (HF_USEC_PER_SEC * 20) /* Peform check every 20 sec. */

static uint64_t iterCnt = 0;
static time_t firstInputUSecs = 0;

static uint64_t initialUSecsPerExec = 0;

static uint64_t lastCheckUSecs = 0;
static uint64_t lastCheckIters = 0;

static bool performanceInit(void) {
    if (iterCnt == 1) {
        firstInputUSecs = util_timeNowUSecs();
    }

    uint64_t timeDiffUSecs = util_timeNowUSecs() - firstInputUSecs;
    if (iterCnt == 5000 || timeDiffUSecs > HF_CHECK_INTERVAL_USECS) {
        initialUSecsPerExec = timeDiffUSecs / iterCnt;
        lastCheckUSecs = util_timeNowUSecs();
        lastCheckIters = iterCnt;
        return true;
    }

    return false;
}

bool performanceTooSlow(void) {
    uint64_t timeDiffUSecs = util_timeNowUSecs() - lastCheckUSecs;
    if (timeDiffUSecs > HF_CHECK_INTERVAL_USECS) {
        uint64_t currentUSecsPerExec = timeDiffUSecs / (iterCnt - lastCheckIters);
        if (currentUSecsPerExec > (initialUSecsPerExec * 5)) {
            LOG_W("pid=%d became too slow to process fuzzing data, initial: %" PRIu64
                  " us/exec, current: %" PRIu64 " us/exec. Restaring myself!",
                getpid(), initialUSecsPerExec, currentUSecsPerExec);
            return true;
        }
        lastCheckIters = iterCnt;
        lastCheckUSecs = util_timeNowUSecs();
    }

    return false;
}

void performanceCheck(void) {
    iterCnt += 1;

    static bool initialized = false;
    if (!initialized) {
        initialized = performanceInit();
        return;
    }

    if (performanceTooSlow()) {
        exit(0);
    }
}
