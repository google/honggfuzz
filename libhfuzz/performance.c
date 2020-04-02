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
#define HF_CHECK_INTERVAL (HF_USEC_PER_SEC * 20) /* Peform check every 20 sec. */

static uint64_t iterCnt = 0;
static time_t firstInputUSecs = 0;
static uint64_t first1000USecsPerExec = 0;
static uint64_t lastCheckUSecs = 0;
static uint64_t lastCheckIters = 0;

void performanceCheck(void) {
    iterCnt += 1;
    if (iterCnt == 1) {
        firstInputUSecs = util_timeNowUSecs();
    }
    if (iterCnt == 1000) {
        first1000USecsPerExec = (util_timeNowUSecs() - firstInputUSecs) / 1000;
        lastCheckUSecs = util_timeNowUSecs();
        lastCheckIters = 0;
    }
    if (iterCnt <= 1000) {
        return;
    }

    if ((util_timeNowUSecs() - lastCheckUSecs) > HF_CHECK_INTERVAL) {
        uint64_t currentUSecsPerExec =
            (util_timeNowUSecs() - lastCheckUSecs) / (iterCnt - lastCheckIters);
        if (currentUSecsPerExec > (first1000USecsPerExec * 5)) {
            LOG_W("PID %d became to slow, initial USecsPerExec:%" PRIu64
                  " us. current: %" PRIu64 " us. Restaring!",
                getpid(), first1000USecsPerExec, currentUSecsPerExec);
            exit(0);
        }
        lastCheckIters = iterCnt;
        lastCheckUSecs = util_timeNowUSecs();
    }
}
