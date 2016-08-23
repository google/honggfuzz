#include <error.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

static feedback_t *feedback;
static pid_t mypid;

__attribute__ ((no_instrument_function))
__attribute__ ((constructor))
static void mapBB(void)
{
    mypid = getpid();
    if (mypid >= _HF_FEEDBACK_PID_SZ) {
        fprintf(stderr, "mypid > _HF_FEEDBACK_PID_SZ (%d > %d)\n", mypid, _HF_FEEDBACK_PID_SZ);
        _exit(1);
    }
    struct stat st;
    if (fstat(_HF_BITMAP_FD, &st) == -1) {
        fprintf(stderr, "fstat(%d): %s\n", _HF_BITMAP_FD, strerror(errno));
        _exit(1);
    }
    if (st.st_size != sizeof(feedback_t)) {
        fprintf(stderr, "st.size != sizeof(feedback_t) (%zu != %zu)\n", (size_t) st.st_size,
                sizeof(feedback_t));
        _exit(1);
    }
    if ((feedback =
         mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED, _HF_BITMAP_FD,
              0)) == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        _exit(1);
    }
    feedback->pidFeedback[mypid] = 0U;
}

__attribute__ ((no_instrument_function))
void __cyg_profile_func_enter(void *func, void *caller)
{
    register size_t pos =
        (((uintptr_t) func << 12) | ((uintptr_t) caller & 0xFFF)) & _HF_PERF_BITMAP_MASK;
    register size_t byteOff = pos / 8;
    register uint8_t bitSet = (uint8_t) (1 << (pos % 8));

    register uint8_t prev = ATOMIC_POST_OR_RELAXED(feedback->bbMap[byteOff], bitSet);
    if (!(prev & bitSet)) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedback[mypid]);
    }
}
