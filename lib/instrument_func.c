#include "common.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(_HF_ARCH_LINUX)
#include <sys/syscall.h>
#endif                          // defined(_HF_ARCH_LINUX)

#include "util.h"

static feedback_t *feedback;
static uint32_t my_thread_no = 0;

/* Fall-back mode, just map the buffer to avoid SIGSEGV in __cyg_profile_func_enter */
static void mapBBFallback(void)
{
    feedback =
        mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    feedback->pidFeedback[my_thread_no] = 0U;
    feedback->maxFeedback[my_thread_no] = 0U;
}

__attribute__ ((constructor))
static void mapBB(void)
{
    char *my_thread_no_str = getenv(_HF_THREAD_NO_ENV);
    if (my_thread_no_str == NULL) {
        mapBBFallback();
        return;
    }
    my_thread_no = atoi(my_thread_no_str);

    if (my_thread_no >= _HF_THREAD_MAX) {
        fprintf(stderr, "my_thread_no > _HF_THREAD_MAX (%" PRIu32 " > %d)\n", my_thread_no,
                _HF_THREAD_MAX);
        _exit(1);
    }
    struct stat st;
    if (fstat(_HF_BITMAP_FD, &st) == -1) {
        mapBBFallback();
        return;
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
    feedback->pidFeedback[my_thread_no] = 0U;
    feedback->maxFeedback[my_thread_no] = 0U;
}

/*
 * -finstrument-functions
 */
void __cyg_profile_func_enter(void *func, void *caller)
{
    register size_t pos =
        (((uintptr_t) func << 12) | ((uintptr_t) caller & 0xFFF)) & _HF_PERF_BITMAP_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMap, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedback[my_thread_no]);
    }
}

void __cyg_profile_func_exit(void *func UNUSED, void *caller UNUSED)
{
    return;
}

/*
 * -fsanitize=<address|memory|leak|undefined> -fsanitize-coverage=trace-pc,indirect-calls
 */
void __sanitizer_cov_trace_pc(void)
{
    register uintptr_t ret = (uintptr_t) __builtin_return_address(0) & _HF_PERF_BITMAP_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMap, ret);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedback[my_thread_no]);
    }
}

void __sanitizer_cov_trace_pc_indir(void *callee)
{
    register size_t pos =
        (((uintptr_t) callee << 12) | ((uintptr_t) __builtin_return_address(0) & 0xFFF)) &
        _HF_PERF_BITMAP_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMap, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedback[my_thread_no]);
    }
}
