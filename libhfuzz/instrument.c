#include "instrument.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
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

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

__attribute__((visibility("default"))) __attribute__((used))
const char* const LIBHFUZZ_module_instrument = "LIBHFUZZ_module_instrument";

/*
 * We require SSE4.2 with x86-(32|64) for the 'popcnt', as it's much faster than the software
 * emulation of gcc/clang
 */
#if defined(__x86_64__) || defined(__i386__)
#define ATTRIBUTE_X86_REQUIRE_SSE42 __attribute__((__target__("sse4.2")))
#else
#define ATTRIBUTE_X86_REQUIRE_SSE42
#endif /* defined(__x86_64__) || defined(__i386__) */

/*
 * If there's no _HF_BITMAP_FD available (running without the honggfuzz
 * supervisor), use a dummy bitmap and control structure located in the BSS
 */
static feedback_t bbMapFb;
feedback_t* feedback = &bbMapFb;
uint32_t my_thread_no = 0;

__attribute__((constructor)) static void initializeInstrument(void) {
    if (fcntl(_HF_LOG_FD, F_GETFD) != -1) {
        enum llevel_t ll = INFO;
        const char* llstr = getenv(_HF_LOG_LEVEL_ENV);
        if (llstr) {
            ll = atoi(llstr);
        }
        logInitLogFile(NULL, _HF_LOG_FD, ll);
    }

    char* my_thread_no_str = getenv(_HF_THREAD_NO_ENV);
    if (my_thread_no_str == NULL) {
        LOG_D("The '%s' envvar is not set", _HF_THREAD_NO_ENV);
        return;
    }
    my_thread_no = atoi(my_thread_no_str);

    if (my_thread_no >= _HF_THREAD_MAX) {
        LOG_F("Received (via envvar) my_thread_no > _HF_THREAD_MAX (%" PRIu32 " > %d)\n",
            my_thread_no, _HF_THREAD_MAX);
    }

    struct stat st;
    if (fstat(_HF_BITMAP_FD, &st) == -1) {
        return;
    }
    if (st.st_size != sizeof(feedback_t)) {
        LOG_F(
            "size of the feedback structure mismatch: st.size != sizeof(feedback_t) (%zu != %zu). "
            "Link your fuzzed binaries with the newest honggfuzz sources via hfuzz-clang(++)",
            (size_t)st.st_size, sizeof(feedback_t));
    }
    if ((feedback = mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, MAP_SHARED,
             _HF_BITMAP_FD, 0)) == MAP_FAILED) {
        PLOG_F("mmap(fd=%d, size=%zu) of the feedback structure failed", _HF_BITMAP_FD,
            sizeof(feedback_t));
    }

    /* Reset coverage counters to their initial state */
    instrumentClearNewCov();
}

/* Reset the counters of newly discovered edges/pcs/features */
void instrumentClearNewCov() {
    feedback->pidFeedbackPc[my_thread_no] = 0U;
    feedback->pidFeedbackEdge[my_thread_no] = 0U;
    feedback->pidFeedbackCmp[my_thread_no] = 0U;
}

/*
 * -finstrument-functions
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __cyg_profile_func_enter(void* func, void* caller) {
    register size_t pos =
        (((uintptr_t)func << 12) | ((uintptr_t)caller & 0xFFF)) & _HF_PERF_BITMAP_BITSZ_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __cyg_profile_func_exit(
    void* func HF_ATTR_UNUSED, void* caller HF_ATTR_UNUSED) {
    return;
}

/*
 * -fsanitize-coverage=trace-pc
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc(void) {
    register uintptr_t ret = (uintptr_t)__builtin_return_address(0) & _HF_PERF_BITMAP_BITSZ_MASK;
    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, ret);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=trace-cmp
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcountll(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

/*
 * Const versions of trace_cmp, we don't use any special handling for these
 *
 * For MacOS, these're weak aliases, as Darwin supports only them
 */

#if defined(_HF_ARCH_DARWIN)
#pragma weak __sanitizer_cov_trace_const_cmp1 = __sanitizer_cov_trace_cmp1
#pragma weak __sanitizer_cov_trace_const_cmp2 = __sanitizer_cov_trace_cmp2
#pragma weak __sanitizer_cov_trace_const_cmp4 = __sanitizer_cov_trace_cmp4
#pragma weak __sanitizer_cov_trace_const_cmp8 = __sanitizer_cov_trace_cmp8
#else
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp1")));
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp2")));
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp4")));
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp8")));
#endif /* defined(_HF_ARCH_DARWIN) */

/*
 * Cases[0] is number of comparison entries
 * Cases[1] is length of Val in bits
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t* Cases) {
    for (uint64_t i = 0; i < Cases[0]; i++) {
        uintptr_t pos = ((uintptr_t)__builtin_return_address(0) + i) % _HF_PERF_BITMAP_SIZE_16M;
        uint8_t v = (uint8_t)Cases[1] - __builtin_popcountll(Val ^ Cases[i + 2]);
        uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
        if (prev < v) {
            ATOMIC_SET(feedback->bbMapCmp[pos], v);
            ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
        }
    }
}

/*
 * Old version of __sanitizer_cov_trace_cmp[n]. Remove it at some point
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmp(
    uint64_t SizeAndType, uint64_t Arg1, uint64_t Arg2) {
    uint64_t CmpSize = (SizeAndType >> 32) / 8;
    switch (CmpSize) {
        case (sizeof(uint8_t)):
            __sanitizer_cov_trace_cmp1(Arg1, Arg2);
            return;
        case (sizeof(uint16_t)):
            __sanitizer_cov_trace_cmp2(Arg1, Arg2);
            return;
        case (sizeof(uint32_t)):
            __sanitizer_cov_trace_cmp4(Arg1, Arg2);
            return;
        case (sizeof(uint64_t)):
            __sanitizer_cov_trace_cmp8(Arg1, Arg2);
            return;
    }
}

/*
 * gcc-8 -fsanitize-coverage=trace-cmp trace hooks
 * TODO: evaluate, whether it makes sense to implement them
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmpf(
    float Arg1 HF_ATTR_UNUSED, float Arg2 HF_ATTR_UNUSED) {
}
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_cmpd(
    double Arg1 HF_ATTR_UNUSED, double Arg2 HF_ATTR_UNUSED) {
}

/*
 * -fsanitize-coverage=trace-div
 */
void __sanitizer_cov_trace_div8(uint64_t Val) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t v = ((sizeof(Val) * 8) - __builtin_popcountll(Val));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

void __sanitizer_cov_trace_div4(uint32_t Val) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t v = ((sizeof(Val) * 8) - __builtin_popcount(Val));
    uint8_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

/*
 * -fsanitize-coverage=indirect-calls
 */
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc_indir(uintptr_t callee) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * In LLVM-4.0 it's marked (probably mistakenly) as non-weak symbol, so we need to mark it as weak
 * here
 */
__attribute__((weak)) ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_indir_call16(
    void* callee, void* callee_cache16[] HF_ATTR_UNUSED) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = (uintptr_t)callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register uint8_t prev = ATOMIC_BTS(feedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=trace-pc-guard
 */
static bool guards_initialized = false;
ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc_guard_init(
    uint32_t* start, uint32_t* stop) {
    guards_initialized = true;
    static uint32_t n = 1U;
    for (uint32_t* x = start; x < stop; x++, n++) {
        if (n >= _HF_PC_GUARD_MAX) {
            LOG_F("This process has too many PC guards:%" PRIu32
                  " (current module:%tu start:%p stop:%p)\n",
                n, ((uintptr_t)stop - (uintptr_t)start) / sizeof(start), start, stop);
        }
        /* If the corresponding PC was already hit, map this specific guard as non-interesting (0)
         */
        *x = ATOMIC_GET(feedback->pcGuardMap[n]) ? 0U : n;
    }
}

ATTRIBUTE_X86_REQUIRE_SSE42 void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
#if defined(__ANDROID__)
    // ANDROID: Bionic invokes routines that Honggfuzz wraps, before either
    //          *SAN or Honggfuzz have initialized.  Check to see if Honggfuzz
    //          has initialized -- if not, force *SAN to initialize (otherwise
    //          _strcmp() will crash, as it is *SAN-instrumented).
    //
    //          Defer all trace_pc_guard activity until trace_pc_guard_init is
    //          invoked via sancov.module_ctor in the normal process of things.
    if (!guards_initialized) {
        void __asan_init(void) __attribute__((weak));
        if (__asan_init) {
            __asan_init();
        }
        void __msan_init(void) __attribute__((weak));
        if (__msan_init) {
            __msan_init();
        }
        void __ubsan_init(void) __attribute__((weak));
        if (__ubsan_init) {
            __ubsan_init();
        }
        void __tsan_init(void) __attribute__((weak));
        if (__tsan_init) {
            __tsan_init();
        }
        return;
    }
#endif /* defined(__ANDROID__) */
    if (*guard == 0U) {
        return;
    }
    bool prev = ATOMIC_XCHG(feedback->pcGuardMap[*guard], true);
    if (prev == false) {
        ATOMIC_PRE_INC_RELAXED(feedback->pidFeedbackEdge[my_thread_no]);
    }
    *guard = 0U;
}

void instrumentUpdateCmpMap(uintptr_t addr, uint32_t v) {
    uintptr_t pos = addr % _HF_PERF_BITMAP_SIZE_16M;
    uint32_t prev = ATOMIC_GET(feedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(feedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(feedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}
