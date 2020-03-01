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
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

__attribute__((visibility("default"))) __attribute__((used))
const char* const LIBHFUZZ_module_instrument = "LIBHFUZZ_module_instrument";

/*
 * We require SSE4.2 with x86-(32|64) for the 'popcnt', as it's much faster than the software
 * emulation of gcc/clang
 */
#if defined(__x86_64__) || defined(__i386__)
#define HF_REQUIRE_SSE42_POPCNT __attribute__((__target__("sse4.2,popcnt")))
#else
#define HF_REQUIRE_SSE42_POPCNT
#endif /* defined(__x86_64__) || defined(__i386__) */

/*
 * If there's no _HF_COV_BITMAP_FD available (running without the honggfuzz
 * supervisor), use a dummy bitmap and control structure located in the BSS
 */
static feedback_t bbMapFb;

feedback_t* covFeedback = &bbMapFb;
cmpfeedback_t* cmpFeedback = NULL;

uint32_t my_thread_no = 0;

static void initializeCmpFeedback(void) {
    struct stat st;
    if (fstat(_HF_CMP_BITMAP_FD, &st) == -1) {
        return;
    }
    if (st.st_size != sizeof(cmpfeedback_t)) {
        LOG_W("Size of the cmpFeedback structure mismatch: st.size != sizeof(cmpfeedback_t) (%zu "
              "!= %zu). Link your fuzzed binaries with the newest honggfuzz and hfuzz-clang(++)",
            (size_t)st.st_size, sizeof(cmpfeedback_t));
        return;
    }
    int mflags = files_getTmpMapFlags(MAP_SHARED, /* nocore= */ true);
    if ((cmpFeedback = mmap(NULL, sizeof(cmpfeedback_t), PROT_READ | PROT_WRITE, mflags,
             _HF_CMP_BITMAP_FD, 0)) == MAP_FAILED) {
        PLOG_W("mmap(_HF_CMP_BITMAP_FD==%d, size=%zu) of the feedback structure failed",
            _HF_CMP_BITMAP_FD, sizeof(cmpfeedback_t));
        cmpFeedback = NULL;
        return;
    }
}

static bool initializeCovFeedback(void) {
    struct stat st;
    if (fstat(_HF_COV_BITMAP_FD, &st) == -1) {
        return false;
    }
    if (st.st_size != sizeof(feedback_t)) {
        LOG_W("Size of the feedback structure mismatch: st.size != sizeof(feedback_t) (%zu != "
              "%zu). Link your fuzzed binaries with the newest honggfuzz and hfuzz-clang(++)",
            (size_t)st.st_size, sizeof(feedback_t));
        return false;
    }
    int mflags = files_getTmpMapFlags(MAP_SHARED, /* nocore= */ true);
    if ((covFeedback = mmap(NULL, sizeof(feedback_t), PROT_READ | PROT_WRITE, mflags,
             _HF_COV_BITMAP_FD, 0)) == MAP_FAILED) {
        PLOG_W("mmap(_HF_COV_BITMAP_FD=%d, size=%zu) of the feedback structure failed",
            _HF_COV_BITMAP_FD, sizeof(feedback_t));
        return false;
    }
    return true;
}

static void initializeInstrument(void) {
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

    if (!initializeCovFeedback()) {
        covFeedback = &bbMapFb;
        LOG_F("Could not intialize the coverage feedback map");
    }
    initializeCmpFeedback();

    /* Reset coverage counters to their initial state */
    instrumentClearNewCov();
}

static __thread pthread_once_t localInitOnce = PTHREAD_ONCE_INIT;

extern void hfuzzInstrumentInit(void);
__attribute__((constructor)) void hfuzzInstrumentInit(void) {
    pthread_once(&localInitOnce, initializeInstrument);
}

static int _memcmp(const uint8_t* m1, const uint8_t* m2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (m1[i] != m2[i]) {
            return ((int)m1[i] - (int)m2[i]);
        }
    }
    return 0;
}
/*
 * -finstrument-functions
 */
HF_REQUIRE_SSE42_POPCNT void __cyg_profile_func_enter(void* func, void* caller) {
    register size_t pos =
        (((uintptr_t)func << 12) | ((uintptr_t)caller & 0xFFF)) & _HF_PERF_BITMAP_BITSZ_MASK;
    register bool prev = ATOMIC_BITMAP_SET(covFeedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(covFeedback->pidFeedbackPc[my_thread_no]);
    }
}

HF_REQUIRE_SSE42_POPCNT void __cyg_profile_func_exit(
    void* func HF_ATTR_UNUSED, void* caller HF_ATTR_UNUSED) {
    return;
}

/*
 * -fsanitize-coverage=trace-pc
 */
HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_pc_internal(uintptr_t pc) {
    register uintptr_t ret = pc & _HF_PERF_BITMAP_BITSZ_MASK;

    register bool prev = ATOMIC_BITMAP_SET(covFeedback->bbMapPc, ret);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(covFeedback->pidFeedbackPc[my_thread_no]);
    }
}

HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc(void) {
    hfuzz_trace_pc_internal((uintptr_t)__builtin_return_address(0));
}

HF_REQUIRE_SSE42_POPCNT void hfuzz_trace_pc(uintptr_t pc) {
    hfuzz_trace_pc_internal(pc);
}

/*
 * -fsanitize-coverage=trace-cmp
 */
HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp1_internal(
    uintptr_t pc, uint8_t Arg1, uint8_t Arg2) {
    uintptr_t pos = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp2_internal(
    uintptr_t pc, uint16_t Arg1, uint16_t Arg2) {
    uintptr_t pos = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp4_internal(
    uintptr_t pc, uint32_t Arg1, uint32_t Arg2) {
    uintptr_t pos = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp8_internal(
    uintptr_t pc, uint64_t Arg1, uint64_t Arg2) {
    uintptr_t pos = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v = ((sizeof(Arg1) * 8) - __builtin_popcountll(Arg1 ^ Arg2));
    uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

/* Standard __sanitizer_cov_trace_cmp wrappers */
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
    hfuzz_trace_cmp1_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
    hfuzz_trace_cmp2_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
    hfuzz_trace_cmp4_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
    hfuzz_trace_cmp8_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

/* Standard __sanitizer_cov_trace_const_cmp wrappers */
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
    /* No need to report back 1 byte comparisons */
    hfuzz_trace_cmp1_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
    instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    hfuzz_trace_cmp2_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
    instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    hfuzz_trace_cmp4_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
    instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    hfuzz_trace_cmp8_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

/* Custom functions for e.g. the qemu-honggfuzz code */
void hfuzz_trace_cmp1(uintptr_t pc, uint8_t Arg1, uint8_t Arg2) {
    hfuzz_trace_cmp1_internal(pc, Arg1, Arg2);
}

void hfuzz_trace_cmp2(uintptr_t pc, uint16_t Arg1, uint16_t Arg2) {
    hfuzz_trace_cmp2_internal(pc, Arg1, Arg2);
}

void hfuzz_trace_cmp4(uintptr_t pc, uint32_t Arg1, uint32_t Arg2) {
    hfuzz_trace_cmp4_internal(pc, Arg1, Arg2);
}

void hfuzz_trace_cmp8(uintptr_t pc, uint64_t Arg1, uint64_t Arg2) {
    hfuzz_trace_cmp8_internal(pc, Arg1, Arg2);
}

/*
 * Old version of __sanitizer_cov_trace_cmp[n]. Remove it at some point
 */
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_cmp(
    uint64_t SizeAndType, uint64_t Arg1, uint64_t Arg2) {
    uint64_t CmpSize = (SizeAndType >> 32) / 8;
    switch (CmpSize) {
        case (sizeof(uint8_t)):
            hfuzz_trace_cmp1_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
            return;
        case (sizeof(uint16_t)):
            hfuzz_trace_cmp2_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
            return;
        case (sizeof(uint32_t)):
            hfuzz_trace_cmp4_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
            return;
        case (sizeof(uint64_t)):
            hfuzz_trace_cmp8_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
            return;
    }
}

/*
 * Cases[0] is number of comparison entries
 * Cases[1] is length of Val in bits
 */
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t* Cases) {
    for (uint64_t i = 0; i < Cases[0]; i++) {
        uintptr_t pos = ((uintptr_t)__builtin_return_address(0) + i) % _HF_PERF_BITMAP_SIZE_16M;
        uint8_t v = (uint8_t)Cases[1] - __builtin_popcountll(Val ^ Cases[i + 2]);
        uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
        if (prev < v) {
            ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
            ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
        }
    }
}

/*
 * gcc-8 -fsanitize-coverage=trace-cmp trace hooks
 * TODO: evaluate, whether it makes sense to implement them
 */
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_cmpf(
    float Arg1 HF_ATTR_UNUSED, float Arg2 HF_ATTR_UNUSED) {
}
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_cmpd(
    double Arg1 HF_ATTR_UNUSED, double Arg2 HF_ATTR_UNUSED) {
}

/*
 * -fsanitize-coverage=trace-div
 */
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_div8(uint64_t Val) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t v = ((sizeof(Val) * 8) - __builtin_popcountll(Val));
    uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_div4(uint32_t Val) {
    uintptr_t pos = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t v = ((sizeof(Val) * 8) - __builtin_popcount(Val));
    uint8_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
    }
}

/*
 * -fsanitize-coverage=indirect-calls
 */

HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc_indir(uintptr_t callee) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register bool prev = ATOMIC_BITMAP_SET(covFeedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(covFeedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * In LLVM-4.0 it's marked (probably mistakenly) as non-weak symbol, so we need to mark it as weak
 * here
 */
__attribute__((weak)) HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_indir_call16(
    void* callee, void* callee_cache16[] HF_ATTR_UNUSED) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = (uintptr_t)callee & 0xFFF;
    register size_t pos = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register bool prev = ATOMIC_BITMAP_SET(covFeedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC_RELAXED(covFeedback->pidFeedbackPc[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=trace-pc-guard
 */
static bool guards_initialized = false;
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    guards_initialized = true;
    static uint32_t n = 1U;

    /* Make sure that the feedback struct is already mmap()'d */
    hfuzzInstrumentInit();

    /* If this module was already initialized, skip it */
    if (*start > 0) {
        LOG_D("Module %p-%p is already initialized", start, stop);
        return;
    }

    LOG_D("Module initialization: %p-%p at %" PRId32, start, stop, n);
    for (uint32_t* x = start; x < stop; x++, n++) {
        if (n >= _HF_PC_GUARD_MAX) {
            LOG_F("This process has too many PC guards:%" PRIu32
                  " (current module:%tu start:%p stop:%p)\n",
                n, ((uintptr_t)stop - (uintptr_t)start) / sizeof(start), start, stop);
        }
        /* If the corresponding PC was already hit, map this specific guard as uninteresting (0) */
        *x = ATOMIC_GET(covFeedback->pcGuardMap[n]) ? 0U : n;
    }

    /* Store number of guards for statistical purposes */
    if (ATOMIC_GET(covFeedback->guardNb) < n - 1) {
        ATOMIC_SET(covFeedback->guardNb, n - 1);
    }
}

HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
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
    if (!ATOMIC_GET(covFeedback->pcGuardMap[*guard])) {
        bool prev = ATOMIC_XCHG(covFeedback->pcGuardMap[*guard], true);
        if (prev == false) {
            ATOMIC_PRE_INC_RELAXED(covFeedback->pidFeedbackEdge[my_thread_no]);
        }
    }
}

bool instrumentUpdateCmpMap(uintptr_t addr, uint32_t v) {
    uintptr_t pos = addr % _HF_PERF_BITMAP_SIZE_16M;
    uint32_t prev = ATOMIC_GET(covFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(covFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(covFeedback->pidFeedbackCmp[my_thread_no], v - prev);
        return true;
    }
    return false;
}

/* Reset the counters of newly discovered edges/pcs/features */
void instrumentClearNewCov() {
    covFeedback->pidFeedbackPc[my_thread_no] = 0U;
    covFeedback->pidFeedbackEdge[my_thread_no] = 0U;
    covFeedback->pidFeedbackCmp[my_thread_no] = 0U;
}

void instrumentAddConstMem(const void* mem, size_t len, bool check_if_ro) {
    if (!cmpFeedback) {
        return;
    }
    if (len > sizeof(cmpFeedback->valArr[0].val)) {
        len = sizeof(cmpFeedback->valArr[0].val);
    }
    uint32_t curroff = ATOMIC_GET(cmpFeedback->cnt);
    if (curroff >= ARRAYSIZE(cmpFeedback->valArr)) {
        return;
    }
    if (check_if_ro && !util_isAddrRO(mem)) {
        return;
    }

    for (uint32_t i = 0; i < curroff; i++) {
        if ((len == cmpFeedback->valArr[i].len) &&
            _memcmp(cmpFeedback->valArr[i].val, mem, len) == 0) {
            return;
        }
    }

    uint32_t newoff = ATOMIC_POST_INC(cmpFeedback->cnt);
    if (newoff >= ARRAYSIZE(cmpFeedback->valArr)) {
        ATOMIC_SET(cmpFeedback->cnt, ARRAYSIZE(cmpFeedback->valArr));
        return;
    }

    memcpy(cmpFeedback->valArr[newoff].val, mem, len);
    ATOMIC_SET(cmpFeedback->valArr[newoff].len, len);
}
