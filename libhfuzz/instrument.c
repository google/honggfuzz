#include "instrument.h"

#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#if defined(_HF_ARCH_LINUX)
#include <linux/mman.h>
#endif /* defined(_HF_ARCH_LINUX) */
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

/* Cygwin doesn't support this */
#if !defined(__CYGWIN__)
__attribute__((visibility("hidden")))
#endif /* !defined(__CYGWIN__) */
__attribute__((used)) const char* const LIBHFUZZ_module_instrument = "LIBHFUZZ_module_instrument";

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

feedback_t*    globalCovFeedback = &bbMapFb;
feedback_t*    localCovFeedback  = &bbMapFb;
cmpfeedback_t* globalCmpFeedback = NULL;

uint32_t my_thread_no = 0;

__attribute__((hot)) static int _memcmp(const void* m1, const void* m2, size_t n) {
    const unsigned char* s1 = (const unsigned char*)m1;
    const unsigned char* s2 = (const unsigned char*)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (int)s1[i] - (int)s2[i];
        }
    }

    return 0;
}

int (*hf_memcmp)(const void* s1, const void* s2, size_t n) = _memcmp;

static void* getsym(const char* fname, const char* sym) {
    if (fname) {
        void* dlh = dlopen(fname, RTLD_LAZY);
        if (!dlh) {
            return NULL;
        }
        return dlsym(dlh, sym);
    }

#if defined(RTLD_NEXT)
    return dlsym(RTLD_NEXT, sym);
#else  /* defined(RTLD_NEXT) */
    void* dlh = dlopen(NULL, RTLD_LAZY);
    if (!dlh) {
        return NULL;
    }
    return dlsym(dlh, sym);
#endif /* defined(RTLD_NEXT) */
}

extern int __wrap_memcmp(const void* s1, const void* s2, size_t n) __attribute__((weak));
extern int __sanitizer_weak_hook_memcmp(const void* s1, const void* s2, size_t n)
    __attribute__((weak));
static void initializeLibcFunctions(void) {
    /*
     * Look for the original "memcmp" function.
     *
     * First, in standard C libraries, because if an instrumented shared library is loaded, it can
     * overshadow the libc's symbol. Next, among the already loaded symbols.
     */
    int (*libcso6_memcmp)(const void* s1, const void* s2, size_t n) =
        (int (*)(const void* s1, const void* s2, size_t n))getsym("libc.so.6", "memcmp");
    int (*libcso_memcmp)(const void* s1, const void* s2, size_t n) =
        (int (*)(const void* s1, const void* s2, size_t n))getsym("libc.so", "memcmp");
    int (*libc_memcmp)(const void* s1, const void* s2, size_t n) =
        (int (*)(const void* s1, const void* s2, size_t n))getsym(NULL, "memcmp");

    if (libcso6_memcmp) {
        hf_memcmp = libcso6_memcmp;
    } else if (libcso_memcmp) {
        hf_memcmp = libcso_memcmp;
    } else if (libc_memcmp) {
        hf_memcmp = libc_memcmp;
    }

    if (hf_memcmp == __wrap_memcmp) {
        LOG_W("hf_memcmp==__wrap_memcmp: %p==%p", hf_memcmp, __wrap_memcmp);
        hf_memcmp = _memcmp;
    }
    if (hf_memcmp == __sanitizer_weak_hook_memcmp) {
        LOG_W("hf_memcmp==__sanitizer_weak_hook_memcmp: %p==%p", hf_memcmp,
            __sanitizer_weak_hook_memcmp);
        hf_memcmp = _memcmp;
    }

    LOG_D("hf_memcmp=%p, (_memcmp=%p, memcmp=%p, __wrap_memcmp=%p, "
          "__sanitizer_weak_hook_memcmp=%p, libcso6_memcmp=%p, libcso_memcmp=%p, libc_memcmp=%p)",
        hf_memcmp, _memcmp, memcmp, __wrap_memcmp, __sanitizer_weak_hook_memcmp, libcso6_memcmp,
        libcso_memcmp, libc_memcmp);
}

static void* initializeTryMapHugeTLB(int fd, size_t sz) {
    int initflags = MAP_SHARED;
#if defined(MAP_ALIGNED_SUPER)
    initflags |= MAP_ALIGNED_SUPER;
#endif
    int   mflags = files_getTmpMapFlags(initflags, /* nocore= */ true);
    void* ret    = mmap(NULL, sz, PROT_READ | PROT_WRITE, mflags, fd, 0);

#if defined(MADV_HUGEPAGE)
    if (madvise(ret, sz, MADV_HUGEPAGE) == -1) {
        PLOG_W("madvise(addr=%p, sz=%zu, MADV_HUGEPAGE) failed", ret, sz);
    }
#endif /* defined(MADV_HUGEPAGE) */

    return ret;
}

static void initializeCmpFeedback(void) {
    struct stat st;
    if (fstat(_HF_CMP_BITMAP_FD, &st) == -1) {
        return;
    }
    if (st.st_size != sizeof(cmpfeedback_t)) {
        LOG_W(
            "Size of the globalCmpFeedback structure mismatch: st.size != sizeof(cmpfeedback_t) "
            "(%zu != %zu). Link your fuzzed binaries with the newest honggfuzz and hfuzz-clang(++)",
            (size_t)st.st_size, sizeof(cmpfeedback_t));
        return;
    }
    void* ret = initializeTryMapHugeTLB(_HF_CMP_BITMAP_FD, sizeof(cmpfeedback_t));
    if (ret == MAP_FAILED) {
        PLOG_W("mmap(_HF_CMP_BITMAP_FD=%d, size=%zu) of the feedback structure failed",
            _HF_CMP_BITMAP_FD, sizeof(cmpfeedback_t));
        return;
    }
    ATOMIC_SET(globalCmpFeedback, ret);
}

static bool initializeLocalCovFeedback(void) {
    struct stat st;
    if (fstat(_HF_PERTHREAD_BITMAP_FD, &st) == -1) {
        return false;
    }
    if ((size_t)st.st_size < sizeof(feedback_t)) {
        LOG_W("Size of the feedback structure mismatch: st.size < sizeof(feedback_t) (%zu < "
              "%zu). Build your honggfuzz binary from newer sources",
            (size_t)st.st_size, sizeof(feedback_t));
        return false;
    }

    localCovFeedback = initializeTryMapHugeTLB(_HF_PERTHREAD_BITMAP_FD, sizeof(feedback_t));
    if (localCovFeedback == MAP_FAILED) {
        PLOG_W("mmap(_HF_PERTHREAD_BITMAP_FD=%d, size=%zu) of the local feedback structure failed",
            _HF_PERTHREAD_BITMAP_FD, sizeof(feedback_t));
        return false;
    }
    return true;
}

static bool initializeGlobalCovFeedback(void) {
    struct stat st;
    if (fstat(_HF_COV_BITMAP_FD, &st) == -1) {
        return false;
    }
    if ((size_t)st.st_size < sizeof(feedback_t)) {
        LOG_W("Size of the feedback structure mismatch: st.size < sizeof(feedback_t) (%zu < %zu). "
              "Build your honggfuzz binary from newer sources",
            (size_t)st.st_size, sizeof(feedback_t));
        return false;
    }

    globalCovFeedback = initializeTryMapHugeTLB(_HF_COV_BITMAP_FD, sizeof(feedback_t));
    if (globalCovFeedback == MAP_FAILED) {
        PLOG_W("mmap(_HF_COV_BITMAP_FD=%d, size=%zu) of the feedback structure failed",
            _HF_COV_BITMAP_FD, sizeof(feedback_t));
        return false;
    }
    return true;
}

static void initializeInstrument(void) {
    if (fcntl(_HF_LOG_FD, F_GETFD) != -1) {
        enum llevel_t ll    = INFO;
        const char*   llstr = getenv(_HF_LOG_LEVEL_ENV);
        if (llstr) {
            ll = atoi(llstr);
        }
        logInitLogFile(NULL, _HF_LOG_FD, ll);
    }
    LOG_D("Initializing pid=%d", (int)getpid());

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

    if (!initializeGlobalCovFeedback()) {
        globalCovFeedback = &bbMapFb;
        LOG_F("Could not intialize the global coverage feedback map");
    }
    if (!initializeLocalCovFeedback()) {
        localCovFeedback = &bbMapFb;
        LOG_F("Could not intialize the local coverage feedback map");
    }
    initializeCmpFeedback();

    /* Initialize native functions found in libc */
    initializeLibcFunctions();

    /* Reset coverage counters to their initial state */
    instrumentClearNewCov();
}

static __thread pthread_once_t localInitOnce = PTHREAD_ONCE_INIT;

extern void                       hfuzzInstrumentInit(void);
__attribute__((constructor)) void hfuzzInstrumentInit(void) {
    pthread_once(&localInitOnce, initializeInstrument);
}

__attribute__((weak)) size_t instrumentReserveGuard(size_t cnt) {
    static size_t guardCnt = 1;
    size_t        base     = guardCnt;
    guardCnt += cnt;
    if (guardCnt >= _HF_PC_GUARD_MAX) {
        LOG_F(
            "This process requested too many PC-guards, total:%zu, requested:%zu)", guardCnt, cnt);
    }
    if (ATOMIC_GET(globalCovFeedback->guardNb) < guardCnt) {
        ATOMIC_SET(globalCovFeedback->guardNb, guardCnt);
    }
    return base;
}

void instrumentResetLocalCovFeedback(void) {
    bzero(localCovFeedback->pcGuardMap, HF_MIN(instrumentReserveGuard(0), _HF_PC_GUARD_MAX));

    wmb();
}

/* Used to limit certain expensive actions, like adding values to dictionaries */
static inline bool instrumentLimitEvery(uint64_t step) {
    if (util_rndGet(0, step) == 0) return true;
    return false;
}

static inline void instrumentAddConstMemInternal(const void* mem, size_t len) {
    if (len <= 1) {
        return;
    }
    if (len > sizeof(globalCmpFeedback->valArr[0].val)) {
        len = sizeof(globalCmpFeedback->valArr[0].val);
    }
    uint32_t curroff = ATOMIC_GET(globalCmpFeedback->cnt);
    if (curroff >= ARRAYSIZE(globalCmpFeedback->valArr)) {
        return;
    }

    for (uint32_t i = 0; i < curroff; i++) {
        if ((len == ATOMIC_GET(globalCmpFeedback->valArr[i].len)) &&
            hf_memcmp(globalCmpFeedback->valArr[i].val, mem, len) == 0) {
            return;
        }
    }

    uint32_t newoff = ATOMIC_POST_INC(globalCmpFeedback->cnt);
    if (newoff >= ARRAYSIZE(globalCmpFeedback->valArr)) {
        ATOMIC_SET(globalCmpFeedback->cnt, ARRAYSIZE(globalCmpFeedback->valArr));
        return;
    }

    memcpy(globalCmpFeedback->valArr[newoff].val, mem, len);
    ATOMIC_SET(globalCmpFeedback->valArr[newoff].len, len);
    wmb();
}

/*
 * -finstrument-functions
 */
HF_REQUIRE_SSE42_POPCNT void __cyg_profile_func_enter(void* func, void* caller) {
    register size_t pos =
        (((uintptr_t)func << 12) | ((uintptr_t)caller & 0xFFF)) & _HF_PERF_BITMAP_BITSZ_MASK;
    register bool prev = ATOMIC_BITMAP_SET(globalCovFeedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC(globalCovFeedback->pidNewPC[my_thread_no]);
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

    register bool prev = ATOMIC_BITMAP_SET(globalCovFeedback->bbMapPc, ret);
    if (!prev) {
        ATOMIC_PRE_INC(globalCovFeedback->pidNewPC[my_thread_no]);
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
    uintptr_t        pos  = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v    = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t          prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp2_internal(
    uintptr_t pc, uint16_t Arg1, uint16_t Arg2) {
    uintptr_t        pos  = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v    = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t          prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp4_internal(
    uintptr_t pc, uint32_t Arg1, uint32_t Arg2) {
    uintptr_t        pos  = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v    = ((sizeof(Arg1) * 8) - __builtin_popcount(Arg1 ^ Arg2));
    uint8_t          prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT static inline void hfuzz_trace_cmp8_internal(
    uintptr_t pc, uint64_t Arg1, uint64_t Arg2) {
    uintptr_t        pos  = pc % _HF_PERF_BITMAP_SIZE_16M;
    register uint8_t v    = ((sizeof(Arg1) * 8) - __builtin_popcountll(Arg1 ^ Arg2));
    uint8_t          prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
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
    /* Add 4byte values to the const_dictionary if they exist within the binary */
    if (globalCmpFeedback && instrumentLimitEvery(4095)) {
        if (Arg1 > 0xffff) {
            uint32_t bswp = __builtin_bswap32(Arg1);
            if (util_32bitValInBinary(Arg1) || util_32bitValInBinary(bswp)) {
                instrumentAddConstMemInternal(&Arg1, sizeof(Arg1));
                instrumentAddConstMemInternal(&bswp, sizeof(bswp));
            }
        }
        if (Arg2 > 0xffff) {
            uint32_t bswp = __builtin_bswap32(Arg2);
            if (util_32bitValInBinary(Arg2) || util_32bitValInBinary(bswp)) {
                instrumentAddConstMemInternal(&Arg2, sizeof(Arg2));
                instrumentAddConstMemInternal(&bswp, sizeof(bswp));
            }
        }
    }

    hfuzz_trace_cmp4_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
    /* Add 8byte values to the const_dictionary if they exist within the binary */
    if (globalCmpFeedback && instrumentLimitEvery(4095)) {
        if (Arg1 > 0xffffff) {
            uint64_t bswp = __builtin_bswap64(Arg1);
            if (util_64bitValInBinary(Arg1) || util_64bitValInBinary(bswp)) {
                instrumentAddConstMemInternal(&Arg1, sizeof(Arg1));
                instrumentAddConstMemInternal(&bswp, sizeof(bswp));
            }
        }
        if (Arg2 > 0xffffff) {
            uint64_t bswp = __builtin_bswap64(Arg2);
            if (util_64bitValInBinary(Arg2) || util_64bitValInBinary(bswp)) {
                instrumentAddConstMemInternal(&Arg2, sizeof(Arg2));
                instrumentAddConstMemInternal(&bswp, sizeof(bswp));
            }
        }
    }

    hfuzz_trace_cmp8_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

/* Standard __sanitizer_cov_trace_const_cmp wrappers */
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
    instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    hfuzz_trace_cmp1_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
    if (Arg1) {
        uint16_t bswp = __builtin_bswap16(Arg1);
        instrumentAddConstMem(&bswp, sizeof(bswp), /* check_if_ro= */ false);
        instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    }
    hfuzz_trace_cmp2_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
    if (Arg1) {
        uint32_t bswp = __builtin_bswap32(Arg1);
        instrumentAddConstMem(&bswp, sizeof(bswp), /* check_if_ro= */ false);
        instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    }
    hfuzz_trace_cmp4_internal((uintptr_t)__builtin_return_address(0), Arg1, Arg2);
}

void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
    if (Arg1) {
        uint64_t bswp = __builtin_bswap64(Arg1);
        instrumentAddConstMem(&bswp, sizeof(bswp), /* check_if_ro= */ false);
        instrumentAddConstMem(&Arg1, sizeof(Arg1), /* check_if_ro= */ false);
    }
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
        uintptr_t pos  = ((uintptr_t)__builtin_return_address(0) + i) % _HF_PERF_BITMAP_SIZE_16M;
        uint8_t   v    = (uint8_t)Cases[1] - __builtin_popcountll(Val ^ Cases[i + 2]);
        uint8_t   prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
        if (prev < v) {
            ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
            ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
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
    uintptr_t pos  = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t   v    = ((sizeof(Val) * 8) - __builtin_popcountll(Val));
    uint8_t   prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
    }
}

HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_div4(uint32_t Val) {
    uintptr_t pos  = (uintptr_t)__builtin_return_address(0) % _HF_PERF_BITMAP_SIZE_16M;
    uint8_t   v    = ((sizeof(Val) * 8) - __builtin_popcount(Val));
    uint8_t   prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
    }
}

/*
 * -fsanitize-coverage=indirect-calls
 */
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc_indir(uintptr_t callee) {
    register size_t pos1 = (uintptr_t)__builtin_return_address(0) << 12;
    register size_t pos2 = callee & 0xFFF;
    register size_t pos  = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register bool prev = ATOMIC_BITMAP_SET(globalCovFeedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC(globalCovFeedback->pidNewPC[my_thread_no]);
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
    register size_t pos  = (pos1 | pos2) & _HF_PERF_BITMAP_BITSZ_MASK;

    register bool prev = ATOMIC_BITMAP_SET(globalCovFeedback->bbMapPc, pos);
    if (!prev) {
        ATOMIC_PRE_INC(globalCovFeedback->pidNewPC[my_thread_no]);
    }
}

/*
 * -fsanitize-coverage=trace-pc-guard
 */
static bool                  guards_initialized = false;
HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    guards_initialized = true;

    /* Make sure that the feedback struct is already mmap()'d */
    hfuzzInstrumentInit();

    if ((uintptr_t)start == (uintptr_t)stop) {
        return;
    }
    /* If this module was already initialized, skip it */
    if (*start > 0) {
        LOG_D("Module %p-%p is already initialized", start, stop);
        return;
    }

    LOG_D("PC-Guard module initialization: %p-%p (count:%tu) at %zu", start, stop,
        ((uintptr_t)stop - (uintptr_t)start) / sizeof(*start), instrumentReserveGuard(0));

    for (uint32_t* x = start; x < stop; x++) {
        uint32_t guardNo = instrumentReserveGuard(1);
        *x               = guardNo;
    }

    wmb();
}

/* Map number of visits to an edge into buckets */
static uint8_t const instrumentCntMap[256] = {
    [0]          = 0,
    [1]          = 1U << 0,
    [2]          = 1U << 1,
    [3]          = 1U << 2,
    [4 ... 5]    = 1U << 3,
    [6 ... 10]   = 1U << 4,
    [11 ... 32]  = 1U << 5,
    [33 ... 64]  = 1U << 6,
    [65 ... 255] = 1U << 7,
};

HF_REQUIRE_SSE42_POPCNT void __sanitizer_cov_trace_pc_guard(uint32_t* guard_ptr) {
#if defined(__ANDROID__)
    /*
     * ANDROID: Bionic invokes routines that Honggfuzz wraps, before either
     *          *SAN or Honggfuzz have initialized.  Check to see if Honggfuzz
     *          has initialized -- if not, force *SAN to initialize (otherwise
     *          _strcmp() will crash, as it is *SAN-instrumented).
     *
     *          Defer all trace_pc_guard activity until trace_pc_guard_init is
     *          invoked via sancov.module_ctor in the normal process of things.
     */
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

    /* This guard is uninteresting, it was probably maxed out already */
    const uint32_t guard = *guard_ptr;
    if (!guard) {
        return;
    }

    if (ATOMIC_GET(localCovFeedback->pcGuardMap[guard]) > 100) {
        /* This guard has been maxed out. Mark it as uninteresting */
        ATOMIC_CLEAR(*guard_ptr);
    }

    /* Update the total/local counters */
    const uint8_t v = ATOMIC_PRE_INC(localCovFeedback->pcGuardMap[guard]);
    if (v == 1) {
        ATOMIC_PRE_INC(globalCovFeedback->pidTotalEdge[my_thread_no]);
    } else {
        ATOMIC_PRE_INC(globalCovFeedback->pidTotalCmp[my_thread_no]);
    }

    /* Update the new/global counters */
    const uint8_t newval = instrumentCntMap[v];
    if (ATOMIC_GET(globalCovFeedback->pcGuardMap[guard]) < newval) {
        const uint8_t oldval = ATOMIC_POST_OR(globalCovFeedback->pcGuardMap[guard], newval);
        if (!oldval) {
            ATOMIC_PRE_INC(globalCovFeedback->pidNewEdge[my_thread_no]);
        } else if (oldval < newval) {
            ATOMIC_PRE_INC(globalCovFeedback->pidNewCmp[my_thread_no]);
        }
    }
}

/* Support up to 256 DSO modules with separate 8bit counters */
static struct {
    uint8_t* start;
    size_t   cnt;
    size_t   guard;
} hf8bitcounters[256] = {};

void instrument8BitCountersCount(void) {
    rmb();

    uint64_t totalEdge = 0;
    uint64_t totalCmp  = 0;

    for (size_t i = 0; i < ARRAYSIZE(hf8bitcounters) && hf8bitcounters[i].start; i++) {
        for (size_t j = 0; j < hf8bitcounters[i].cnt; j++) {
            const uint8_t v            = hf8bitcounters[i].start[j];
            hf8bitcounters[i].start[j] = 0;
            if (!v) {
                continue;
            }

            const uint8_t newval = instrumentCntMap[v];
            const size_t  guard  = hf8bitcounters[i].guard + j;

            /* New hits */
            if (ATOMIC_GET(globalCovFeedback->pcGuardMap[guard]) < newval) {
                const uint8_t oldval = ATOMIC_POST_OR(globalCovFeedback->pcGuardMap[guard], newval);
                if (!oldval) {
                    ATOMIC_PRE_INC(globalCovFeedback->pidNewEdge[my_thread_no]);
                } else if (oldval < newval) {
                    ATOMIC_PRE_INC(globalCovFeedback->pidNewCmp[my_thread_no]);
                }
            }

            /* Total hits */
            {
                totalEdge++;
                if (v > 1) {
                    totalCmp += newval;
                }
            }
        }
    }

    ATOMIC_POST_ADD(globalCovFeedback->pidTotalEdge[my_thread_no], totalEdge);
    ATOMIC_POST_ADD(globalCovFeedback->pidTotalCmp[my_thread_no], totalCmp);
}

void __sanitizer_cov_8bit_counters_init(char* start, char* end) {
    /* Make sure that the feedback struct is already mmap()'d */
    hfuzzInstrumentInit();

    if ((uintptr_t)start == (uintptr_t)end) {
        return;
    }
    for (size_t i = 0; i < ARRAYSIZE(hf8bitcounters); i++) {
        if (hf8bitcounters[i].start == NULL) {
            hf8bitcounters[i].start = (uint8_t*)start;
            hf8bitcounters[i].cnt   = (uintptr_t)end - (uintptr_t)start;
            hf8bitcounters[i].guard = instrumentReserveGuard(hf8bitcounters[i].cnt);
            LOG_D("8-bit module initialization %p-%p (count:%zu) at guard %zu", start, end,
                hf8bitcounters[i].cnt, hf8bitcounters[i].guard);
            break;
        }
    }
}

/* Not implemented yet */
void __sanitizer_cov_pcs_init(
    const uintptr_t* pcs_beg HF_ATTR_UNUSED, const uintptr_t* pcs_end HF_ATTR_UNUSED) {
}

unsigned instrumentThreadNo(void) {
    return my_thread_no;
}

/* Cygwin has problem with visibility of this symbol */
#if !defined(__CYGWIN__)
/* For some reason -fsanitize=fuzzer-no-link references this symbol */
__attribute__((tls_model("initial-exec")))
__attribute__((weak)) __thread uintptr_t __sancov_lowest_stack = 0;
#endif /* !defined(__CYGWIN__) */

bool instrumentUpdateCmpMap(uintptr_t addr, uint32_t v) {
    uintptr_t pos  = addr % _HF_PERF_BITMAP_SIZE_16M;
    uint32_t  prev = ATOMIC_GET(globalCovFeedback->bbMapCmp[pos]);
    if (prev < v) {
        ATOMIC_SET(globalCovFeedback->bbMapCmp[pos], v);
        ATOMIC_POST_ADD(globalCovFeedback->pidNewCmp[my_thread_no], v - prev);
        return true;
    }
    return false;
}

/* Reset the counters of newly discovered edges/pcs/features */
void instrumentClearNewCov() {
    ATOMIC_CLEAR(globalCovFeedback->pidNewPC[my_thread_no]);
    ATOMIC_CLEAR(globalCovFeedback->pidNewEdge[my_thread_no]);
    ATOMIC_CLEAR(globalCovFeedback->pidNewCmp[my_thread_no]);

    ATOMIC_CLEAR(globalCovFeedback->pidTotalPC[my_thread_no]);
    ATOMIC_CLEAR(globalCovFeedback->pidTotalEdge[my_thread_no]);
    ATOMIC_CLEAR(globalCovFeedback->pidTotalCmp[my_thread_no]);
}

void instrumentAddConstMem(const void* mem, size_t len, bool check_if_ro) {
    if (!globalCmpFeedback) {
        return;
    }
    if (len <= 1) {
        return;
    }
    if (!instrumentLimitEvery(127)) {
        return;
    }
    if (check_if_ro && util_getProgAddr(mem) == LHFC_ADDR_NOTFOUND) {
        return;
    }
    instrumentAddConstMemInternal(mem, len);
}

void instrumentAddConstStr(const char* s) {
    if (!globalCmpFeedback) {
        return;
    }
    if (!instrumentLimitEvery(127)) {
        return;
    }
    /*
     * if (len <= 1)
     */
    if (s[0] == '\0' || s[1] == '\0') {
        return;
    }
    if (util_getProgAddr(s) == LHFC_ADDR_NOTFOUND) {
        return;
    }
    instrumentAddConstMemInternal(s, strlen(s));
}

void instrumentAddConstStrN(const char* s, size_t n) {
    if (!globalCmpFeedback) {
        return;
    }
    if (n <= 1) {
        return;
    }
    if (!instrumentLimitEvery(127)) {
        return;
    }
    if (util_getProgAddr(s) == LHFC_ADDR_NOTFOUND) {
        return;
    }
    instrumentAddConstMemInternal(s, strnlen(s, n));
}

bool instrumentConstAvail(void) {
    return (ATOMIC_GET(globalCmpFeedback) != NULL);
}
