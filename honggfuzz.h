/*
 *
 * honggfuzz - core structures and macros
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
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

#ifndef _HF_HONGGFUZZ_H_
#define _HF_HONGGFUZZ_H_

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>

#include "libhfcommon/util.h"

#define PROG_NAME "honggfuzz"
#define PROG_VERSION "1.9"

/* Name of the template which will be replaced with the proper name of the file */
#define _HF_FILE_PLACEHOLDER "___FILE___"

/* Default name of the report created with some architectures */
#define _HF_REPORT_FILE "HONGGFUZZ.REPORT.TXT"

/* Default stack-size of created threads. */
#define _HF_PTHREAD_STACKSIZE (1024ULL * 1024ULL * 2ULL) /* 2MB */

/* Name of envvar which indicates sequential number of fuzzer */
#define _HF_THREAD_NO_ENV "HFUZZ_THREAD_NO"

/* Name of envvar which indicates that the netDriver should be used */
#define _HF_THREAD_NETDRIVER_ENV "HFUZZ_USE_NETDRIVER"

/* Name of envvar which indicates honggfuzz's log level in use */
#define _HF_LOG_LEVEL_ENV "HFUZZ_LOG_LEVEL"

/* Number of crash verifier iterations before tag crash as stable */
#define _HF_VERIFIER_ITER 5

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 8192

/* Perf bitmap size */
#define _HF_PERF_BITMAP_SIZE_16M (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7FFFFFFULL
/* Maximum number of PC guards (=trace-pc-guard) we support */
#define _HF_PC_GUARD_MAX (1024ULL * 1024ULL * 64ULL)

/* Maximum size of the input file in bytes (128 MiB) */
#define _HF_INPUT_MAX_SIZE (1024ULL * 1024ULL * 128ULL)

/* FD used to log inside the child process */
#define _HF_LOG_FD 1020
/* FD used to represent the input file */
#define _HF_INPUT_FD 1021
/* FD used to pass feedback bitmap a process */
#define _HF_BITMAP_FD 1022
/* FD used to pass data to a persistent process */
#define _HF_PERSISTENT_FD 1023

/* Message indicating that the fuzzed process is ready for new data */
static const uint8_t HFReadyTag = 'R';

/* Maximum number of active fuzzing threads */
#define _HF_THREAD_MAX 1024U

/* Persistent-binary signature - if found within file, it means it's a persistent mode binary */
#define _HF_PERSISTENT_SIG "\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"
/* HF NetDriver signature - if found within file, it means it's a NetDriver-based binary */
#define _HF_NETDRIVER_SIG "\x01_LIBHFUZZ_NETDRIVER_BINARY_SIGNATURE_\x02\xFF"

typedef enum {
    _HF_DYNFILE_NONE = 0x0,
    _HF_DYNFILE_INSTR_COUNT = 0x1,
    _HF_DYNFILE_BRANCH_COUNT = 0x2,
    _HF_DYNFILE_BTS_EDGE = 0x10,
    _HF_DYNFILE_IPT_BLOCK = 0x20,
    _HF_DYNFILE_SOFT = 0x40,
} dynFileMethod_t;

typedef struct {
    uint64_t cpuInstrCnt;
    uint64_t cpuBranchCnt;
    uint64_t bbCnt;
    uint64_t newBBCnt;
    uint64_t softCntPc;
    uint64_t softCntEdge;
    uint64_t softCntCmp;
} hwcnt_t;

typedef struct {
    uint32_t capacity;
    uint32_t* pChunks;
    uint32_t nChunks;
} bitmap_t;

/* Memory map struct */
typedef struct __attribute__((packed)) {
    uint64_t start;          // region start addr
    uint64_t end;            // region end addr
    uint64_t base;           // region base addr
    char mapName[NAME_MAX];  // bin/DSO name
    uint64_t bbCnt;
    uint64_t newBBCnt;
} memMap_t;

/* Trie node data struct */
typedef struct __attribute__((packed)) {
    bitmap_t* pBM;
} trieData_t;

/* Trie node struct */
typedef struct node {
    char key;
    trieData_t data;
    struct node* next;
    struct node* prev;
    struct node* children;
    struct node* parent;
} node_t;

/* EOF Sanitizer coverage specific data structures */

typedef enum {
    _HF_STATE_UNSET = 0,
    _HF_STATE_STATIC = 1,
    _HF_STATE_DYNAMIC_DRY_RUN = 2,
    _HF_STATE_DYNAMIC_SWITCH_TO_MAIN = 3,
    _HF_STATE_DYNAMIC_MAIN = 4,
} fuzzState_t;

struct dynfile_t {
    uint8_t* data;
    size_t size;
    TAILQ_ENTRY(dynfile_t)
    pointers;
};

struct strings_t {
    char* s;
    size_t len;
    TAILQ_ENTRY(strings_t)
    pointers;
};

typedef struct {
    bool pcGuardMap[_HF_PC_GUARD_MAX];
    uint8_t bbMapPc[_HF_PERF_BITMAP_SIZE_16M];
    uint32_t bbMapCmp[_HF_PERF_BITMAP_SIZE_16M];
    uint64_t pidFeedbackPc[_HF_THREAD_MAX];
    uint64_t pidFeedbackEdge[_HF_THREAD_MAX];
    uint64_t pidFeedbackCmp[_HF_THREAD_MAX];
} feedback_t;

typedef struct {
    struct {
        size_t threadsMax;
        size_t threadsFinished;
        uint32_t threadsActiveCnt;
        pthread_t mainThread;
        pid_t mainPid;
        pthread_t threads[_HF_THREAD_MAX];
    } threads;
    struct {
        const char* inputDir;
        DIR* inputDirPtr;
        size_t fileCnt;
        const char* fileExtn;
        bool fileCntDone;
        const char* workDir;
        const char* crashDir;
        const char* covDirAll;
        const char* covDirNew;
        bool saveUnique;
        size_t dynfileqCnt;
        pthread_rwlock_t dynfileq_mutex;
        TAILQ_HEAD(dyns_t, dynfile_t) dynfileq;
    } io;
    struct {
        int argc;
        const char* const* cmdline;
        bool nullifyStdio;
        bool fuzzStdin;
        const char* externalCommand;
        const char* postExternalCommand;
        const char* feedbackMutateCommand;
        bool netDriver;
        bool persistent;
        uint64_t asLimit;
        uint64_t rssLimit;
        uint64_t dataLimit;
        uint64_t coreLimit;
        bool clearEnv;
        char* envs[128];
        sigset_t waitSigSet;
    } exe;
    struct {
        time_t timeStart;
        time_t runEndTime;
        time_t tmOut;
        time_t lastCovUpdate;
        bool tmoutVTALRM;
    } timing;
    struct {
        const char* dictionaryFile;
        TAILQ_HEAD(strq_t, strings_t) dictq;
        size_t dictionaryCnt;
        size_t mutationsMax;
        unsigned mutationsPerRun;
        size_t maxFileSz;
    } mutate;
    struct {
        bool useScreen;
        char cmdline_txt[65];
        int64_t lastDisplayMillis;
    } display;
    struct {
        bool useVerifier;
        bool exitUponCrash;
        const char* reportFile;
        pthread_mutex_t report_mutex;
        bool monitorSIGABRT;
        size_t dynFileIterExpire;
        bool only_printable;
    } cfg;
    struct {
        bool enable;
    } sanitizer;
    struct {
        fuzzState_t state;
        feedback_t* feedbackMap;
        int bbFd;
        pthread_mutex_t feedback_mutex;
        const char* blacklistFile;
        uint64_t* blacklist;
        size_t blacklistCnt;
        bool skipFeedbackOnTimeout;
        dynFileMethod_t dynFileMethod;
    } feedback;
    struct {
        size_t mutationsCnt;
        size_t crashesCnt;
        size_t uniqueCrashesCnt;
        size_t verifiedCrashesCnt;
        size_t blCrashesCnt;
        size_t timeoutedCnt;
    } cnts;
    struct {
        bool enabled;
        int serverSocket;
        int clientSocket;
    } socketFuzzer;
    /* For the Linux code */
    struct {
        int exeFd;
        hwcnt_t hwCnts;
        uint64_t dynamicCutOffAddr;
        bool disableRandomization;
        void* ignoreAddr;
        size_t numMajorFrames;
        const char* symsBlFile;
        char** symsBl;
        size_t symsBlCnt;
        const char* symsWlFile;
        char** symsWl;
        size_t symsWlCnt;
        uintptr_t cloneFlags;
        bool kernelOnly;
        bool useClone;
    } linux;
    /* For the NetBSD code */
    struct {
        void* ignoreAddr;
        size_t numMajorFrames;
        const char* symsBlFile;
        char** symsBl;
        size_t symsBlCnt;
        const char* symsWlFile;
        char** symsWl;
        size_t symsWlCnt;
    } netbsd;
} honggfuzz_t;

typedef enum {
    _HF_RS_UNKNOWN = 0,
    _HF_RS_WAITING_FOR_INITIAL_READY = 1,
    _HF_RS_WAITING_FOR_READY = 2,
    _HF_RS_SEND_DATA = 3,
} runState_t;

typedef struct {
    honggfuzz_t* global;
    pid_t pid;
    int64_t timeStartedMillis;
    char origFileName[PATH_MAX];
    char crashFileName[PATH_MAX];
    uint64_t pc;
    uint64_t backtrace;
    uint64_t access;
    int exception;
    char report[_HF_REPORT_SIZE];
    bool mainWorker;
    unsigned mutationsPerRun;
    struct dynfile_t* dynfileqCurrent;
    uint8_t* dynamicFile;
    size_t dynamicFileSz;
    int dynamicFileFd;
    int dynamicFileCopyFd;
    uint32_t fuzzNo;
    int persistentSock;
    bool waitingForReady;
    runState_t runState;
    bool tmOutSignaled;
#if !defined(_HF_ARCH_DARWIN)
    timer_t timerId;
#endif  // !defined(_HF_ARCH_DARWIN)

    struct {
        /* For Linux code */
        uint8_t* perfMmapBuf;
        uint8_t* perfMmapAux;
        hwcnt_t hwCnts;
        int cpuInstrFd;
        int cpuBranchFd;
        int cpuIptBtsFd;
    } linux;

    struct {
        /* For NetBSD code */
        uint8_t* perfMmapBuf;
        uint8_t* perfMmapAux;
        hwcnt_t hwCnts;
        int cpuInstrFd;
        int cpuBranchFd;
        int cpuIptBtsFd;
    } netbsd;
} run_t;

/*
 * Go-style defer scoped implementation
 *
 * When compiled with clang, use: -fblocks -lBlocksRuntime
 *
 * Example of use:
 *
 * {
 *   int fd = open(fname, O_RDONLY);
 *   if (fd == -1) {
 *     error(....);
 *     return;
 *   }
 *   defer { close(fd); };
 *   ssize_t sz = read(fd, buf, sizeof(buf));
 *   ...
 *   ...
 * }
 *
 */

#define __STRMERGE(a, b) a##b
#define _STRMERGE(a, b) __STRMERGE(a, b)
#ifdef __clang__
#if __has_extension(blocks)
static void __attribute__((unused)) __clang_cleanup_func(void (^*dfunc)(void)) {
    (*dfunc)();
}

#define defer                                        \
    void (^_STRMERGE(__defer_f_, __COUNTER__))(void) \
        __attribute__((cleanup(__clang_cleanup_func))) __attribute__((unused)) = ^

#else /* __has_extension(blocks) */
#define defer UNIMPLEMENTED - NO - SUPPORT - FOR - BLOCKS - IN - YOUR - CLANG - ENABLED
#endif /*  __has_extension(blocks) */
#else  /* !__clang__, e.g.: gcc */

#define __block
#define _DEFER(a, count)                                                                      \
    auto void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)));         \
    int _STRMERGE(__defer_var_, count) __attribute__((cleanup(_STRMERGE(__defer_f_, count)))) \
        __attribute__((unused));                                                              \
    void _STRMERGE(__defer_f_, count)(void* _defer_arg __attribute__((unused)))
#define defer _DEFER(a, __COUNTER__)
#endif /* ifdef __clang__ */

/* Block scoped mutexes */
#define MX_SCOPED_LOCK(m) \
    MX_LOCK(m);           \
    defer {               \
        MX_UNLOCK(m);     \
    }

#define MX_SCOPED_RWLOCK_READ(m) \
    MX_RWLOCK_READ(m);           \
    defer {                      \
        MX_RWLOCK_UNLOCK(m);     \
    }
#define MX_SCOPED_RWLOCK_WRITE(m) \
    MX_RWLOCK_WRITE(m);           \
    defer {                       \
        MX_RWLOCK_UNLOCK(m);      \
    }

#endif
