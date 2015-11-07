/*
 *
 * honggfuzz - core structures and macros
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2015 by Google Inc. All Rights Reserved.
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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/types.h>

#define PROG_NAME "honggfuzz"
#define PROG_VERSION "0.6rc"
#define PROG_AUTHORS "Robert Swiecki <swiecki@google.com> et al.,\nCopyright 2010-2015 by Google Inc. All Rights Reserved."

/* Name of the template which will be replaced with the proper name of the file */
#define _HF_FILE_PLACEHOLDER "___FILE___"

/* Default name of the report created with some architectures */
#define _HF_REPORT_FILE "HONGGFUZZ.REPORT.TXT"

/* Default stack-size of created threads. Must be bigger then _HF_DYNAMIC_FILE_MAX_SZ */
#define _HF_PTHREAD_STACKSIZE (1024 * 1024 * 8) /* 8MB */

/* Align to the upper-page boundary */
#define _HF_PAGE_ALIGN_UP(x)  (((size_t)x + (size_t)getpagesize() - (size_t)1) & ~((size_t)getpagesize() - (size_t)1))

/* String buffer size for function names in stack traces produced from libunwind */
#define _HF_FUNC_NAME_SZ    256 // Should be alright for mangled C++ procs too

/* Number of crash verifier iterations before tag crash as stable */
#define _HF_VERIFIER_ITER   5

typedef enum {
    _HF_DYNFILE_NONE = 0x0,
    _HF_DYNFILE_INSTR_COUNT = 0x1,
    _HF_DYNFILE_BRANCH_COUNT = 0x2,
    _HF_DYNFILE_UNIQUE_BLOCK_COUNT = 0x8,
    _HF_DYNFILE_UNIQUE_EDGE_COUNT = 0x10,
    _HF_DYNFILE_CUSTOM = 0x20,
} dynFileMethod_t;

typedef struct {
    uint64_t cpuInstrCnt;
    uint64_t cpuBranchCnt;
    uint64_t pcCnt;
    uint64_t pathCnt;
    uint64_t customCnt;
} hwcnt_t;

typedef struct {
    char **cmdline;
    char *inputFile;
    bool nullifyStdio;
    bool fuzzStdin;
    bool saveUnique;
    bool useScreen;
    bool useVerifier;
    char *fileExtn;
    char *workDir;
    double flipRate;
    char *externalCommand;
    const char *dictionaryFile;
    const char **dictionary;
    const char *blacklistFile;
    uint64_t *blacklist;
    size_t blacklistCnt;
    long tmOut;
    size_t dictionaryCnt;
    size_t mutationsMax;
    size_t threadsMax;
    size_t threadsFinished;
    size_t maxFileSz;
    char *reportFile;
    uint64_t asLimit;
    char **files;
    size_t fileCnt;
    size_t lastCheckedFileIndex;
    pid_t pid;
    char *envs[128];

    time_t timeStart;
    size_t mutationsCnt;
    size_t crashesCnt;
    size_t uniqueCrashesCnt;
    size_t verifiedCrashesCnt;
    size_t blCrashesCnt;
    size_t timeoutedCnt;

    /* For the linux/ code */
    uint8_t *dynamicFileBest;
    size_t dynamicFileBestSz;
    dynFileMethod_t dynFileMethod;
    hwcnt_t hwCnts;
    uint64_t dynamicCutOffAddr;
    pthread_mutex_t dynamicFile_mutex;
    bool disableRandomization;
    bool msanReportUMRS;
    void *ignoreAddr;
} honggfuzz_t;

typedef struct fuzzer_t {
    pid_t pid;
    int64_t timeStartedMillis;
    char origFileName[PATH_MAX];
    char fileName[PATH_MAX];
    char crashFileName[PATH_MAX];
    uint64_t pc;
    uint64_t backtrace;
    uint64_t access;
    int exception;
    char report[8192];
    bool mainWorker;

    /* For linux/ code */
    uint8_t *dynamicFile;
    hwcnt_t hwCnts;
    size_t dynamicFileSz;
} fuzzer_t;

#define _HF_MAX_FUNCS 80
typedef struct {
    void *pc;
    char func[_HF_FUNC_NAME_SZ];
    size_t line;
} funcs_t;

#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))

#endif
