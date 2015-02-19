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
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/types.h>

#define PROG_NAME "honggfuzz"
#define PROG_VERSION "0.4"
#define PROG_AUTHORS "Robert Swiecki <swiecki@google.com> and others, Copyright 2010-2015 by Google Inc. All Rights Reserved."

/* Name of the template which will be replaced with the proper name of the file */
#define _HF_FILE_PLACEHOLDER "___FILE___"

/* Default name of the report created with some architectures */
#define _HF_REPORT_FILE "HONGGFUZZ.REPORT.TXT"

/* Default stack-size of created threads. Must be bigger then _HF_DYNAMIC_FILE_MAX_SZ */
#define _HF_PTHREAD_STACKSIZE (1024 * 1024 * 4) /* 2MB */

/* Maximal size of a dynamically created file (-D) */
#define _HF_DYNAMIC_FILE_MAX_SZ (256 * 1024)

typedef struct {
    char **cmdline;
    char *inputFile;
    bool nullifyStdio;
    bool fuzzStdin;
    bool saveUnique;
    char *fileExtn;
    double flipRate;
    char flipMode;
    char *externalCommand;
    long tmOut;
    long mutationsMax;
    long mutationsCnt;
    long threadsMax;
    void *ignoreAddr;
    char *reportFile;
    unsigned long asLimit;
    char **files;
    int fileCnt;
    sem_t *sem;
    int pid;

    char createDynamically;
    uint8_t dynamicFileBest[_HF_DYNAMIC_FILE_MAX_SZ];
    size_t dynamicFileBestSz;
    /* For linux/ code */
    int64_t branchBestCnt;
    int64_t branchBestCntIni;
    pthread_mutex_t dynamicFile_mutex;
} honggfuzz_t;

typedef struct fuzzer_t {
    pid_t pid;
    time_t timeStarted;
    char origFileName[PATH_MAX];
    char fileName[PATH_MAX];
    uint64_t pc;
    uint64_t backtrace;
    uint64_t access;
    int exception;
    char report[8192];

    /* For linux/ code */
    uint8_t dynamicFile[_HF_DYNAMIC_FILE_MAX_SZ];
    size_t dynamicFileSz;
    int64_t branchCnt;
} fuzzer_t;

#define _HF_MAX_FUNCS 200
typedef struct {
    void *pc;
    char func[64];
    int line;
} funcs_t;

#endif
