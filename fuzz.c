/*
 *
 * honggfuzz - fuzzing routines
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
 * Felix Gröbert <groebert@google.com>
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

#include "fuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "honggfuzz.h"
#include "input.h"
#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/util.h"
#include "mangle.h"
#include "report.h"
#include "sancov.h"
#include "sanitizers.h"
#include "subproc.h"

static pthread_t fuzz_mainThread;

static void fuzz_getFileName(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    snprintf(fuzzer->fileName, PATH_MAX, "%s/honggfuzz.input.%" PRIu32 ".%s.%s", hfuzz->workDir,
             fuzzer->fuzzNo, basename(hfuzz->cmdline[0]), hfuzz->fileExtn);
}

static bool fuzz_prepareFileDynamically(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    fuzzer->origFileName = "[DYNAMIC]";
    struct dynfile_t *dynfile;

    {
        MX_SCOPED_LOCK(&hfuzz->dynfileq_mutex);

        if (hfuzz->dynfileqCnt == 0) {
            LOG_F("The dynamic file corpus is empty. Apparently, the initial fuzzing of the "
                  "provided file corpus (-f) has not produced any follow-up files with positive "
                  "coverage and/or CPU counters");
        }

        if (hfuzz->dynfileqCurrent == NULL
            || hfuzz->dynfileqCurrent == TAILQ_LAST(&hfuzz->dynfileq, dictq_t)) {
            hfuzz->dynfileqCurrent = TAILQ_FIRST(&hfuzz->dynfileq);
        }
        dynfile = hfuzz->dynfileqCurrent;
        hfuzz->dynfileqCurrent = TAILQ_NEXT(hfuzz->dynfileqCurrent, pointers);
    }

    memcpy(fuzzer->dynamicFile, dynfile->data, dynfile->size);
    fuzzer->dynamicFileSz = dynfile->size;

    mangle_mangleContent(hfuzz, fuzzer);

    if (hfuzz->persistent == false
        && files_writeBufToFile(fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
                                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC)
        == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFile(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, bool rewind)
{
    char fname[PATH_MAX];
    if (input_getNext(hfuzz, fname, rewind) == false) {
        return false;
    }
    fuzzer->origFileName = files_basename(fname);

    ssize_t fileSz = files_readFileToBufMax(fname, fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (fileSz < 0) {
        LOG_E("Couldn't read contents of '%s'", fname);
        return false;
    }
    fuzzer->dynamicFileSz = fileSz;

    mangle_mangleContent(hfuzz, fuzzer);

    if (hfuzz->persistent == false
        && files_writeBufToFile(fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
                                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC)
        == false) {
        LOG_E("Couldn't write buffer to file '%s'", fuzzer->fileName);
        return false;
    }

    return true;
}

static bool fuzz_prepareFileExternally(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    char fname[PATH_MAX];
    if (input_getNext(hfuzz, fname, true /* rewind */ )) {
        fuzzer->origFileName = files_basename(fname);
        if (files_copyFile(fname, fuzzer->fileName, NULL, false /* try_link */ ) == false) {
            LOG_E("files_copyFile('%s', '%s')", fname, fuzzer->fileName);
            return false;
        }
    } else {
        fuzzer->origFileName = "[EXTERNAL]";
        int dstfd = open(fuzzer->fileName, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0644);
        if (dstfd == -1) {
            PLOG_E("Couldn't create a temporary file '%s'", fuzzer->fileName);
            return false;
        }
        close(dstfd);
    }

    LOG_D("Created '%s' as an input file", fuzzer->fileName);

    const char *const argv[] = { hfuzz->externalCommand, fuzzer->fileName, NULL };
    if (subproc_System(hfuzz, fuzzer, argv) != 0) {
        LOG_E("Subprocess '%s' returned abnormally", hfuzz->externalCommand);
        return false;
    }
    LOG_D("Subporcess '%s' finished with success", hfuzz->externalCommand);

    ssize_t rsz = files_readFileToBufMax(fuzzer->fileName, fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (rsz < 0) {
        LOG_W("Couldn't read back '%s' to the buffer", fuzzer->fileName);
        return false;
    }
    fuzzer->dynamicFileSz = rsz;

    if (hfuzz->persistent) {
        unlink(fuzzer->fileName);
    }

    return true;
}

static bool fuzz_postProcessFile(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->persistent) {
        if (files_writeBufToFile(fuzzer->fileName, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
                                 O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC)
            == false) {
            LOG_E("Couldn't write file to '%s'", fuzzer->fileName);
            return false;
        }
    }

    const char *const argv[] = { hfuzz->postExternalCommand, fuzzer->fileName, NULL };
    if (subproc_System(hfuzz, fuzzer, argv) != 0) {
        LOG_E("Subprocess '%s' returned abnormally", hfuzz->postExternalCommand);
        return false;
    }
    LOG_D("Subporcess '%s' finished with success", hfuzz->externalCommand);

    ssize_t rsz = files_readFileToBufMax(fuzzer->fileName, fuzzer->dynamicFile, hfuzz->maxFileSz);
    if (rsz < 0) {
        LOG_W("Couldn't read back '%s' to the buffer", fuzzer->fileName);
        return false;
    }
    fuzzer->dynamicFileSz = rsz;

    return true;
}

static fuzzState_t fuzz_getState(honggfuzz_t * hfuzz)
{
    return ATOMIC_GET(hfuzz->state);
}

static void fuzz_setState(honggfuzz_t * hfuzz, fuzzState_t state)
{
    /* All threads must indicate willingness to switch to _HF_STATE_DYNAMIC_MAIN */
    if (state == _HF_STATE_DYNAMIC_MAIN) {
        static size_t cnt = 0;
        ATOMIC_PRE_INC(cnt);
        while (ATOMIC_GET(cnt) < hfuzz->threadsMax) {
            if (ATOMIC_GET(hfuzz->terminating) == true) {
                return;
            }
            sleep(1);
        }
    }

    static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
    MX_SCOPED_LOCK(&state_mutex);

    if (hfuzz->state == state) {
        return;
    }

    switch (state) {
    case _HF_STATE_DYNAMIC_PRE:
        LOG_I("Entering phase 1/2: Dry Run");
        break;
    case _HF_STATE_DYNAMIC_MAIN:
        LOG_I("Entering phase 2/2: Main");
        break;
    case _HF_STATE_STATIC:
        LOG_I("Entering phase: Static");
        break;
    default:
        LOG_I("Entering unknown phase: %d", state);
        break;
    }

    ATOMIC_SET(hfuzz->state, state);
}

static bool fuzz_runVerifier(honggfuzz_t * hfuzz, fuzzer_t * crashedFuzzer)
{
    int crashFd = -1;
    uint8_t *crashBuf = NULL;
    off_t crashFileSz = 0;

    crashBuf = files_mapFile(crashedFuzzer->crashFileName, &crashFileSz, &crashFd, false);
    if (crashBuf == NULL) {
        LOG_E("Couldn't open and map '%s' in R/O mode", crashedFuzzer->crashFileName);
        return false;
    }
    defer {
        munmap(crashBuf, crashFileSz);
        close(crashFd);
    };

    LOG_I("Launching verifier for %" PRIx64 " hash", crashedFuzzer->backtrace);
    for (int i = 0; i < _HF_VERIFIER_ITER; i++) {
        fuzzer_t vFuzzer = {
            .pid = 0,
            .persistentPid = 0,
            .state = fuzz_getState(hfuzz),
            .timeStartedMillis = util_timeNowMillis(),
            .crashFileName = {0},
            .pc = 0ULL,
            .backtrace = 0ULL,
            .access = 0ULL,
            .exception = 0,
            .dynamicFileSz = 0,
            .dynamicFile = NULL,
            .sanCovCnts = {
                           .hitBBCnt = 0ULL,
                           .totalBBCnt = 0ULL,
                           .dsoCnt = 0ULL,
                           .iDsoCnt = 0ULL,
                           .newBBCnt = 0ULL,
                           .crashesCnt = 0ULL,
                           },
            .report = {'\0'},
            .mainWorker = false,
            .fuzzNo = crashedFuzzer->fuzzNo,
            .persistentSock = -1,
            .tmOutSignaled = false,

            .linux = {
                      .hwCnts = {
                                 .cpuInstrCnt = 0ULL,.cpuBranchCnt = 0ULL,.bbCnt = 0ULL,.newBBCnt =
                                 0ULL,.softCntPc = 0ULL,.softCntEdge = 0ULL,.softCntCmp = 0ULL,
                                 },
                      .attachedPid = 0,
                      },
        };

        if (arch_archThreadInit(hfuzz, &vFuzzer) == false) {
            LOG_F("Could not initialize the thread");
        }

        fuzz_getFileName(hfuzz, &vFuzzer);
        if (files_writeBufToFile(vFuzzer.fileName, crashBuf, crashFileSz,
                                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC)
            == false) {
            LOG_E("Couldn't write buffer to file '%s'", vFuzzer.fileName);
            return false;
        }

        if (subproc_Run(hfuzz, &vFuzzer) == false) {
            LOG_F("subproc_Run()");
        }

        /* Delete intermediate files generated from verifier */
        unlink(vFuzzer.fileName);

        /* If stack hash doesn't match skip name tag and exit */
        if (crashedFuzzer->backtrace != vFuzzer.backtrace) {
            LOG_D("Verifier stack hash mismatch");
            return false;
        }
    }

    /* Workspace is inherited, just append a extra suffix */
    char verFile[PATH_MAX] = { 0 };
    snprintf(verFile, sizeof(verFile), "%s.verified", crashedFuzzer->crashFileName);

    /* Copy file with new suffix & remove original copy */
    bool dstFileExists = false;
    if (files_copyFile(crashedFuzzer->crashFileName, verFile, &dstFileExists, true /* try_link */ )) {
        LOG_I("Successfully verified, saving as (%s)", verFile);
        ATOMIC_POST_INC(hfuzz->verifiedCrashesCnt);
        unlink(crashedFuzzer->crashFileName);
    } else {
        if (dstFileExists) {
            LOG_I("It seems that '%s' already exists, skipping", verFile);
        } else {
            LOG_E("Couldn't copy '%s' to '%s'", crashedFuzzer->crashFileName, verFile);
            return false;
        }
    }

    return true;
}

static void fuzz_addFileToFileQ(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    struct dynfile_t *dynfile = (struct dynfile_t *)util_Malloc(sizeof(struct dynfile_t));
    dynfile->size = fuzzer->dynamicFileSz;
    dynfile->data = (uint8_t *) util_Malloc(fuzzer->dynamicFileSz);
    memcpy(dynfile->data, fuzzer->dynamicFile, fuzzer->dynamicFileSz);

    MX_SCOPED_LOCK(&hfuzz->dynfileq_mutex);
    TAILQ_INSERT_HEAD(&hfuzz->dynfileq, dynfile, pointers);
    hfuzz->dynfileqCnt++;

    /* No need to add new coverage if we are supposed to append new coverage-inducing inputs only */
    if (fuzzer->state == _HF_STATE_DYNAMIC_PRE && hfuzz->covDir == NULL) {
        LOG_D("New coverage found, but we're in the initial coverage assessment state. Skipping");
        return;
    }

    char fname[PATH_MAX];
    uint64_t crc64f = util_CRC64(fuzzer->dynamicFile, fuzzer->dynamicFileSz);
    uint64_t crc64r = util_CRC64Rev(fuzzer->dynamicFile, fuzzer->dynamicFileSz);
    snprintf(fname, sizeof(fname), "%s/%016" PRIx64 "%016" PRIx64 ".%08" PRIx32 ".honggfuzz.cov",
             hfuzz->covDir ? hfuzz->covDir : hfuzz->inputDir, crc64f, crc64r,
             (uint32_t) fuzzer->dynamicFileSz);

    if (access(fname, R_OK) == 0) {
        LOG_D("File '%s' already exists in the corpus directory", fname);
        return;
    }

    LOG_D("Adding file '%s' to the corpus directory", fname);

    if (files_writeBufToFile(fname, fuzzer->dynamicFile, fuzzer->dynamicFileSz,
                             O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC)
        == false) {
        LOG_W("Couldn't write buffer to file '%s'", fname);
    }
}

static void fuzz_perfFeedback(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->skipFeedbackOnTimeout && fuzzer->tmOutSignaled) {
        return;
    }

    LOG_D("New file size: %zu, Perf feedback new/cur (instr,branch): %" PRIu64 "/%" PRIu64 "/%"
          PRIu64 "/%" PRIu64 ", BBcnt new/total: %" PRIu64 "/%" PRIu64, fuzzer->dynamicFileSz,
          fuzzer->linux.hwCnts.cpuInstrCnt, hfuzz->linux.hwCnts.cpuInstrCnt,
          fuzzer->linux.hwCnts.cpuBranchCnt, hfuzz->linux.hwCnts.cpuBranchCnt,
          fuzzer->linux.hwCnts.newBBCnt, hfuzz->linux.hwCnts.bbCnt);

    MX_SCOPED_LOCK(&hfuzz->feedback_mutex);

    uint64_t softCntPc = 0UL;
    uint64_t softCntEdge = 0UL;
    uint64_t softCntCmp = 0UL;
    if (hfuzz->bbFd != -1) {
        softCntPc = ATOMIC_GET(hfuzz->feedback->pidFeedbackPc[fuzzer->fuzzNo]);
        ATOMIC_CLEAR(hfuzz->feedback->pidFeedbackPc[fuzzer->fuzzNo]);
        softCntEdge = ATOMIC_GET(hfuzz->feedback->pidFeedbackEdge[fuzzer->fuzzNo]);
        ATOMIC_CLEAR(hfuzz->feedback->pidFeedbackEdge[fuzzer->fuzzNo]);
        softCntCmp = ATOMIC_GET(hfuzz->feedback->pidFeedbackCmp[fuzzer->fuzzNo]);
        ATOMIC_CLEAR(hfuzz->feedback->pidFeedbackCmp[fuzzer->fuzzNo]);
    }

    int64_t diff0 = hfuzz->linux.hwCnts.cpuInstrCnt - fuzzer->linux.hwCnts.cpuInstrCnt;
    int64_t diff1 = hfuzz->linux.hwCnts.cpuBranchCnt - fuzzer->linux.hwCnts.cpuBranchCnt;

    /*
     * Coverage is the primary counter, the rest is secondary, and taken into consideration only
     * if the coverage counter has not been changed
     */
    if (fuzzer->linux.hwCnts.newBBCnt > 0 || softCntPc > 0 || softCntEdge > 0 || softCntCmp > 0
        || diff0 < 0 || diff1 < 0) {

        if (diff0 < 0) {
            hfuzz->linux.hwCnts.cpuInstrCnt = fuzzer->linux.hwCnts.cpuInstrCnt;
        }
        if (diff1 < 0) {
            hfuzz->linux.hwCnts.cpuBranchCnt = fuzzer->linux.hwCnts.cpuBranchCnt;
        }
        hfuzz->linux.hwCnts.bbCnt += fuzzer->linux.hwCnts.newBBCnt;
        hfuzz->linux.hwCnts.softCntPc += softCntPc;
        hfuzz->linux.hwCnts.softCntEdge += softCntEdge;
        hfuzz->linux.hwCnts.softCntCmp += softCntCmp;

        LOG_I("Size:%zu (i,b,edg,ip,hw,cmp): %" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%"
              PRIu64 "/%" PRIu64 ", Tot:%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
              "/%" PRIu64, fuzzer->dynamicFileSz, fuzzer->linux.hwCnts.cpuInstrCnt,
              fuzzer->linux.hwCnts.cpuBranchCnt, softCntEdge, softCntPc,
              fuzzer->linux.hwCnts.newBBCnt, softCntCmp, hfuzz->linux.hwCnts.cpuInstrCnt,
              hfuzz->linux.hwCnts.cpuBranchCnt, hfuzz->linux.hwCnts.softCntEdge,
              hfuzz->linux.hwCnts.softCntPc, hfuzz->linux.hwCnts.bbCnt,
              hfuzz->linux.hwCnts.softCntCmp);

        fuzz_addFileToFileQ(hfuzz, fuzzer);
    }
}

static void fuzz_sanCovFeedback(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (hfuzz->skipFeedbackOnTimeout && fuzzer->tmOutSignaled) {
        return;
    }

    LOG_D("File size (Best/New): %zu, SanCov feedback (bb,dso): Best: [%" PRIu64
          ",%" PRIu64 "] / New: [%" PRIu64 ",%" PRIu64 "], newBBs:%" PRIu64,
          fuzzer->dynamicFileSz, hfuzz->sanCovCnts.hitBBCnt,
          hfuzz->sanCovCnts.iDsoCnt, fuzzer->sanCovCnts.hitBBCnt, fuzzer->sanCovCnts.iDsoCnt,
          fuzzer->sanCovCnts.newBBCnt);

    MX_SCOPED_LOCK(&hfuzz->feedback_mutex);

    int64_t diff0 = hfuzz->linux.hwCnts.cpuInstrCnt - fuzzer->linux.hwCnts.cpuInstrCnt;
    int64_t diff1 = hfuzz->linux.hwCnts.cpuBranchCnt - fuzzer->linux.hwCnts.cpuBranchCnt;

    /*
     * Keep mutated seed if:
     *  a) Newly discovered (not met before) BBs
     *  b) More instrumented DSOs loaded
     *
     * TODO: (a) method can significantly assist to further improvements in interesting areas
     * discovery if combined with seeds pool/queue support. If a runtime queue is maintained
     * more interesting seeds can be saved between runs instead of instantly discarded
     * based on current absolute elitism (only one mutated seed is promoted).
     */

    bool newCov = (fuzzer->sanCovCnts.newBBCnt > 0
                   || hfuzz->sanCovCnts.iDsoCnt < fuzzer->sanCovCnts.iDsoCnt);

    if (newCov || (diff0 < 0 || diff1 < 0)) {
        LOG_I("SanCov Update: fsize:%zu, newBBs:%" PRIu64
              ", (Cur,New): %" PRIu64 "/%" PRIu64 ",%" PRIu64 "/%" PRIu64,
              fuzzer->dynamicFileSz, fuzzer->sanCovCnts.newBBCnt,
              hfuzz->sanCovCnts.hitBBCnt, hfuzz->sanCovCnts.iDsoCnt, fuzzer->sanCovCnts.hitBBCnt,
              fuzzer->sanCovCnts.iDsoCnt);

        hfuzz->sanCovCnts.hitBBCnt += fuzzer->sanCovCnts.newBBCnt;
        hfuzz->sanCovCnts.dsoCnt = fuzzer->sanCovCnts.dsoCnt;
        hfuzz->sanCovCnts.iDsoCnt = fuzzer->sanCovCnts.iDsoCnt;
        hfuzz->sanCovCnts.crashesCnt += fuzzer->sanCovCnts.crashesCnt;
        hfuzz->sanCovCnts.newBBCnt = fuzzer->sanCovCnts.newBBCnt;

        if (hfuzz->sanCovCnts.totalBBCnt < fuzzer->sanCovCnts.totalBBCnt) {
            /* Keep only the max value (for dlopen cases) to measure total target coverage */
            hfuzz->sanCovCnts.totalBBCnt = fuzzer->sanCovCnts.totalBBCnt;
        }

        hfuzz->linux.hwCnts.cpuInstrCnt = fuzzer->linux.hwCnts.cpuInstrCnt;
        hfuzz->linux.hwCnts.cpuBranchCnt = fuzzer->linux.hwCnts.cpuBranchCnt;

        fuzz_addFileToFileQ(hfuzz, fuzzer);
    }
}

static void fuzz_fuzzLoop(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    fuzzer->pid = 0;
    fuzzer->timeStartedMillis = util_timeNowMillis();
    fuzzer->state = fuzz_getState(hfuzz);
    fuzzer->crashFileName[0] = '\0';
    fuzzer->pc = 0ULL;
    fuzzer->backtrace = 0ULL;
    fuzzer->access = 0ULL;
    fuzzer->exception = 0;
    fuzzer->report[0] = '\0';
    fuzzer->mainWorker = true;
    fuzzer->origFileName = "DYNAMIC";
    fuzzer->flipRate = hfuzz->origFlipRate;
    fuzzer->dynamicFileSz = 0;

    fuzzer->sanCovCnts.hitBBCnt = 0ULL;
    fuzzer->sanCovCnts.totalBBCnt = 0ULL;
    fuzzer->sanCovCnts.dsoCnt = 0ULL;
    fuzzer->sanCovCnts.newBBCnt = 0ULL;
    fuzzer->sanCovCnts.crashesCnt = 0ULL;

    fuzzer->linux.hwCnts.cpuInstrCnt = 0ULL;
    fuzzer->linux.hwCnts.cpuBranchCnt = 0ULL;
    fuzzer->linux.hwCnts.bbCnt = 0ULL;
    fuzzer->linux.hwCnts.newBBCnt = 0ULL;

    if (fuzzer->state == _HF_STATE_DYNAMIC_PRE) {
        fuzzer->flipRate = 0.0f;
        if (fuzz_prepareFile(hfuzz, fuzzer, false /* rewind */ ) == false) {
            fuzz_setState(hfuzz, _HF_STATE_DYNAMIC_MAIN);
            fuzzer->state = fuzz_getState(hfuzz);
        }
    }

    if (ATOMIC_GET(hfuzz->terminating) == true) {
        return;
    }

    if (fuzzer->state == _HF_STATE_DYNAMIC_MAIN) {
        if (hfuzz->externalCommand) {
            if (!fuzz_prepareFileExternally(hfuzz, fuzzer)) {
                LOG_F("fuzz_prepareFileExternally() failed");
            }
        } else if (!fuzz_prepareFileDynamically(hfuzz, fuzzer)) {
            LOG_F("fuzz_prepareFileDynamically() failed");
        }

        if (hfuzz->postExternalCommand) {
            if (!fuzz_postProcessFile(hfuzz, fuzzer)) {
                LOG_F("fuzz_postProcessFile() failed");
            }
        }
    }

    if (fuzzer->state == _HF_STATE_STATIC) {
        if (hfuzz->externalCommand) {
            if (!fuzz_prepareFileExternally(hfuzz, fuzzer)) {
                LOG_F("fuzz_prepareFileExternally() failed");
            }
        } else {
            if (!fuzz_prepareFile(hfuzz, fuzzer, true /* rewind */ )) {
                LOG_F("fuzz_prepareFile() failed");
            }
        }

        if (hfuzz->postExternalCommand != NULL) {
            if (!fuzz_postProcessFile(hfuzz, fuzzer)) {
                LOG_F("fuzz_postProcessFile() failed");
            }
        }
    }

    if (subproc_Run(hfuzz, fuzzer) == false) {
        LOG_F("subproc_Run()");
    }

    if (hfuzz->persistent == false) {
        unlink(fuzzer->fileName);
    }

    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_perfFeedback(hfuzz, fuzzer);
    }
    if (hfuzz->useSanCov) {
        fuzz_sanCovFeedback(hfuzz, fuzzer);
    }

    if (hfuzz->useVerifier && (fuzzer->crashFileName[0] != 0) && fuzzer->backtrace) {
        if (!fuzz_runVerifier(hfuzz, fuzzer)) {
            LOG_I("Failed to verify %s", fuzzer->crashFileName);
        }
    }

    report_Report(hfuzz, fuzzer->report);
}

static void *fuzz_threadNew(void *arg)
{
    honggfuzz_t *hfuzz = (honggfuzz_t *) arg;
    unsigned int fuzzNo = ATOMIC_POST_INC(hfuzz->threadsActiveCnt);
    LOG_I("Launched new fuzzing thread, no. #%" PRId32, fuzzNo);

    fuzzer_t fuzzer = {
        .pid = 0,
        .persistentPid = 0,
        .dynamicFile = util_Calloc(hfuzz->maxFileSz),
        .fuzzNo = fuzzNo,
        .persistentSock = -1,
        .tmOutSignaled = false,
        .fileName = "[UNSET]",

        .linux.attachedPid = 0,
    };
    defer {
        free(fuzzer.dynamicFile);
    };
    fuzz_getFileName(hfuzz, &fuzzer);

    if (arch_archThreadInit(hfuzz, &fuzzer) == false) {
        LOG_F("Could not initialize the thread");
    }

    for (;;) {
        /* Check if dry run mode with verifier enabled */
        if (hfuzz->origFlipRate == 0.0L && hfuzz->useVerifier) {
            if (ATOMIC_POST_INC(hfuzz->mutationsCnt) >= hfuzz->fileCnt) {
                ATOMIC_POST_INC(hfuzz->threadsFinished);
                break;
            }
        }
        /* Check for max iterations limit if set */
        else if ((ATOMIC_POST_INC(hfuzz->mutationsCnt) >= hfuzz->mutationsMax)
                 && hfuzz->mutationsMax) {
            ATOMIC_POST_INC(hfuzz->threadsFinished);
            break;
        }

        fuzz_fuzzLoop(hfuzz, &fuzzer);

        if (ATOMIC_GET(hfuzz->terminating) == true) {
            break;
        }

        if (hfuzz->exitUponCrash && ATOMIC_GET(hfuzz->crashesCnt) > 0) {
            LOG_I("Seen a crash. Terminating all fuzzing threads");
            ATOMIC_SET(hfuzz->terminating, true);
            break;
        }
    }

    LOG_I("Terminating thread no. #%" PRId32, fuzzNo);
    ATOMIC_POST_INC(hfuzz->threadsFinished);
    pthread_kill(fuzz_mainThread, SIGALRM);
    return NULL;
}

static void fuzz_runThread(honggfuzz_t * hfuzz, pthread_t * thread, void *(*thread_func) (void *))
{
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setstacksize(&attr, _HF_PTHREAD_STACKSIZE);
    pthread_attr_setguardsize(&attr, (size_t) sysconf(_SC_PAGESIZE));

    if (pthread_create(thread, &attr, thread_func, (void *)hfuzz) < 0) {
        PLOG_F("Couldn't create a new thread");
    }

    pthread_attr_destroy(&attr);

    return;
}

void fuzz_threadsStart(honggfuzz_t * hfuzz, pthread_t * threads)
{
    fuzz_mainThread = pthread_self();

    if (!arch_archInit(hfuzz)) {
        LOG_F("Couldn't prepare arch for fuzzing");
    }
    if (!sanitizers_Init(hfuzz)) {
        LOG_F("Couldn't prepare sanitizer options");
    }
    if (!sancov_Init(hfuzz)) {
        LOG_F("Couldn't prepare sancov options");
    }

    if (hfuzz->useSanCov || hfuzz->dynFileMethod != _HF_DYNFILE_NONE) {
        fuzz_setState(hfuzz, _HF_STATE_DYNAMIC_PRE);
    } else {
        fuzz_setState(hfuzz, _HF_STATE_STATIC);
    }

    for (size_t i = 0; i < hfuzz->threadsMax; i++) {
        fuzz_runThread(hfuzz, &threads[i], fuzz_threadNew);
    }
}

void fuzz_threadsStop(honggfuzz_t * hfuzz, pthread_t * threads)
{
    for (size_t i = 0; i < hfuzz->threadsMax; i++) {
        void *retval;
        if (pthread_join(threads[i], &retval) != 0) {
            PLOG_F("Couldn't pthread_join() thread: %zu", i);
        }
    }
    LOG_I("All threads done");
}
