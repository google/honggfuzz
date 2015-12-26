/*
 *
 * honggfuzz - sanitizer coverage feedback parsing
 * -----------------------------------------------
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

#include "common.h"
#include "sancov.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "util.h"
#include "files.h"
#include "log.h"

/* Magic values */
#define kMagic32 0xC0BFFFFFFFFFFF32
#define kMagic64 0xC0BFFFFFFFFFFF64

void arch_sanCovAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (!hfuzz->useSanCov) {
        return;
    }

    int dataFd = -1;
    uint8_t *dataBuf = NULL;
    off_t dataFileSz = 0, pos = 0;
    bool is32bit = true;
    char covFile[PATH_MAX] = { 0 };

    /* 
     * Firstly check case where target exited normally 
     * or with sanitizer handled signal. Otherwise proceed
     * with rawunpack method
     */
    snprintf(covFile, sizeof(covFile), "%s.%d.sancov", files_basename(hfuzz->cmdline[0]),
             fuzzer->pid);
    if (files_exists(covFile)) {
        dataBuf = files_mapFile(covFile, &dataFileSz, &dataFd, false);
        if (dataBuf == NULL) {
            LOG_E("Couldn't open and map '%s' in R/O mode", covFile);
            return;
        }

        if (dataFileSz < 8) {
            LOG_E("Coverage data file too short");
            goto bail;
        }

        /* Check magic values & derive PC length */
        uint64_t magic = util_getUINT64(dataBuf);
        LOG_E("Magic: %" PRIx64 "", magic);
        if (magic == kMagic32) {
            LOG_D("32bit target");
        } else if (magic == kMagic64) {
            LOG_D("64bit target");
            is32bit = false;
        } else {
            LOG_E("Invalid coverage data file");
            goto bail;
        }
        pos += 8;
    } else {
        /* TODO: Fully parse .map file and target only interesting PCs */
        snprintf(covFile, sizeof(covFile), "%d.sancov.map", fuzzer->pid);
        FILE *fCovMap = fopen(covFile, "rb");
        if (fCovMap == NULL) {
            PLOG_E("Couldn't open '%s' - R/O mode", covFile);
            goto bail;
        }

        /* First line contains PC length (32/64-bit) */
        char *lineptr = NULL;
        size_t n = 0;
        if (getline(&lineptr, &n, fCovMap) == -1) {
            LOG_E("Invalid map file '%s'", covFile);
            fclose(fCovMap);
            goto bail;
        }

        int pcLen = atoi(lineptr);
        if (pcLen == 32) {
            is32bit = true;
        } else if (pcLen == 64) {
            is32bit = false;
        } else {
            LOG_E("Invalid PC length (%d) in map file '%s'", pcLen, covFile);
        }

        fclose(fCovMap);
        unlink(covFile);
        snprintf(covFile, sizeof(covFile), "%d.sancov.raw", fuzzer->pid);

        dataBuf = files_mapFile(covFile, &dataFileSz, &dataFd, false);
        if (dataBuf == NULL) {
            LOG_E("Couldn't open and map '%s' in R/O mode", covFile);
            return;
        }
    }

    uint64_t nPCs = 0;
    while (pos < dataFileSz) {
        if (is32bit) {
            uint32_t pc = util_getUINT32(dataBuf + pos);
            pos += 4;
            if (pc == 0x0)
                continue;
        } else {
            uint64_t pc = util_getUINT64(dataBuf + pos);
            pos += 8;
            if (pc == 0x0)
                continue;
        }
        nPCs++;
    }
    fuzzer->sanCovCnts.pcCnt = nPCs;

 bail:
    unlink(covFile);
    if (dataBuf) {
        munmap(dataBuf, dataFileSz);
    }
    if (dataFd != -1) {
        close(dataFd);
    }
}
