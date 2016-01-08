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

/*
 * Clang sanitizer coverage (sancov) data parsing functions. Supported methods:
 * - raw unified data (preferred method)
 * - individual data per executable/DSO (not preferred since lots of data lost if instrumented
 *   code exits abnormally or with sanitizer unhandled signal (common in Android OS)
 * 
 * For raw-unpack method a global (shared across workers) Trie is created for the chosen 
 * initial seed and maintained until seed is replaced. Trie nodes store the loaded (as exposed
 * from *.sancov.map file) execs/DSOs from target application using the map name as key. Trie node
 * data struct (trieData_t) maintains information for each instrumented map including a bitmap with
 * all hit relative PC addresses (realPC - baseAddr to circumvent ASLR). Map's bitmap is updated while
 * new areas on target application are discovered based on absolute elitism implemented at
 * fuzz_sanCovFeedback().
 * 
 * For individual data files a PID (fuzzer's thread) based filename search is performed to identify
 * all files belonging to examined execution. This method doesn't implement yet bitmap runtime data
 * to detect newly discovered areas. It's mainly used so far as a comparison metric for raw-unpack method
 * and stability check for sancov experimental features such as coverage counters:
 * http://clang.llvm.org/docs/SanitizerCoverage.html
 */

#include "common.h"
#include "sancov.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <dirent.h>

#include "util.h"
#include "files.h"
#include "log.h"

/* sancov files magic values */
#define kMagic32 0xC0BFFFFFFFFFFF32
#define kMagic64 0xC0BFFFFFFFFFFF64

/* 
 * bitmap implementation
 */
static bitmap_t *arch_newBitmap(uint32_t capacity)
{
    bitmap_t *pBM = malloc(sizeof(bitmap_t));
    if (pBM == NULL) {
        PLOG_E("malloc(%zu) failed", sizeof(bitmap_t));
        return NULL;
    }
    pBM->capacity = capacity;
    pBM->nChunks = (capacity + 31) / 32;
    pBM->pChunks = malloc(pBM->nChunks * sizeof(uint32_t));
    if (pBM->pChunks == NULL) {
        PLOG_E("malloc(%zu) failed", pBM->nChunks * sizeof(uint32_t));
        return NULL;
    }
    memset(pBM->pChunks, 0, pBM->nChunks * sizeof(uint32_t));
    return pBM;
}

static inline bool arch_queryBitmap(bitmap_t * pBM, uint32_t index)
{
    if (pBM->pChunks[index / 32] & (1 << (index % 32))) {
        return true;
    }
    return false;
}

static inline void arch_setBitmap(bitmap_t * pBM, uint32_t index)
{
    /* This will be removed. So far checks only to verify accepted ranges. */
    if (index >= pBM->capacity) {
        LOG_E("Out of range index (%u > %u)", index, pBM->capacity);
    }
    pBM->pChunks[index / 32] |= (1 << (index % 32));
}

static inline void arch_destroyBitmap(bitmap_t * pBM)
{
    free(pBM->pChunks);
    free(pBM);
}

/* 
 * Trie implementation
 */
static node_t *arch_trieCreateNode(char key)
{
    node_t *node = (node_t *) malloc(sizeof(node_t));
    if (node == NULL) {
        PLOG_E("malloc(%zu) failed", sizeof(node_t));
        return node;
    }
    node->key = key;
    node->next = NULL;
    node->children = NULL;
    node->parent = NULL;
    node->prev = NULL;

    /* Zero init node's data struct */
    memset(&node->data, 0, sizeof(trieData_t));
    return node;
}

static node_t *arch_trieSearch(node_t * root, const char *key)
{
    node_t *pNodeLevel = root, *pNodePtr = NULL;
    int nodeLevelId = 0;
    while (1) {
        node_t *pNodeFound = NULL, *pCurNode = NULL;
        for (pCurNode = pNodeLevel; pCurNode != NULL; pCurNode = pCurNode->next) {
            if (pCurNode->key == *key) {
                pNodeFound = pCurNode;
                nodeLevelId++;
                break;
            }
        }
        if (pNodeFound == NULL) {
            return NULL;
        }
        if (*key == '\0') {
            pNodePtr = pCurNode;
            return pNodePtr;
        }
        pNodeLevel = pNodeFound->children;
        key++;
    }
}

static void arch_trieAdd(node_t ** root, const char *key)
{
    if (*root == NULL) {
        LOG_E("Invalid Trie (NULL root node)");
        return;
    }

    /* Traverse Trie */
    node_t *pTravNode = (*root)->children;
    if (pTravNode == NULL) {
        /* First node */
        for (pTravNode = *root; *key != '\0'; pTravNode = pTravNode->children) {
            pTravNode->children = arch_trieCreateNode(*key);
            pTravNode->children->parent = pTravNode;
            key++;
        }
        pTravNode->children = arch_trieCreateNode('\0');
        pTravNode->children->parent = pTravNode;
        return;
    }

    while (*key != '\0') {
        if (*key == pTravNode->key) {
            key++;
            pTravNode = pTravNode->children;
        } else {
            break;
        }
    }
    while (pTravNode->next) {
        if (*key == pTravNode->next->key) {
            key++;
            arch_trieAdd(&(pTravNode->next), key);
            return;
        }
        pTravNode = pTravNode->next;
    }
    if (*key) {
        pTravNode->next = arch_trieCreateNode(*key);
    } else {
        pTravNode->next = arch_trieCreateNode(*key);
    }
    pTravNode->next->parent = pTravNode->parent;
    pTravNode->next->prev = pTravNode;
    if (!*key) {
        return;
    }
    key++;
    for (pTravNode = pTravNode->next; *key; pTravNode = pTravNode->children) {
        pTravNode->children = arch_trieCreateNode(*key);
        pTravNode->children->parent = pTravNode;
        key++;
    }
    pTravNode->children = arch_trieCreateNode('\0');
    pTravNode->children->parent = pTravNode;

    return;
}

static inline void arch_trieFreeNode(node_t * node)
{
    /* First destroy bitmap heap buffers allocated for instrumented maps */
    if (node->data.pBM) {
        arch_destroyBitmap(node->data.pBM);
    }
    free(node);
}

static inline void arch_trieCreate(node_t ** root)
{
    /* Create root node if new Trie */
    *root = arch_trieCreateNode('\0');
}

/* Destroy Trie - iterate nodes and free memory */
static void arch_trieDestroy(node_t * root)
{
    node_t *pNode = root;
    node_t *pNodeTmp = root;
    while (pNode) {
        while (pNode->children) {
            pNode = pNode->children;
        }

        if (pNode->prev && pNode->next) {
            pNodeTmp = pNode;
            pNode->next->prev = pNode->prev;
            pNode->prev->next = pNode->next;
            arch_trieFreeNode(pNodeTmp);
        } else if (pNode->prev && !pNode->next) {
            pNodeTmp = pNode;
            pNode->prev->next = NULL;
            arch_trieFreeNode(pNodeTmp);
        } else if (!pNode->prev && pNode->next) {
            pNodeTmp = pNode;
            pNode->parent->children = pNode->next;
            pNode->next->prev = NULL;
            pNode = pNode->next;
            arch_trieFreeNode(pNodeTmp);
        } else {
            pNodeTmp = pNode;
            if (pNode->parent == NULL) {
                /* Root */
                arch_trieFreeNode(pNodeTmp);
                return;
            }
            pNode = pNode->parent;
            pNode->children = NULL;
            arch_trieFreeNode(pNodeTmp);
        }
    }
}

/* Modified interpolation search algorithm to search for nearest address fit */
static inline uint64_t arch_interpSearch(uint64_t * buf, uint64_t size, uint64_t key)
{
    /* Avoid extra checks assuming caller always provides non-zero array size */
    uint64_t low = 0;
    uint64_t high = size - 1;
    uint64_t mid = high;

    while (buf[high] != buf[low] && key >= buf[low] && key <= buf[high]) {
        mid = low + (key - buf[low]) * ((high - low) / (buf[high] - buf[low]));
        if (buf[mid] < key) {
            low = mid + 1;
        } else if (key < buf[mid]) {
            high = mid - 1;
        } else {
            return mid;
        }
    }
    return mid;
}

/* qsort struct comparison function (memMap_t struct start addr field) */
static int arch_qsortCmp(const void *a, const void *b)
{
    memMap_t *pA = (memMap_t *) a;
    memMap_t *pB = (memMap_t *) b;
    if (pA->start < pB->start) {
        return -1;
    } else if (pA->start > pB->start) {
        return 1;
    } else {
        /* Normally we should never hit that case */
        LOG_W("Duplicate map start addr detected");
        return 0;
    }

}

static bool arch_sanCovParseRaw(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int dataFd = -1;
    uint8_t *dataBuf = NULL;
    off_t dataFileSz = 0, pos = 0;
    bool is32bit = true, ret = false, isSeedFirstRun = false;
    char covFile[PATH_MAX] = { 0 };

    /* Fuzzer local runtime data structs - need free() before exit */
    uint64_t *startMapsIndex = NULL;
    memMap_t *mapsBuf = NULL;

    /* Local counters */
    uint64_t nPCs = 0;          /* Total PCs found in raw file */
    uint64_t nZeroPCs = 0;      /* Number of non-hit instrumented blocks */
    uint64_t mapsNum = 0;       /* Total number of entries in map file */
    uint64_t noCovMapsNum = 0;  /* Loaded DSOs not compiled with coverage */

    /* File line-by-line read help buffers */
    char *pLine = NULL;
    size_t lineSz = 0;

    /* Coverage data analysis starts by parsing map file listing */
    snprintf(covFile, sizeof(covFile), "%s/%s/%d.sancov.map", hfuzz->workDir, _HF_SANCOV_DIR,
             fuzzer->pid);
    if (!files_exists(covFile)) {
        LOG_D("sancov map file not found");
        return false;
    }
    FILE *fCovMap = fopen(covFile, "rb");
    if (fCovMap == NULL) {
        PLOG_E("Couldn't open '%s' - R/O mode", covFile);
        goto bail;
    }

    /* First line contains PC length (32/64-bit) */
    if (getline(&pLine, &lineSz, fCovMap) == -1) {
        LOG_E("Invalid map file '%s'", covFile);
        fclose(fCovMap);
        goto bail;
    }
    int pcLen = atoi(pLine);
    if (pcLen == 32) {
        is32bit = true;
    } else if (pcLen == 64) {
        is32bit = false;
    } else {
        LOG_E("Invalid PC length (%d) in map file '%s'", pcLen, covFile);
    }

    /* Interaction with global Trie should mutex wrap to avoid threads races */
    MX_LOCK(&hfuzz->sanCov_mutex);
    {
        /* If runtime data destroy flag, new seed has been picked so destroy old & create new Trie */
        if (hfuzz->clearCovMetadata == true) {
            /* Since this path is invoked on first run too, destroy old Trie only if exists */
            if (hfuzz->covMetadata != NULL) {
                arch_trieDestroy(hfuzz->covMetadata);
            }
            arch_trieCreate(&hfuzz->covMetadata);
            hfuzz->clearCovMetadata = false;
            isSeedFirstRun = true;
        }
    }
    MX_UNLOCK(&hfuzz->sanCov_mutex);

    /* See if #maps is available from previous run to avoid realloc inside loop */
    uint64_t prevMapsNum = __sync_fetch_and_add(&hfuzz->sanCovCnts.dsoCnt, 0UL);
    if (prevMapsNum > 0) {
        if ((mapsBuf = malloc(prevMapsNum * sizeof(memMap_t))) == NULL) {
            PLOG_E("malloc failed (sz=%" PRIu64 ")", prevMapsNum * sizeof(memMap_t));
            /* This will be picked-up later from realloc branch */
            prevMapsNum = 0;
        }
    }

    /* Iterate map entries */
    for (;;) {
        if (getline(&pLine, &lineSz, fCovMap) == -1) {
            break;
        }

        /* Trim trailing whitespaces, not sure if needed copied from upstream sancov.py */
        char *lineEnd = pLine + strlen(pLine) - 1;
        while (lineEnd > pLine && isspace(*lineEnd)) {
            lineEnd--;
        }
        *(lineEnd + 1) = 0;

        /* 
         * Each line has following format:
         * Start    End      Base     bin/DSO name
         * b5843000 b584e6ac b5843000 liblog.so
         */
        memMap_t mapData = { 0 };
        char *savePtr = NULL;
        mapData.start = strtoull(strtok_r(pLine, " ", &savePtr), NULL, 16);
        mapData.end = strtoull(strtok_r(NULL, " ", &savePtr), NULL, 16);
        mapData.base = strtoull(strtok_r(NULL, " ", &savePtr), NULL, 16);
        char *mapName = strtok_r(NULL, " ", &savePtr);
        memcpy(mapData.mapName, mapName, strlen(mapName));

        /* Interaction with global Trie should mutex wrap to avoid threads races */
        MX_LOCK(&hfuzz->sanCov_mutex);
        {
            /* Add entry to Trie with zero data if not already */
            if (!arch_trieSearch(hfuzz->covMetadata->children, mapData.mapName)) {
                arch_trieAdd(&hfuzz->covMetadata, mapData.mapName);
            }
        }
        MX_UNLOCK(&hfuzz->sanCov_mutex);

        /* If not DSO number history (first run) or new DSO loaded, realloc local maps metadata buf */
        if (prevMapsNum == 0 || prevMapsNum < mapsNum) {
            if ((mapsBuf = realloc(mapsBuf, (size_t) (mapsNum + 1) * sizeof(memMap_t))) == NULL) {
                PLOG_E("realloc failed (sz=%" PRIu64 ")", (mapsNum + 1) * sizeof(memMap_t));
                goto bail;
            }
        }

        /* Add entry to local maps metadata array */
        memcpy(&mapsBuf[mapsNum], &mapData, sizeof(memMap_t));

        /* Increase loaded maps counter (includes non-instrumented DSOs too) */
        mapsNum++;
    }

    /* Delete .sancov.map file */
    fclose(fCovMap);
    unlink(covFile);

    /* Create a quick index array with maps start addresses */
    startMapsIndex = malloc(mapsNum * sizeof(uint64_t));
    if (startMapsIndex == NULL) {
        PLOG_E("malloc failed (sz=%" PRIu64 ")", mapsNum * sizeof(uint64_t));
        goto bail;
    }

    /* Sort quick maps index */
    qsort(mapsBuf, mapsNum, sizeof(memMap_t), arch_qsortCmp);
    for (size_t i = 0; i < mapsNum; i++) {
        startMapsIndex[i] = mapsBuf[i].start;
    }

    /* mmap() .sancov.raw file */
    snprintf(covFile, sizeof(covFile), "%s/%s/%d.sancov.raw", hfuzz->workDir, _HF_SANCOV_DIR,
             fuzzer->pid);
    dataBuf = files_mapFile(covFile, &dataFileSz, &dataFd, false);
    if (dataBuf == NULL) {
        LOG_E("Couldn't open and map '%s' in R/O mode", covFile);
        goto bail;
    }

    /* 
     * Avoid cost of size checks inside raw data read loop by defining the read function
     * & pivot size based on PC length.
     */
    uint64_t(*pReadRawPCFunc) (const uint8_t *) = NULL;
    uint8_t pivot = 0;
    if (is32bit) {
        pReadRawPCFunc = &util_getUINT32;
        pivot = 4;
    } else {
        pReadRawPCFunc = &util_getUINT64;
        pivot = 8;
    }

    /* 
     * Take advantage of data locality (next processed PC is very likely to belong
     * to same map) to avoid Trie node search for each read entry.
     */
    node_t *curMap = NULL;
    uint64_t prevIndex = 0;

    /* Iterate over data buffer containing list of hit PC addresses */
    while (pos < dataFileSz) {
        uint64_t pc = pReadRawPCFunc(dataBuf + pos);
        pos += pivot;
        /* Don't bother for zero PC (inserted checks without hit) */
        if (pc == 0x0) {
            nZeroPCs++;
            continue;
        } else {
            /* Find best hit based on start addr & verify range for errors */
            uint64_t bestFit = arch_interpSearch(startMapsIndex, mapsNum, pc);
            if (pc >= mapsBuf[bestFit].start && pc < mapsBuf[bestFit].end) {
                /* Increase exe/DSO total PC counter */
                mapsBuf[bestFit].pcCnt++;

                /* Update current Trie node if map changed */
                if (curMap == NULL || (prevIndex != bestFit)) {
                    prevIndex = bestFit;

                    /* Interaction with global Trie should mutex wrap to avoid threads races */
                    MX_LOCK(&hfuzz->sanCov_mutex);
                    {
                        curMap =
                            arch_trieSearch(hfuzz->covMetadata->children, mapsBuf[bestFit].mapName);
                        if (curMap == NULL) {
                            LOG_E("Corrupted Trie - '%s' not found", mapsBuf[bestFit].mapName);
                            MX_UNLOCK(&hfuzz->sanCov_mutex);
                            continue;
                        }

                        /* Maintain bitmaps only for exec/DSOs with coverage enabled - allocate on first use */
                        if (curMap->data.pBM == NULL) {
                            LOG_D("Allocating bitmap for map '%s'", mapsBuf[bestFit].mapName);
                            curMap->data.pBM = arch_newBitmap(_HF_BITMAP_SIZE);

                            /* 
                             * If bitmap allocation failed, unset cached Trie node ptr
                             * to execute this selection branch again.
                             */
                            if (curMap->data.pBM == NULL) {
                                curMap = NULL;
                                MX_UNLOCK(&hfuzz->sanCov_mutex);
                                continue;
                            }
                        }
                    }
                    MX_UNLOCK(&hfuzz->sanCov_mutex);
                }

                /* If new relative PC update DSO's bitmap */
                uint32_t relPC = (uint32_t) (pc - mapsBuf[bestFit].base);
                if (!arch_queryBitmap(curMap->data.pBM, relPC)) {

                    /* Interaction with global Trie should mutex wrap to avoid threads races */
                    MX_LOCK(&hfuzz->sanCov_mutex);
                    {
                        arch_setBitmap(curMap->data.pBM, relPC);
                    }
                    MX_UNLOCK(&hfuzz->sanCov_mutex);

                    /* Also increase new PCs counter at worker's thread runtime data */
                    mapsBuf[bestFit].newPcCnt++;
                }
            } else {
                /* 
                 * Normally this should never get executed. If hit, sanitizer
                 * coverage data collection come across some kind of bug.
                 */
                LOG_E("Invalid PC (%" PRIx64 ") at offset %ld", pc, pos);
            }
        }
        nPCs++;
    }

    /* Finally iterate over all instrumented maps to sum-up the number of newly met PC addresses */
    for (uint64_t i = 0; i < mapsNum; i++) {
        if (mapsBuf[i].pcCnt > 0 && !isSeedFirstRun) {
            fuzzer->sanCovCnts.newPcCnt += mapsBuf[i].newPcCnt;
        } else {
            noCovMapsNum++;
        }
    }

    /* Successful parsing - update fuzzer worker's counters */
    fuzzer->sanCovCnts.hitPcCnt = nPCs;
    fuzzer->sanCovCnts.totalPcCnt = nPCs + nZeroPCs;
    fuzzer->sanCovCnts.dsoCnt = mapsNum;
    fuzzer->sanCovCnts.iDsoCnt = mapsNum - noCovMapsNum;        /* Instrumented DSOs */
    ret = true;

 bail:
    unlink(covFile);
    if (dataBuf) {
        munmap(dataBuf, dataFileSz);
    }
    if (dataFd != -1) {
        close(dataFd);
    }
    if (mapsBuf) {
        free(mapsBuf);
    }
    if (startMapsIndex) {
        free(startMapsIndex);
    }
    if (pLine) {
        free(pLine);
    }
    return ret;
}

static bool arch_sanCovParse(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    int dataFd = -1;
    uint8_t *dataBuf = NULL;
    off_t dataFileSz = 0, pos = 0;
    bool is32bit = true;
    char covFile[PATH_MAX] = { 0 };
    DIR *pSanCovDir = NULL;
    bool ret = false;

    snprintf(covFile, sizeof(covFile), "%s/%s/%s.%d.sancov", hfuzz->workDir, _HF_SANCOV_DIR,
             files_basename(hfuzz->cmdline[0]), fuzzer->pid);
    if (!files_exists(covFile)) {
        LOG_D("Target sancov file not found");
        return false;
    }

    /* Local cache file suffix to use for file search of worker pid data */
    char pidFSuffix[13] = { 0 };
    snprintf(pidFSuffix, sizeof(pidFSuffix), "%d.sancov", fuzzer->pid);

    /* Total PCs counter summarizes all DSOs */
    uint64_t nPCs = 0;

    /* Iterate sancov dir for files generated against fuzzer pid */
    snprintf(covFile, sizeof(covFile), "%s/%s", hfuzz->workDir, _HF_SANCOV_DIR);
    pSanCovDir = opendir(covFile);
    struct dirent *pDir = NULL;
    while ((pDir = readdir(pSanCovDir)) != NULL) {
        /* Parse files with worker's PID */
        if (strstr(pDir->d_name, pidFSuffix)) {
            snprintf(covFile, sizeof(covFile), "%s/%s/%s", hfuzz->workDir, _HF_SANCOV_DIR,
                     pDir->d_name);
            dataBuf = files_mapFile(covFile, &dataFileSz, &dataFd, false);
            if (dataBuf == NULL) {
                LOG_E("Couldn't open and map '%s' in R/O mode", covFile);
                goto bail;
            }

            if (dataFileSz < 8) {
                LOG_E("Coverage data file too short");
                goto bail;
            }

            /* Check magic values & derive PC length */
            uint64_t magic = util_getUINT64(dataBuf);
            if (magic == kMagic32) {
                is32bit = true;
            } else if (magic == kMagic64) {
                is32bit = false;
            } else {
                LOG_E("Invalid coverage data file");
                goto bail;
            }
            pos += 8;

            /* Avoid size checks inside loop by registering the read function & pivot based on PC size */
            uint64_t(*readPC) (const uint8_t *) = NULL;
            uint8_t pivot = 0;
            if (is32bit) {
                readPC = &util_getUINT32;
                pivot = 4;
            } else {
                readPC = &util_getUINT64;
                pivot = 8;
            }

            while (pos < dataFileSz) {
                uint32_t pc = readPC(dataBuf + pos);
                pos += pivot;
                if (pc == 0x0) {
                    continue;
                }
                nPCs++;
            }
        }
    }

    /* Successful parsing - update fuzzer worker counters */
    fuzzer->sanCovCnts.hitPcCnt = nPCs;
    ret = true;

 bail:
    unlink(covFile);
    if (dataBuf) {
        munmap(dataBuf, dataFileSz);
    }
    if (dataFd != -1) {
        close(dataFd);
    }
    if (pSanCovDir) {
        closedir(pSanCovDir);
    }
    return ret;
}

/* 
 * Sanitizer coverage data are stored in FS can be parsed via two methods:
 * raw unpack & separate bin/DSO sancov file. Separate bin/DSO sancov file 
 * method is usually avoided since coverage data are lost if sanitizer unhandled 
 * signal. Additionally, the FS I/O overhead is bigger compared to raw unpack 
 * method which uses runtime data structures.
 * 
 * Enabled methods are controlled from sanitizer flags in arch.c
 */
void arch_sanCovAnalyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer)
{
    if (!hfuzz->useSanCov) {
        return;
    }

    /* 
     * For now supported methods are implemented in as a fail-over. This will
     * change in the future when best method is concluded.
     */
    if (arch_sanCovParseRaw(hfuzz, fuzzer) == false) {
        arch_sanCovParse(hfuzz, fuzzer);
    }
}
