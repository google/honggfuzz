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
 * all hit relative BB addresses (realBBAddr - baseAddr to circumvent ASLR). Map's bitmap is updated
 * while new areas on target application are discovered based on absolute elitism implemented at
 * fuzz_sanCovFeedback().
 *
 * For individual data files a pid (fuzzer's thread or remote process) based filename search is
 * performed to identify all files belonging to examined execution. This method doesn't implement
 * yet bitmap runtime data to detect newly discovered areas. It's mainly used so far as a comparison
 * metric for raw-unpack method and stability check for sancov experimental features such as
 * coverage counters: http://clang.llvm.org/docs/SanitizerCoverage.html
 */

#include "sancov.h"

#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/util.h"
#include "sanitizers.h"

/* sancov files magic values */
#define kMagic32 0xC0BFFFFFFFFFFF32
#define kMagic64 0xC0BFFFFFFFFFFF64

/*
 * Each DSO/executable that has been compiled with enabled coverage instrumentation
 * is detected from compiler_rt runtime library when loaded. When coverage_direct
 * method is selected, runtime library is pre-allocating kPcArrayMmapSize [1] byte
 * chunks until the total size of chunks is greater than the number of inserted
 * guards. This effectively means that we might have a large unused (zero-filled)
 * area that we can't identify at runtime (we need to do binary inspection).
 *
 * Runtime maintained data structs size overhead is not affected since fixed-size
 * bitmap is used. However, the way the display coverage statistics are generated
 * is not very accurate because:
 *  a) ASan compiled DSO might get loaded although not followed from monitoring
       execution affecting the counters
 *  b) Not all zero-fill chunks translate into non-hit basic block as they might
 *     be the chunk padding
 *
 * Probably there aren't many we can do to deal with this issue without introducing
 * a huge performance overhead at an already costly feedback method.
 *
 * [1]
 'https://llvm.org/svn/llvm-project/compiler-rt/branches/release_38/lib/sanitizer_common/sanitizer_coverage_libcdep.cc'
 */
#define kPcArrayMmapSize (64 * 1024)

/*
 * bitmap implementation
 */
static bitmap_t* sancov_newBitmap(uint32_t capacity) {
    bitmap_t* pBM = util_Malloc(sizeof(bitmap_t));
    pBM->capacity = capacity;
    pBM->nChunks = (capacity + 31) / 32;
    pBM->pChunks = util_Calloc(pBM->nChunks * sizeof(uint32_t));
    return pBM;
}

static inline bool sancov_queryBitmap(bitmap_t* pBM, uint32_t index) {
    if (index > pBM->capacity) {
        LOG_E("bitmap overflow (%u)", index);
        return false;
    }
    if (pBM->pChunks[index / 32] & (1 << (index % 32))) {
        return true;
    }
    return false;
}

static inline void sancov_setBitmap(bitmap_t* pBM, uint32_t index) {
    /* This will be removed. So far checks only to verify accepted ranges. */
    if (index >= pBM->capacity) {
        LOG_E("Out of range index (%u > %u)", index, pBM->capacity);
    }
    pBM->pChunks[index / 32] |= (1 << (index % 32));
}

static inline void sancov_destroyBitmap(bitmap_t* pBM) {
    free(pBM->pChunks);
    free(pBM);
}

/*
 * Trie implementation
 */
static node_t* sancov_trieCreateNode(char key) {
    node_t* node = (node_t*)util_Malloc(sizeof(node_t));
    node->key = key;
    node->next = NULL;
    node->children = NULL;
    node->parent = NULL;
    node->prev = NULL;

    /* Zero init node's data struct */
    memset(&node->data, 0, sizeof(trieData_t));
    return node;
}

static node_t* sancov_trieSearch(node_t* root, const char* key) {
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

static void sancov_trieAdd(node_t** root, const char* key) {
    if (*root == NULL) {
        LOG_E("Invalid Trie (NULL root node)");
        return;
    }

    /* Traverse Trie */
    node_t* pTravNode = (*root)->children;
    if (pTravNode == NULL) {
        /* First node */
        for (pTravNode = *root; *key != '\0'; pTravNode = pTravNode->children) {
            pTravNode->children = sancov_trieCreateNode(*key);
            pTravNode->children->parent = pTravNode;
            key++;
        }
        pTravNode->children = sancov_trieCreateNode('\0');
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
            sancov_trieAdd(&(pTravNode->next), key);
            return;
        }
        pTravNode = pTravNode->next;
    }
    if (*key) {
        pTravNode->next = sancov_trieCreateNode(*key);
    } else {
        pTravNode->next = sancov_trieCreateNode(*key);
    }
    pTravNode->next->parent = pTravNode->parent;
    pTravNode->next->prev = pTravNode;
    if (!*key) {
        return;
    }
    key++;
    for (pTravNode = pTravNode->next; *key; pTravNode = pTravNode->children) {
        pTravNode->children = sancov_trieCreateNode(*key);
        pTravNode->children->parent = pTravNode;
        key++;
    }
    pTravNode->children = sancov_trieCreateNode('\0');
    pTravNode->children->parent = pTravNode;

    return;
}

static inline void sancov_trieFreeNode(node_t* node) {
    /* First destroy bitmap heap buffers allocated for instrumented maps */
    if (node->data.pBM) {
        sancov_destroyBitmap(node->data.pBM);
    }
    free(node);
}

static inline void sancov_trieCreate(node_t** root) {
    /* Create root node if new Trie */
    *root = sancov_trieCreateNode('\0');
}

/* Destroy Trie - iterate nodes and free memory */
UNUSED static void sancov_trieDestroy(node_t* root) {
    node_t* pNode = root;
    node_t* pNodeTmp = root;
    while (pNode) {
        while (pNode->children) {
            pNode = pNode->children;
        }

        if (pNode->prev && pNode->next) {
            pNodeTmp = pNode;
            pNode->next->prev = pNode->prev;
            pNode->prev->next = pNode->next;
            sancov_trieFreeNode(pNodeTmp);
        } else if (pNode->prev && !pNode->next) {
            pNodeTmp = pNode;
            pNode->prev->next = NULL;
            sancov_trieFreeNode(pNodeTmp);
        } else if (!pNode->prev && pNode->next) {
            pNodeTmp = pNode;
            pNode->parent->children = pNode->next;
            pNode->next->prev = NULL;
            pNode = pNode->next;
            sancov_trieFreeNode(pNodeTmp);
        } else {
            pNodeTmp = pNode;
            if (pNode->parent == NULL) {
                /* Root */
                sancov_trieFreeNode(pNodeTmp);
                return;
            }
            pNode = pNode->parent;
            pNode->children = NULL;
            sancov_trieFreeNode(pNodeTmp);
        }
    }
}

/* Modified interpolation search algorithm to search for nearest address fit */
static inline uint64_t sancov_interpSearch(uint64_t* buf, uint64_t size, uint64_t key) {
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
static int sancov_qsortCmp(const void* a, const void* b) {
    memMap_t* pA = (memMap_t*)a;
    memMap_t* pB = (memMap_t*)b;
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

static bool sancov_sanCovParseRaw(run_t* run) {
    int dataFd = -1;
    uint8_t* dataBuf = NULL;
    off_t dataFileSz = 0, pos = 0;
    bool is32bit = true;
    char covFile[PATH_MAX] = {0};
    pid_t targetPid = (run->global->linux.pid > 0) ? run->global->linux.pid : run->pid;

    /* Fuzzer local runtime data structs - need free() before exit */
    uint64_t* startMapsIndex = NULL;
    memMap_t* mapsBuf = NULL;

    /* Local counters */
    uint64_t nBBs = 0;         /* Total BB hits found in raw file */
    uint64_t nZeroBBs = 0;     /* Number of non-hit instrumented BBs */
    uint64_t mapsNum = 0;      /* Total number of entries in map file */
    uint64_t noCovMapsNum = 0; /* Loaded DSOs not compiled with coverage */

    /* File line-by-line read help buffers */
    __block char* pLine = NULL;
    size_t lineSz = 0;

    /* Coverage data analysis starts by parsing map file listing */
    snprintf(covFile, sizeof(covFile), "%s/%s/%d.sancov.map", run->global->io.workDir,
        _HF_SANCOV_DIR, targetPid);
    if (!files_exists(covFile)) {
        LOG_D("sancov map file not found");
        return false;
    }
    FILE* fCovMap = fopen(covFile, "rb");
    if (fCovMap == NULL) {
        PLOG_E("Couldn't open '%s' - R/O mode", covFile);
        return false;
    }
    defer { fclose(fCovMap); };

    /* First line contains PC length (32/64-bit) */
    if (getline(&pLine, &lineSz, fCovMap) == -1) {
        LOG_E("Invalid map file '%s'", covFile);
        return false;
    }
    defer {
        free(pLine);
        pLine = NULL;
    };

    int pcLen = atoi(pLine);
    if (pcLen == 32) {
        is32bit = true;
    } else if (pcLen == 64) {
        is32bit = false;
    } else {
        LOG_E("Invalid PC length (%d) in map file '%s'", pcLen, covFile);
    }

    /* See if #maps is available from previous run to avoid realloc inside loop */
    uint64_t prevMapsNum = ATOMIC_GET(run->global->sanCovCnts.dsoCnt);
    if (prevMapsNum > 0) {
        mapsBuf = util_Malloc(prevMapsNum * sizeof(memMap_t));
    }
    /* It's OK to free(NULL) */
    defer { free(mapsBuf); };

    /* Iterate map entries */
    for (;;) {
        if (getline(&pLine, &lineSz, fCovMap) == -1) {
            break;
        }

        /* Trim trailing whitespaces, not sure if needed copied from upstream sancov.py */
        char* lineEnd = pLine + strlen(pLine) - 1;
        while (lineEnd > pLine && isspace((int)*lineEnd)) {
            lineEnd--;
        }
        *(lineEnd + 1) = 0;

        /*
         * Each line has following format:
         * Start    End      Base     bin/DSO name
         * b5843000 b584e6ac b5843000 liblog.so
         */
        memMap_t mapData = {.start = 0};
        char* savePtr = NULL;
        mapData.start = strtoull(strtok_r(pLine, " ", &savePtr), NULL, 16);
        mapData.end = strtoull(strtok_r(NULL, " ", &savePtr), NULL, 16);
        mapData.base = strtoull(strtok_r(NULL, " ", &savePtr), NULL, 16);
        char* mapName = strtok_r(NULL, " ", &savePtr);
        memcpy(mapData.mapName, mapName, strlen(mapName));

        /* Interaction with global Trie should mutex wrap to avoid threads races */
        {
            MX_SCOPED_LOCK(&run->global->sanCov_mutex);

            /* Add entry to Trie with zero data if not already */
            if (!sancov_trieSearch(run->global->covMetadata->children, mapData.mapName)) {
                sancov_trieAdd(&run->global->covMetadata, mapData.mapName);
            }
        }

        /* If no DSO number history (first run) or new DSO loaded, realloc local maps metadata buf
         */
        if (prevMapsNum == 0 || prevMapsNum < mapsNum) {
            if ((mapsBuf = util_Realloc(mapsBuf, (size_t)(mapsNum + 1) * sizeof(memMap_t))) ==
                NULL) {
                PLOG_E("realloc failed (sz=%" PRIu64 ")", (mapsNum + 1) * sizeof(memMap_t));
                return false;
            }
        }

        /* Add entry to local maps metadata array */
        memcpy(&mapsBuf[mapsNum], &mapData, sizeof(memMap_t));

        /* Increase loaded maps counter (includes non-instrumented DSOs too) */
        mapsNum++;
    }

    /* Delete .sancov.map file */
    if (run->global->linux.pid == 0 && run->global->persistent == false) {
        unlink(covFile);
    }

    /* Create a quick index array with maps start addresses */
    startMapsIndex = util_Malloc(mapsNum * sizeof(uint64_t));
    defer { free(startMapsIndex); };

    /* Sort quick maps index */
    qsort(mapsBuf, mapsNum, sizeof(memMap_t), sancov_qsortCmp);
    for (size_t i = 0; i < mapsNum; i++) {
        startMapsIndex[i] = mapsBuf[i].start;
    }

    /* mmap() .sancov.raw file */
    snprintf(covFile, sizeof(covFile), "%s/%s/%d.sancov.raw", run->global->io.workDir,
        _HF_SANCOV_DIR, targetPid);
    dataBuf = files_mapFile(covFile, &dataFileSz, &dataFd, false);
    if (dataBuf == NULL) {
        LOG_E("Couldn't open and map '%s' in R/O mode", covFile);
        return false;
    }
    defer {
        munmap(dataBuf, dataFileSz);
        close(dataFd);
    };

    /*
     * Avoid cost of size checks inside raw data read loop by defining the read function
     * & pivot size based on PC length.
     */
    uint64_t (*pReadRawBBAddrFunc)(const uint8_t*) = NULL;
    uint8_t pivot = 0;
    if (is32bit) {
        pReadRawBBAddrFunc = &util_getUINT32;
        pivot = 4;
    } else {
        pReadRawBBAddrFunc = &util_getUINT64;
        pivot = 8;
    }

    /*
     * Take advantage of data locality (next processed addr is very likely to belong
     * to same map) to avoid Trie node search for each read entry.
     */
    node_t* curMap = NULL;
    uint64_t prevIndex = 0;

    /* Iterate over data buffer containing list of hit BB addresses */
    while (pos < dataFileSz) {
        uint64_t bbAddr = pReadRawBBAddrFunc(dataBuf + pos);
        pos += pivot;
        /* Don't bother for zero BB addr (inserted checks without hit) */
        if (bbAddr == 0x0) {
            nZeroBBs++;
            continue;
        } else {
            /* Find best hit based on start addr & verify range for errors */
            uint64_t bestFit = sancov_interpSearch(startMapsIndex, mapsNum, bbAddr);
            if (bbAddr >= mapsBuf[bestFit].start && bbAddr < mapsBuf[bestFit].end) {
                /* Increase exe/DSO total BB counter */
                mapsBuf[bestFit].bbCnt++;

                /* Update current Trie node if map changed */
                if (curMap == NULL || (prevIndex != bestFit)) {
                    prevIndex = bestFit;

                    /* Interaction with global Trie should mutex wrap to avoid threads races */
                    {
                        MX_SCOPED_LOCK(&run->global->sanCov_mutex);

                        curMap = sancov_trieSearch(
                            run->global->covMetadata->children, mapsBuf[bestFit].mapName);
                        if (curMap == NULL) {
                            LOG_E("Corrupted Trie - '%s' not found", mapsBuf[bestFit].mapName);
                            continue;
                        }

                        /* Maintain bitmaps only for exec/DSOs with coverage enabled - allocate on
                         * first use */
                        if (curMap->data.pBM == NULL) {
                            LOG_D("Allocating bitmap for map '%s'", mapsBuf[bestFit].mapName);
                            curMap->data.pBM = sancov_newBitmap(_HF_SANCOV_BITMAP_SIZE);

                            /*
                             * If bitmap allocation failed, unset cached Trie node ptr
                             * to execute this selection branch again.
                             */
                            if (curMap->data.pBM == NULL) {
                                curMap = NULL;
                                continue;
                            }
                        }
                    }
                }

                /* If new relative BB addr update DSO's bitmap */
                uint32_t relAddr = (uint32_t)(bbAddr - mapsBuf[bestFit].base);
                if (!sancov_queryBitmap(curMap->data.pBM, relAddr)) {
                    /* Interaction with global Trie should mutex wrap to avoid threads races */
                    {
                        MX_SCOPED_LOCK(&run->global->sanCov_mutex);

                        sancov_setBitmap(curMap->data.pBM, relAddr);
                    }

                    /* Also increase new BBs counter at worker's thread runtime data */
                    mapsBuf[bestFit].newBBCnt++;
                }
            } else {
                /*
                 * Normally this should never get executed. If hit, sanitizer
                 * coverage data collection come across some kind of bug.
                 */
                LOG_E("Invalid BB addr (%#" PRIx64 ") at offset %" PRId64, bbAddr, (uint64_t)pos);
            }
        }
        nBBs++;
    }

    /* Finally iterate over all instrumented maps to sum-up the number of newly met BB addresses */
    for (uint64_t i = 0; i < mapsNum; i++) {
        if (mapsBuf[i].bbCnt > 0) {
            run->sanCovCnts.newBBCnt += mapsBuf[i].newBBCnt;
        } else {
            noCovMapsNum++;
        }
    }

    /* Successful parsing - update fuzzer worker's counters */
    run->sanCovCnts.hitBBCnt = nBBs;
    run->sanCovCnts.totalBBCnt = nBBs + nZeroBBs;
    run->sanCovCnts.dsoCnt = mapsNum;
    run->sanCovCnts.iDsoCnt = mapsNum - noCovMapsNum; /* Instrumented DSOs */

    if (run->global->linux.pid == 0 && run->global->persistent == false) {
        unlink(covFile);
    }
    return true;
}

static bool sancov_sanCovParse(run_t* run) {
    int dataFd = -1;
    uint8_t* dataBuf = NULL;
    off_t dataFileSz = 0, pos = 0;
    bool is32bit = true;
    char covFile[PATH_MAX] = {0};
    DIR* pSanCovDir = NULL;
    pid_t targetPid = (run->global->linux.pid > 0) ? run->global->linux.pid : run->pid;

    snprintf(covFile, sizeof(covFile), "%s/%s/%s.%d.sancov", run->global->io.workDir,
        _HF_SANCOV_DIR, files_basename(run->global->exe.cmdline[0]), targetPid);
    if (!files_exists(covFile)) {
        LOG_D("Target sancov file not found");
        return false;
    }

    /* Local cache file suffix to use for file search of target pid data */
    char pidFSuffix[13] = {0};
    snprintf(pidFSuffix, sizeof(pidFSuffix), "%d.sancov", targetPid);

    /* Total BBs counter summarizes all DSOs */
    uint64_t nBBs = 0;

    /* Iterate sancov dir for files generated against target pid */
    snprintf(covFile, sizeof(covFile), "%s/%s", run->global->io.workDir, _HF_SANCOV_DIR);
    pSanCovDir = opendir(covFile);
    if (pSanCovDir == NULL) {
        PLOG_E("opendir('%s')", covFile);
        return false;
    }
    defer { closedir(pSanCovDir); };

    struct dirent* pDir = NULL;
    while ((pDir = readdir(pSanCovDir)) != NULL) {
        /* Parse files with target's pid */
        if (strstr(pDir->d_name, pidFSuffix)) {
            snprintf(covFile, sizeof(covFile), "%s/%s/%s", run->global->io.workDir, _HF_SANCOV_DIR,
                pDir->d_name);
            dataBuf = files_mapFile(covFile, &dataFileSz, &dataFd, false);
            if (dataBuf == NULL) {
                LOG_E("Couldn't open and map '%s' in R/O mode", covFile);
                return false;
            }
            defer {
                munmap(dataBuf, dataFileSz);
                close(dataFd);
            };

            if (dataFileSz < 8) {
                LOG_E("Coverage data file too short");
                return false;
            }

            /* Check magic values & derive PC length */
            uint64_t magic = util_getUINT64(dataBuf);
            if (magic == kMagic32) {
                is32bit = true;
            } else if (magic == kMagic64) {
                is32bit = false;
            } else {
                LOG_E("Invalid coverage data file");
                return false;
            }
            pos += 8;

            /*
             * Avoid cost of size checks inside raw data read loop by defining the read function
             * & pivot size based on PC length.
             */
            uint64_t (*pReadRawBBAddrFunc)(const uint8_t*) = NULL;
            uint8_t pivot = 0;
            if (is32bit) {
                pReadRawBBAddrFunc = &util_getUINT32;
                pivot = 4;
            } else {
                pReadRawBBAddrFunc = &util_getUINT64;
                pivot = 8;
            }

            while (pos < dataFileSz) {
                uint32_t bbAddr = pReadRawBBAddrFunc(dataBuf + pos);
                pos += pivot;
                if (bbAddr == 0x0) {
                    continue;
                }
                nBBs++;
            }
        }
    }

    /* Successful parsing - update fuzzer worker counters */
    run->sanCovCnts.hitBBCnt = nBBs;

    if (run->global->linux.pid == 0 && run->global->persistent == false) {
        unlink(covFile);
    }
    return true;
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
void sancov_Analyze(run_t* run) {
    if (!run->global->useSanCov) {
        return;
    }
    /*
     * For now supported methods are implemented in fail-over nature. This will
     * change in the future when best method is concluded.
     */
    if (sancov_sanCovParseRaw(run) == false) {
        sancov_sanCovParse(run);
    }
}

bool sancov_Init(honggfuzz_t* hfuzz) {
    if (hfuzz->useSanCov == false) {
        return true;
    }
    sancov_trieCreate(&hfuzz->covMetadata);

    char sanCovOutDir[PATH_MAX] = {0};
    snprintf(sanCovOutDir, sizeof(sanCovOutDir), "%s/%s", hfuzz->io.workDir, _HF_SANCOV_DIR);
    if (!files_exists(sanCovOutDir)) {
        if (mkdir(sanCovOutDir, S_IRWXU | S_IXGRP | S_IXOTH) != 0) {
            PLOG_E("mkdir() '%s' failed", sanCovOutDir);
        }
    }

    return true;
}
