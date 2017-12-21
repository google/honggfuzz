/*
 *
 * honggfuzz - file operations
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

#include "input.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libcommon/common.h"
#include "libcommon/files.h"

#if defined(_HF_ARCH_LINUX)
#include <sys/syscall.h>
#if defined(__NR_memfd_create)
#include <linux/memfd.h>
#endif /* defined(__NR_memfd_create) */
#endif /* defined(_HF_ARCH_LINUX) */

#include "libcommon/log.h"
#include "libcommon/util.h"

static bool input_getDirStatsAndRewind(honggfuzz_t* hfuzz) {
    rewinddir(hfuzz->io.inputDirPtr);

    size_t maxSize = 0U;
    size_t fileCnt = 0U;
    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(hfuzz->io.inputDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir('%s')", hfuzz->io.inputDir);
            return false;
        }
        if (entry == NULL) {
            break;
        }

        char fname[PATH_MAX];
        snprintf(fname, sizeof(fname), "%s/%s", hfuzz->io.inputDir, entry->d_name);
        LOG_D("Analyzing file '%s'", fname);

        struct stat st;
        if (stat(fname, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", fname);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", fname);
            continue;
        }
        if (hfuzz->maxFileSz != 0UL && st.st_size > (off_t)hfuzz->maxFileSz) {
            LOG_W("File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %" PRId64,
                fname, (int64_t)st.st_size, (int64_t)hfuzz->maxFileSz);
        }
        if ((size_t)st.st_size > maxSize) {
            maxSize = st.st_size;
        }
        fileCnt++;
    }

    ATOMIC_SET(hfuzz->io.fileCnt, fileCnt);
    if (hfuzz->maxFileSz == 0U) {
        if (maxSize < 8192) {
            hfuzz->maxFileSz = 8192;
        } else {
            hfuzz->maxFileSz = maxSize;
        }
    }
    if (hfuzz->persistent && hfuzz->maxFileSz > (1024U * 128)) {
        LOG_D("Persistent mode enabled, lowering maximum input size to 128KiB");
        hfuzz->maxFileSz = 1024U * 128;
    }

    if (hfuzz->io.fileCnt == 0U) {
        LOG_W("No usable files in the input directory '%s'", hfuzz->io.inputDir);
        return false;
    }

    LOG_D("Re-read the '%s', maxFileSz:%zu, number of usable files:%zu", hfuzz->io.inputDir,
        hfuzz->maxFileSz, hfuzz->io.fileCnt);

    rewinddir(hfuzz->io.inputDirPtr);

    return true;
}

bool input_getNext(run_t* run, char* fname, bool rewind) {
    static pthread_mutex_t input_mutex = PTHREAD_MUTEX_INITIALIZER;
    MX_SCOPED_LOCK(&input_mutex);

    if (run->global->io.fileCnt == 0U) {
        return false;
    }

    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(run->global->io.inputDirPtr);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir_r('%s')", run->global->io.inputDir);
            return false;
        }
        if (entry == NULL && rewind == false) {
            return false;
        }
        if (entry == NULL && rewind == true) {
            if (input_getDirStatsAndRewind(run->global) == false) {
                LOG_E("input_getDirStatsAndRewind('%s')", run->global->io.inputDir);
                return false;
            }
            continue;
        }

        snprintf(fname, PATH_MAX, "%s/%s", run->global->io.inputDir, entry->d_name);

        struct stat st;
        if (stat(fname, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", fname);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", fname);
            continue;
        }
        return true;
    }
}

bool input_init(honggfuzz_t* hfuzz) {
    hfuzz->io.fileCnt = 0U;

    if (!hfuzz->io.inputDir) {
        LOG_W("No input file/dir specified");
        return false;
    }

    int dir_fd = open(hfuzz->io.inputDir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (dir_fd == -1) {
        PLOG_W("open('%s', O_DIRECTORY|O_RDONLY|O_CLOEXEC)", hfuzz->io.inputDir);
        return false;
    }
    if ((hfuzz->io.inputDirPtr = fdopendir(dir_fd)) == NULL) {
        close(dir_fd);
        PLOG_W("opendir('%s')", hfuzz->io.inputDir);
        return false;
    }
    if (input_getDirStatsAndRewind(hfuzz) == false) {
        hfuzz->io.fileCnt = 0U;
        LOG_W("input_getDirStatsAndRewind('%s')", hfuzz->io.inputDir);
        return false;
    }

    return true;
}

bool input_parseDictionary(honggfuzz_t* hfuzz) {
    FILE* fDict = fopen(hfuzz->dictionaryFile, "rb");
    if (fDict == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->dictionaryFile);
        return false;
    }
    defer { fclose(fDict); };

    char* lineptr = NULL;
    size_t n = 0;
    defer { free(lineptr); };
    for (;;) {
        ssize_t len = getdelim(&lineptr, &n, '\n', fDict);
        if (len == -1) {
            break;
        }
        if (len > 1 && lineptr[len - 1] == '\n') {
            lineptr[len - 1] = '\0';
            len--;
        }
        if (lineptr[0] == '#') {
            continue;
        }
        if (lineptr[0] == '\n') {
            continue;
        }
        if (lineptr[0] == '\0') {
            continue;
        }
        char bufn[1025] = {0};
        char bufv[1025] = {0};
        if (sscanf(lineptr, "\"%1024s", bufv) != 1 &&
            sscanf(lineptr, "%1024[^=]=\"%1024s", bufn, bufv) != 2) {
            LOG_W("Incorrect dictionary entry: '%s'. Skipping", lineptr);
            continue;
        }

        char* s = util_StrDup(bufv);
        struct strings_t* str = (struct strings_t*)util_Malloc(sizeof(struct strings_t));
        str->len = util_decodeCString(s);
        str->s = s;
        hfuzz->dictionaryCnt += 1;
        TAILQ_INSERT_TAIL(&hfuzz->dictq, str, pointers);

        LOG_D("Dictionary: loaded word: '%s' (len=%zu)", str->s, str->len);
    }
    LOG_I("Loaded %zu words from the dictionary", hfuzz->dictionaryCnt);
    return true;
}

bool input_parseBlacklist(honggfuzz_t* hfuzz) {
    FILE* fBl = fopen(hfuzz->blacklistFile, "rb");
    if (fBl == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->blacklistFile);
        return false;
    }
    defer { fclose(fBl); };

    char* lineptr = NULL;
    /* lineptr can be NULL, but it's fine for free() */
    defer { free(lineptr); };
    size_t n = 0;
    for (;;) {
        if (getline(&lineptr, &n, fBl) == -1) {
            break;
        }

        if ((hfuzz->blacklist = util_Realloc(hfuzz->blacklist,
                 (hfuzz->blacklistCnt + 1) * sizeof(hfuzz->blacklist[0]))) == NULL) {
            PLOG_W(
                "realloc failed (sz=%zu)", (hfuzz->blacklistCnt + 1) * sizeof(hfuzz->blacklist[0]));
            return false;
        }

        hfuzz->blacklist[hfuzz->blacklistCnt] = strtoull(lineptr, 0, 16);
        LOG_D("Blacklist: loaded %'" PRIu64 "'", hfuzz->blacklist[hfuzz->blacklistCnt]);

        // Verify entries are sorted so we can use interpolation search
        if (hfuzz->blacklistCnt > 1) {
            if (hfuzz->blacklist[hfuzz->blacklistCnt - 1] > hfuzz->blacklist[hfuzz->blacklistCnt]) {
                LOG_F(
                    "Blacklist file not sorted. Use 'tools/createStackBlacklist.sh' to sort "
                    "records");
                return false;
            }
        }
        hfuzz->blacklistCnt += 1;
    }

    if (hfuzz->blacklistCnt > 0) {
        LOG_I("Loaded %zu stack hash(es) from the blacklist file", hfuzz->blacklistCnt);
    } else {
        LOG_F("Empty stack hashes blacklist file '%s'", hfuzz->blacklistFile);
    }
    return true;
}
