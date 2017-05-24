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

#include "common.h"
#include "files.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(_HF_ARCH_LINUX)
#include <sys/syscall.h>
#if defined(__NR_memfd_create)
#include <linux/memfd.h>
#endif                          /* defined(__NR_memfd_create) */
#endif                          /* defined(_HF_ARCH_LINUX) */

#include "log.h"
#include "util.h"

ssize_t files_readFileToBufMax(char *fileName, uint8_t * buf, size_t fileMaxSz)
{
    int fd = open(fileName, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        PLOG_W("Couldn't open '%s' for R/O", fileName);
        return -1;
    }
    defer {
        close(fd);
    };

    ssize_t readSz = files_readFromFd(fd, buf, fileMaxSz);
    if (readSz < 0) {
        LOG_W("Couldn't read '%s' to a buf", fileName);
        return -1;
    }

    LOG_D("Read '%zu' bytes from '%s'", readSz, fileName);
    return readSz;
}

bool files_writeBufToFile(char *fileName, uint8_t * buf, size_t fileSz, int flags)
{
    int fd = open(fileName, flags, 0644);
    if (fd == -1) {
        PLOG_W("Couldn't open '%s' for R/W", fileName);
        return false;
    }
    defer {
        close(fd);
    };

    if (files_writeToFd(fd, buf, fileSz) == false) {
        PLOG_W("Couldn't write '%zu' bytes to file '%s' (fd='%d')", fileSz, fileName, fd);
        unlink(fileName);
        return false;
    }

    LOG_D("Written '%zu' bytes to '%s'", fileSz, fileName);
    return true;
}

bool files_writeToFd(int fd, const uint8_t * buf, size_t fileSz)
{
    size_t writtenSz = 0;
    while (writtenSz < fileSz) {
        ssize_t sz = write(fd, &buf[writtenSz], fileSz - writtenSz);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz < 0)
            return false;

        writtenSz += sz;
    }
    return true;
}

bool files_writeStrToFd(int fd, const char *str)
{
    return files_writeToFd(fd, (const uint8_t *)str, strlen(str));
}

ssize_t files_readFromFd(int fd, uint8_t * buf, size_t fileSz)
{
    size_t readSz = 0;
    while (readSz < fileSz) {
        ssize_t sz = read(fd, &buf[readSz], fileSz - readSz);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz == 0)
            break;

        if (sz < 0)
            return -1;

        readSz += sz;
    }
    return (ssize_t) readSz;
}

bool files_exists(char *fileName)
{
    return (access(fileName, F_OK) != -1);
}

bool files_writePatternToFd(int fd, off_t size, unsigned char p)
{
    void *buf = malloc(size);
    if (!buf) {
        PLOG_W("Couldn't allocate memory");
        return false;
    }
    defer {
        free(buf);
    };

    memset(buf, p, (size_t) size);
    int ret = files_writeToFd(fd, buf, size);

    return ret;
}

static bool files_getDirStatsAndRewind(honggfuzz_t * hfuzz)
{
    rewinddir(hfuzz->inputDirP);

    size_t maxSize = 0U;
    size_t fileCnt = 0U;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(hfuzz->inputDirP);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir('%s')", hfuzz->inputDir);
            return false;
        }
        if (entry == NULL) {
            break;
        }

        char fname[PATH_MAX];
        snprintf(fname, sizeof(fname), "%s/%s", hfuzz->inputDir, entry->d_name);
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
        if (hfuzz->maxFileSz != 0UL && st.st_size > (off_t) hfuzz->maxFileSz) {
            LOG_W("File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %"
                  PRId64, fname, (int64_t) st.st_size, (int64_t) hfuzz->maxFileSz);
        }
        if (st.st_size == 0U) {
            LOG_W("File '%s' is empty", fname);
            continue;
        }
        if ((size_t) st.st_size > maxSize) {
            maxSize = st.st_size;
        }
        fileCnt++;
    }

    ATOMIC_SET(hfuzz->fileCnt, fileCnt);
    if (hfuzz->maxFileSz == 0U) {
        if (maxSize < 8192) {
            hfuzz->maxFileSz = 8192;
        } else {
            hfuzz->maxFileSz = maxSize;
        }
    }

    if (hfuzz->fileCnt == 0U) {
        LOG_W("No usable files in the input directory '%s'", hfuzz->inputDir);
        return false;
    }

    LOG_D("Re-read the '%s', maxFileSz:%zu, number of usable files:%zu", hfuzz->inputDir,
          hfuzz->maxFileSz, hfuzz->fileCnt);

    rewinddir(hfuzz->inputDirP);

    return true;
}

bool files_getNext(honggfuzz_t * hfuzz, char *fname, bool rewind)
{
    static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;
    MX_SCOPED_LOCK(&files_mutex);

    if (hfuzz->fileCnt == 0U) {
        return false;
    }

    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(hfuzz->inputDirP);
        if (entry == NULL && errno == EINTR) {
            continue;
        }
        if (entry == NULL && errno != 0) {
            PLOG_W("readdir_r('%s')", hfuzz->inputDir);
            return false;
        }
        if (entry == NULL && rewind == false) {
            return false;
        }
        if (entry == NULL && rewind == true) {
            if (files_getDirStatsAndRewind(hfuzz) == false) {
                LOG_E("files_getDirStatsAndRewind('%s')", hfuzz->inputDir);
                return false;
            }
            continue;
        }

        snprintf(fname, PATH_MAX, "%s/%s", hfuzz->inputDir, entry->d_name);

        struct stat st;
        if (stat(fname, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", fname);
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", fname);
            continue;
        }
        if (st.st_size == 0U) {
            LOG_D("File '%s' is empty", fname);
            continue;
        }
        return true;
    }
}

bool files_init(honggfuzz_t * hfuzz)
{
    hfuzz->fileCnt = 0U;

    if (!hfuzz->inputDir) {
        LOG_W("No input file/dir specified");
        return false;
    }

    if ((hfuzz->inputDirP = opendir(hfuzz->inputDir)) == NULL) {
        PLOG_W("opendir('%s')", hfuzz->inputDir);
        return false;
    }

    if (files_getDirStatsAndRewind(hfuzz) == false) {
        hfuzz->fileCnt = 0U;
        LOG_W("files_getDirStatsAndRewind('%s')", hfuzz->inputDir);
        return false;
    }

    return true;
}

const char *files_basename(char *path)
{
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

bool files_parseDictionary(honggfuzz_t * hfuzz)
{
    FILE *fDict = fopen(hfuzz->dictionaryFile, "rb");
    if (fDict == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->dictionaryFile);
        return false;
    }
    defer {
        fclose(fDict);
    };

    for (;;) {
        char *lineptr = NULL;
        size_t n = 0;
        ssize_t len = getdelim(&lineptr, &n, '\n', fDict);
        if (len == -1) {
            break;
        }
        if (n > 1 && lineptr[len - 1] == '\n') {
            lineptr[len - 1] = '\0';
            len--;
        }

        struct strings_t *str = (struct strings_t *)util_Malloc(sizeof(struct strings_t));
        str->len = util_decodeCString(lineptr);
        str->s = lineptr;
        hfuzz->dictionaryCnt += 1;
        TAILQ_INSERT_TAIL(&hfuzz->dictq, str, pointers);

        LOG_D("Dictionary: loaded word: '%s' (len=%zu)", str->s, str->len);
    }
    LOG_I("Loaded %zu words from the dictionary", hfuzz->dictionaryCnt);
    return true;
}

/*
 * dstExists argument can be used by caller for cases where existing destination
 * file requires special handling (e.g. save unique crashes)
 */
bool files_copyFile(const char *source, const char *destination, bool * dstExists, bool try_link)
{
    if (dstExists) {
        *dstExists = false;
    }

    if (try_link) {
        if (link(source, destination) == 0) {
            return true;
        } else {
            if (errno == EEXIST) {
                // Should kick-in before MAC, so avoid the hassle
                if (dstExists)
                    *dstExists = true;
                return false;
            } else {
                PLOG_D("Couldn't link '%s' as '%s'", source, destination);
                /*
                 * Don't fail yet as we might have a running env which doesn't allow
                 * hardlinks (e.g. SELinux)
                 */
            }
        }
    }
    // Now try with a verbose POSIX alternative
    int inFD, outFD, dstOpenFlags;
    mode_t dstFilePerms;

    // O_EXCL is important for saving unique crashes
    dstOpenFlags = O_CREAT | O_WRONLY | O_CLOEXEC | O_EXCL;
    dstFilePerms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

    inFD = open(source, O_RDONLY | O_CLOEXEC);
    if (inFD == -1) {
        PLOG_D("Couldn't open '%s' source", source);
        return false;
    }
    defer {
        close(inFD);
    };

    struct stat inSt;
    if (fstat(inFD, &inSt) == -1) {
        PLOG_W("Couldn't fstat(fd='%d' fileName='%s')", inFD, source);
        return false;
    }

    outFD = open(destination, dstOpenFlags, dstFilePerms);
    if (outFD == -1) {
        if (errno == EEXIST) {
            if (dstExists)
                *dstExists = true;
        }
        PLOG_D("Couldn't open '%s' destination", destination);
        return false;
    }
    defer {
        close(outFD);
    };

    uint8_t *inFileBuf = malloc(inSt.st_size);
    if (!inFileBuf) {
        PLOG_W("malloc(%zu) failed", (size_t) inSt.st_size);
        return false;
    }
    defer {
        free(inFileBuf);
    };

    ssize_t readSz = files_readFromFd(inFD, inFileBuf, (size_t) inSt.st_size);
    if (readSz < 0) {
        PLOG_W("Couldn't read '%s' to a buf", source);
        return false;
    }

    if (files_writeToFd(outFD, inFileBuf, readSz) == false) {
        PLOG_W("Couldn't write '%zu' bytes to file '%s' (fd='%d')", (size_t) readSz,
               destination, outFD);
        unlink(destination);
        return false;
    }

    return true;
}

bool files_parseBlacklist(honggfuzz_t * hfuzz)
{
    FILE *fBl = fopen(hfuzz->blacklistFile, "rb");
    if (fBl == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", hfuzz->blacklistFile);
        return false;
    }
    defer {
        fclose(fBl);
    };

    char *lineptr = NULL;
    /* lineptr can be NULL, but it's fine for free() */
    defer {
        free(lineptr);
    };
    size_t n = 0;
    for (;;) {
        if (getline(&lineptr, &n, fBl) == -1) {
            break;
        }

        if ((hfuzz->blacklist =
             util_Realloc(hfuzz->blacklist,
                          (hfuzz->blacklistCnt + 1) * sizeof(hfuzz->blacklist[0]))) == NULL) {
            PLOG_W("realloc failed (sz=%zu)",
                   (hfuzz->blacklistCnt + 1) * sizeof(hfuzz->blacklist[0]));
            return false;
        }

        hfuzz->blacklist[hfuzz->blacklistCnt] = strtoull(lineptr, 0, 16);
        LOG_D("Blacklist: loaded %'" PRIu64 "'", hfuzz->blacklist[hfuzz->blacklistCnt]);

        // Verify entries are sorted so we can use interpolation search
        if (hfuzz->blacklistCnt > 1) {
            if (hfuzz->blacklist[hfuzz->blacklistCnt - 1] > hfuzz->blacklist[hfuzz->blacklistCnt]) {
                LOG_F
                    ("Blacklist file not sorted. Use 'tools/createStackBlacklist.sh' to sort records");
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

/*
 * Reads symbols from src file (one per line) and append them to filterList. The
 * total number of added symbols is returned.
 *
 * Simple wildcard strings are also supported (e.g. mem*)
 */
size_t files_parseSymbolFilter(const char *srcFile, char ***filterList)
{
    FILE *f = fopen(srcFile, "rb");
    if (f == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", srcFile);
        return 0;
    }
    defer {
        fclose(f);
    };

    char *lineptr = NULL;
    defer {
        free(lineptr);
    };

    size_t symbolsRead = 0, n = 0;
    for (;;) {
        if (getline(&lineptr, &n, f) == -1) {
            break;
        }

        if (strlen(lineptr) < 3) {
            LOG_F("Input symbol '%s' too short (strlen < 3)", lineptr);
            return 0;
        }

        if ((*filterList =
             (char **)util_Realloc(*filterList,
                                   (symbolsRead + 1) * sizeof((*filterList)[0]))) == NULL) {
            PLOG_W("realloc failed (sz=%zu)", (symbolsRead + 1) * sizeof((*filterList)[0]));
            return 0;
        }
        (*filterList)[symbolsRead] = malloc(strlen(lineptr));
        if (!(*filterList)[symbolsRead]) {
            PLOG_E("malloc(%zu) failed", strlen(lineptr));
            return 0;
        }
        strncpy((*filterList)[symbolsRead], lineptr, strlen(lineptr));
        symbolsRead++;
    }

    LOG_I("%zu filter symbols added to list", symbolsRead);
    return symbolsRead;
}

uint8_t *files_mapFile(char *fileName, off_t * fileSz, int *fd, bool isWritable)
{
    int mmapProt = PROT_READ;
    if (isWritable) {
        mmapProt |= PROT_WRITE;
    }

    if ((*fd = open(fileName, O_RDONLY)) == -1) {
        PLOG_W("Couldn't open() '%s' file in R/O mode", fileName);
        return NULL;
    }

    struct stat st;
    if (fstat(*fd, &st) == -1) {
        PLOG_W("Couldn't stat() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    uint8_t *buf;
    if ((buf = mmap(NULL, st.st_size, mmapProt, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
        PLOG_W("Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

uint8_t *files_mapFileShared(char *fileName, off_t * fileSz, int *fd)
{
    if ((*fd = open(fileName, O_RDONLY)) == -1) {
        PLOG_W("Couldn't open() '%s' file in R/O mode", fileName);
        return NULL;
    }

    struct stat st;
    if (fstat(*fd, &st) == -1) {
        PLOG_W("Couldn't stat() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    uint8_t *buf;
    if ((buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, *fd, 0)) == MAP_FAILED) {
        PLOG_W("Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

void *files_mapSharedMem(size_t sz, int *fd, const char *dir)
{
#if defined(_HF_ARCH_LINUX) && defined(__NR_memfd_create)
    *fd = syscall(__NR_memfd_create, "honggfuzz", (uintptr_t) MFD_CLOEXEC);
#endif                          /* defined(_HF_ARCH_LINUX) && defined(__NR_memfd_create) */
    if (*fd == -1) {
        char template[PATH_MAX];
        snprintf(template, sizeof(template), "%s/hfuzz.XXXXXX", dir);
        if ((*fd = mkstemp(template)) == -1) {
            PLOG_W("mkstemp('%s')", template);
            return MAP_FAILED;
        }
        unlink(template);
    }
    if (ftruncate(*fd, sz) == -1) {
        PLOG_W("ftruncate(%d, %zu)", *fd, sz);
        close(*fd);
        *fd = -1;
        return MAP_FAILED;
    }
    void *ret = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if (ret == MAP_FAILED) {
        PLOG_W("mmap(sz=%zu, fd=%d)", sz, *fd);
        *fd = -1;
        close(*fd);
        return MAP_FAILED;
    }
    return ret;
}

bool files_readPidFromFile(const char *fileName, pid_t * pidPtr)
{
    FILE *fPID = fopen(fileName, "rbe");
    if (fPID == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", fileName);
        return false;
    }
    defer {
        fclose(fPID);
    };

    char *lineptr = NULL;
    size_t lineSz = 0;
    defer {
        free(lineptr);
    };
    if (getline(&lineptr, &lineSz, fPID) == -1) {
        if (lineSz == 0) {
            LOG_W("Empty PID file (%s)", fileName);
            return false;
        }
    }

    *pidPtr = atoi(lineptr);
    if (*pidPtr < 1) {
        LOG_W("Invalid PID read from '%s' file", fileName);
        return false;
    }

    return true;
}
