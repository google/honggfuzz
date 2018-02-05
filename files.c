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
#include <errno.h>

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
    // extern int errno;

    while(1){
        int fd = open(fileName, flags, 0644);
        if (fd == -1) {
            PLOG_W("Couldn't open '%s' for R/O", fileName);
            if(errno == ENOSPC){
                PLOG_E("No Space, Please Clean Your Disk Space !!!");
                /*
                PLOG_E("Clean Finish(y/n): ");
                if(getchar() == 'y'){
                    continue;
                }*/
            }
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
}

bool files_writeToFd(int fd, uint8_t * buf, size_t fileSz)
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

bool files_writeStrToFd(int fd, char *str)
{
    return files_writeToFd(fd, (uint8_t *) str, strlen(str));
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

static bool files_readdir(honggfuzz_t * hfuzz)
{
    DIR *dir = opendir(hfuzz->inputDir);
    if (!dir) {
        PLOG_W("Couldn't open dir '%s'", hfuzz->inputDir);
        return false;
    }
    defer {
        closedir(dir);
    };

    size_t maxSize = 0UL;
    unsigned count = 0;
    for (;;) {
        errno = 0;
        struct dirent *res = readdir(dir);
        if (res == NULL && errno != 0) {
            PLOG_W("Couldn't read the '%s' dir", hfuzz->inputDir);
            return false;
        }

        if (res == NULL) {
            break;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", hfuzz->inputDir, res->d_name);
        struct stat st;
        if (stat(path, &st) == -1) {
            LOG_W("Couldn't stat() the '%s' file", path);
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            LOG_D("'%s' is not a regular file, skipping", path);
            continue;
        }

        if (st.st_size == 0ULL) {
            LOG_D("'%s' is empty", path);
            continue;
        }

        if (hfuzz->maxFileSz != 0UL && st.st_size > (off_t) hfuzz->maxFileSz) {
            LOG_W("File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %"
                  PRId64, path, (int64_t) st.st_size, (int64_t) hfuzz->maxFileSz);
            continue;
        }

        if ((size_t) st.st_size > maxSize) {
            maxSize = st.st_size;
        }

        struct paths_t *file = (struct paths_t *)util_Malloc(sizeof(struct paths_t));
        snprintf(file->path, sizeof(file->path), "%s", path);
        hfuzz->fileCnt = ++count;
        TAILQ_INSERT_TAIL(&hfuzz->fileq, file, pointers);

        LOG_D("Added '%s' to the list of input files", path);
    }

    if (count == 0) {
        LOG_W("Directory '%s' doesn't contain any regular files", hfuzz->inputDir);
        return false;
    }

    if (hfuzz->maxFileSz == 0UL) {
        hfuzz->maxFileSz = maxSize;
    }
    LOG_I("%zu input files have been added to the list. Max file size: %zu", hfuzz->fileCnt,
          hfuzz->maxFileSz);
    return true;
}

bool files_init(honggfuzz_t * hfuzz)
{
    if (!hfuzz->inputDir) {
        LOG_W("No input file/dir specified");
        return false;
    }

    struct stat st;
    if (stat(hfuzz->inputDir, &st) == -1) {
        PLOG_W("Couldn't stat the input dir '%s'", hfuzz->inputDir);
        return false;
    }

    if (!S_ISDIR(st.st_mode)) {
        LOG_W("The initial corpus directory '%s' is not a directory", hfuzz->inputDir);
        return false;
    }

    return files_readdir(hfuzz);
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

        LOG_I("Dictionary: loaded word: '%s' (len=%zu)", str->s, str->len);
    }
    LOG_I("Loaded %zu words from the dictionary", hfuzz->dictionaryCnt);
    return true;
}

/*
 * dstExists argument can be used by caller for cases where existing destination
 * file requires special handling (e.g. save unique crashes)
 */
bool files_copyFile(const char *source, const char *destination, bool * dstExists)
{
    if (dstExists)
        *dstExists = false;
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

    // Now try with a verbose POSIX alternative
    int inFD, outFD, dstOpenFlags;
    mode_t dstFilePerms;

    // O_EXCL is important for saving unique crashes
    dstOpenFlags = O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC;
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
        *fd = -1;
        return NULL;
    }

    uint8_t *buf;
    if ((buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, *fd, 0)) == MAP_FAILED) {
        PLOG_W("Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        *fd = -1;
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

void *files_mapSharedMem(size_t sz, int *fd, const char *dir)
{
    char template[PATH_MAX];
    snprintf(template, sizeof(template), "%s/hfuzz.XXXXXX", dir);
    if ((*fd = mkstemp(template)) == -1) {
        PLOG_W("mkstemp('%s')", template);
        return MAP_FAILED;
    }
    unlink(template);
    if (ftruncate(*fd, sz) == -1) {
        PLOG_W("ftruncate(%d, %zu)", *fd, sz);
        close(*fd);
        return MAP_FAILED;
    }
    void *ret = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if (ret == MAP_FAILED) {
        PLOG_W("mmap(sz=%zu, fd=%d)", sz, *fd);
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

struct paths_t *files_getFileFromFileq(honggfuzz_t * hfuzz, size_t index)
{
    if (index >= hfuzz->fileCnt) {
        LOG_F("File index: %zu >= fileCnt: %zu", index, hfuzz->fileCnt);
    }

    struct paths_t *file;
    size_t i = 0;
    TAILQ_FOREACH(file, &hfuzz->fileq, pointers) {
        if (i++ == index) {
            return file;
        }
    }

    LOG_F("File index: %zu bigger than fileq size", index);
    return NULL;
}

char *files_get_filename_in_path(char* path)
{
    char *filename;

    if(strrchr(path, '/')){		
        filename = strrchr(path, '/')+1;
    }else if(strrchr(path, '\\')){
		filename = strrchr(path, '\\')+1;	// file path use '\' in cygwin 
	}else{
		filename = path;  
	}
    return filename;
}
