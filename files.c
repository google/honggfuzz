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

#include "log.h"

size_t files_readFileToBufMax(char *fileName, uint8_t * buf, size_t fileMaxSz)
{
    int fd = open(fileName, O_RDONLY);
    if (fd == -1) {
        PLOG_E("Couldn't open '%s' for R/O", fileName);
        return 0UL;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        PLOG_E("Couldn't fstat(fd='%d' fileName='%s')", fd, fileName);
        close(fd);
        return 0UL;
    }

    if (st.st_size > (off_t) fileMaxSz) {
        LOG_E("File '%s' size to big (%zu > %zu)", fileName, (size_t) st.st_size, fileMaxSz);
        close(fd);
        return 0UL;
    }

    if (st.st_size == (off_t) 0ULL) {
        size_t sz = read(fd, buf, fileMaxSz);
        close(fd);
        if (sz <= 0U) {
            return 0U;
        }
        return sz;
    }

    if (files_readFromFd(fd, buf, (size_t) st.st_size) == false) {
        LOG_E("Couldn't read '%s' to a buf", fileName);
        close(fd);
        return 0UL;
    }
    close(fd);

    LOG_D("Read '%zu' bytes (max: '%zu') from '%s'", (size_t) st.st_size, fileMaxSz, fileName);

    return (size_t) st.st_size;
}

bool files_writeBufToFile(char *fileName, uint8_t * buf, size_t fileSz, int flags)
{
    int fd = open(fileName, flags, 0644);
    if (fd == -1) {
        PLOG_E("Couldn't open '%s' for R/O", fileName);
        return false;
    }

    if (files_writeToFd(fd, buf, fileSz) == false) {
        PLOG_E("Couldn't write '%zu' bytes to file '%s' (fd='%d')", fileSz, fileName, fd);
        close(fd);
        unlink(fileName);
        return false;
    }
    close(fd);

    LOG_D("Written '%zu' bytes to '%s'", fileSz, fileName);

    return true;
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

bool files_readFromFd(int fd, uint8_t * buf, size_t fileSz)
{
    size_t readSz = 0;
    while (readSz < fileSz) {
        ssize_t sz = read(fd, &buf[readSz], fileSz - readSz);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz < 0)
            return false;

        readSz += sz;
    }
    return true;
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

    memset(buf, p, (size_t) size);
    int ret = files_writeToFd(fd, buf, size);
    free(buf);

    return ret;
}

static bool files_readdir(honggfuzz_t * hfuzz)
{
    DIR *dir = opendir(hfuzz->inputFile);
    if (!dir) {
        PLOG_E("Couldn't open dir '%s'", hfuzz->inputFile);
        return false;
    }

    int count = 0;
    for (;;) {
        struct dirent de, *res;
        if (readdir_r(dir, &de, &res) > 0) {
            PLOG_E("Couldn't read the '%s' dir", hfuzz->inputFile);
            closedir(dir);
            return false;
        }

        if (res == NULL && count > 0) {
            LOG_I("%zu input files have been added to the list", hfuzz->fileCnt);
            closedir(dir);
            return true;
        }

        if (res == NULL && count == 0) {
            LOG_E("Directory '%s' doesn't contain any regular files", hfuzz->inputFile);
            closedir(dir);
            return false;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", hfuzz->inputFile, res->d_name);
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

        if (st.st_size > (off_t) hfuzz->maxFileSz) {
            LOG_W("File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %"
                  PRId64, path, (int64_t) st.st_size, (int64_t) hfuzz->maxFileSz);
            continue;
        }

        if (!(hfuzz->files = realloc(hfuzz->files, sizeof(char *) * (count + 1)))) {
            PLOG_E("Couldn't allocate memory");
            closedir(dir);
            return false;
        }

        hfuzz->files[count] = strdup(path);
        if (!hfuzz->files[count]) {
            PLOG_E("Couldn't allocate memory");
            closedir(dir);
            return false;
        }
        hfuzz->fileCnt = ++count;
        LOG_D("Added '%s' to the list of input files", path);
    }

    abort();                    /* NOTREACHED */
    return false;
}

bool files_init(honggfuzz_t * hfuzz)
{
    hfuzz->files = malloc(sizeof(char *));
    if (hfuzz->dynFileMethod != _HF_DYNFILE_NONE && !hfuzz->inputFile) {
        hfuzz->fileCnt = 1;
        hfuzz->files[0] = "DYNAMIC_FILE";
        return true;
    }
    if (hfuzz->externalCommand && !hfuzz->inputFile) {
        hfuzz->fileCnt = 1;
        hfuzz->files[0] = "CREATED";
        LOG_I
            ("No input file corpus specified, the external command '%s' is responsible for creating the fuzz files",
             hfuzz->externalCommand);
        return true;
    }

    if (!hfuzz->files) {
        PLOG_E("Couldn't allocate memory");
        return false;
    }

    if (!hfuzz->inputFile) {
        LOG_E("No input file/dir specified");
        return false;
    }

    struct stat st;
    if (stat(hfuzz->inputFile, &st) == -1) {
        PLOG_E("Couldn't stat the input file/dir '%s'", hfuzz->inputFile);
        return false;
    }

    if (S_ISDIR(st.st_mode)) {
        return files_readdir(hfuzz);
    }

    if (!S_ISREG(st.st_mode)) {
        LOG_E("'%s' is not a regular file, nor a directory", hfuzz->inputFile);
        return false;
    }

    if (st.st_size > (off_t) hfuzz->maxFileSz) {
        LOG_E("File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %" PRId64,
              hfuzz->inputFile, (int64_t) st.st_size, (int64_t) hfuzz->maxFileSz);
        return false;
    }

    hfuzz->files[0] = hfuzz->inputFile;
    hfuzz->fileCnt = 1;
    return true;
}

char *files_basename(char *path)
{
    char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

bool files_parseDictionary(honggfuzz_t * hfuzz)
{
    FILE *fDict = fopen(hfuzz->dictionaryFile, "rb");
    if (fDict == NULL) {
        PLOG_E("Couldn't open '%s' - R/O mode", hfuzz->dictionaryFile);
        return false;
    }

    char *lineptr = NULL;
    size_t n = 0;
    for (;;) {
        if (getdelim(&lineptr, &n, '\0', fDict) == -1) {
            break;
        }
        if ((hfuzz->dictionary =
             realloc(hfuzz->dictionary,
                     (hfuzz->dictionaryCnt + 1) * sizeof(hfuzz->dictionary[0]))) == NULL) {
            PLOG_E("Realloc failed (sz=%zu)",
                   (hfuzz->dictionaryCnt + 1) * sizeof(hfuzz->dictionary[0]));
            fclose(fDict);
            free(lineptr);
            return false;
        }
        hfuzz->dictionary[hfuzz->dictionaryCnt] = malloc(strlen(lineptr));
        if (!hfuzz->dictionary[hfuzz->dictionaryCnt]) {
            PLOG_E("malloc(%zu) failed", strlen(lineptr));
            fclose(fDict);
            free(lineptr);
            return false;
        }
        strncpy(hfuzz->dictionary[hfuzz->dictionaryCnt], lineptr, strlen(lineptr));;
        LOG_D("Dictionary: loaded word: '%s' (len=%zu)",
              hfuzz->dictionary[hfuzz->dictionaryCnt],
              strlen(hfuzz->dictionary[hfuzz->dictionaryCnt]));
        hfuzz->dictionaryCnt += 1;
    }
    LOG_I("Loaded %zu words from the dictionary", hfuzz->dictionaryCnt);
    fclose(fDict);
    free(lineptr);
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
    dstOpenFlags = O_CREAT | O_WRONLY | O_EXCL;
    dstFilePerms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

    inFD = open(source, O_RDONLY);
    if (inFD == -1) {
        PLOG_D("Couldn't open '%s' source", source);
        return false;
    }

    struct stat inSt;
    if (fstat(inFD, &inSt) == -1) {
        PLOG_E("Couldn't fstat(fd='%d' fileName='%s')", inFD, source);
        close(inFD);
        return false;
    }

    outFD = open(destination, dstOpenFlags, dstFilePerms);
    if (outFD == -1) {
        if (errno == EEXIST) {
            if (dstExists)
                *dstExists = true;
        }
        PLOG_D("Couldn't open '%s' destination", destination);
        close(inFD);
        return false;
    }

    uint8_t *inFileBuf = malloc(inSt.st_size);
    if (!inFileBuf) {
        PLOG_E("malloc(%zu) failed", (size_t) inSt.st_size);
        close(inFD);
        close(outFD);
        return false;
    }

    if (files_readFromFd(inFD, inFileBuf, (size_t) inSt.st_size) == false) {
        PLOG_E("Couldn't read '%s' to a buf", source);
        free(inFileBuf);
        close(inFD);
        close(outFD);
        return false;
    }

    if (files_writeToFd(outFD, inFileBuf, inSt.st_size) == false) {
        PLOG_E("Couldn't write '%zu' bytes to file '%s' (fd='%d')", (size_t) inSt.st_size,
               destination, outFD);
        free(inFileBuf);
        close(inFD);
        close(outFD);
        unlink(destination);
        return false;
    }

    free(inFileBuf);
    close(inFD);
    close(outFD);
    return true;
}

bool files_parseBlacklist(honggfuzz_t * hfuzz)
{
    FILE *fBl = fopen(hfuzz->blacklistFile, "rb");
    if (fBl == NULL) {
        PLOG_E("Couldn't open '%s' - R/O mode", hfuzz->blacklistFile);
        return false;
    }

    char *lineptr = NULL;
    size_t n = 0;
    for (;;) {
        if (getline(&lineptr, &n, fBl) == -1) {
            break;
        }

        if ((hfuzz->blacklist =
             realloc(hfuzz->blacklist,
                     (hfuzz->blacklistCnt + 1) * sizeof(hfuzz->blacklist[0]))) == NULL) {
            PLOG_E("realloc failed (sz=%zu)",
                   (hfuzz->blacklistCnt + 1) * sizeof(hfuzz->blacklist[0]));
            fclose(fBl);
            free(lineptr);
            return false;
        }

        hfuzz->blacklist[hfuzz->blacklistCnt] = strtoull(lineptr, 0, 16);
        LOG_D("Blacklist: loaded %'" PRIu64 "'", hfuzz->blacklist[hfuzz->blacklistCnt]);

        // Verify entries are sorted so we can use interpolation search
        if (hfuzz->blacklistCnt > 1) {
            if (hfuzz->blacklist[hfuzz->blacklistCnt - 1] > hfuzz->blacklist[hfuzz->blacklistCnt]) {
                LOG_F
                    ("Blacklist file not sorted. Use 'tools/createStackBlacklist.sh' to sort records");
                fclose(fBl);
                free(lineptr);
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
    fclose(fBl);
    free(lineptr);
    return true;
}

uint8_t *files_mapFile(char *fileName, off_t * fileSz, int *fd, bool isWritable)
{
    int mmapProt = PROT_READ;
    if (isWritable) {
        mmapProt |= PROT_WRITE;
    }

    if ((*fd = open(fileName, O_RDONLY)) == -1) {
        PLOG_E("Couldn't open() '%s' file in R/O mode", fileName);
        return NULL;
    }

    struct stat st;
    if (fstat(*fd, &st) == -1) {
        PLOG_E("Couldn't stat() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    uint8_t *buf;
    if ((buf = mmap(NULL, st.st_size, mmapProt, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
        PLOG_E("Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}
