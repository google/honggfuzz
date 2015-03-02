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
        LOGMSG_P(l_ERROR, "Couldn't open '%s' for R/O", fileName);
        return 0UL;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        LOGMSG_P(l_ERROR, "Couldn't fstat(fd='%d' fileName='%s')", fd, fileName);
        close(fd);
        return 0UL;
    }

    if (st.st_size > (off_t) fileMaxSz) {
        LOGMSG(l_ERROR, "File '%s' size to big (%zu > %" PRId64 ")", fileName, (int64_t) st.st_size,
               fileMaxSz);
        close(fd);
        return 0UL;
    }

    if (files_readFromFd(fd, buf, (size_t) st.st_size) == false) {
        LOGMSG(l_ERROR, "Couldn't read '%s' to a buf", fileName);
        close(fd);
        return 0UL;
    }
    close(fd);

    LOGMSG(l_DEBUG, "Read '%zu' bytes (max: '%zu') from '%s'", (size_t) st.st_size, fileMaxSz,
           fileName);

    return (size_t) st.st_size;
}

bool files_writeBufToFile(char *fileName, uint8_t * buf, size_t fileSz, int flags)
{
    int fd = open(fileName, flags, 0644);
    if (fd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't open '%s' for R/O", fileName);
        return false;
    }

    if (files_writeToFd(fd, buf, fileSz) == false) {
        LOGMSG(l_ERROR, "Couldn't write '%zu' bytes to file '%s' (fd='%d')", fileSz, fileName, fd);
        close(fd);
        unlink(fileName);
        return false;
    }
    close(fd);

    LOGMSG(l_DEBUG, "Written '%zu' bytes to '%s'", fileSz, fileName);

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
        LOGMSG_P(l_WARN, "Couldn't allocate memory");
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
        LOGMSG_P(l_ERROR, "Couldn't open dir '%s'", hfuzz->inputFile);
        return false;
    }

    int count = 0;
    for (;;) {
        struct dirent de, *res;
        if (readdir_r(dir, &de, &res) > 0) {
            LOGMSG_P(l_ERROR, "Couldn't read the '%s' dir", hfuzz->inputFile);
            closedir(dir);
            return false;
        }

        if (res == NULL && count > 0) {
            LOGMSG(l_INFO, "%d input files have been added to the list", hfuzz->fileCnt);
            closedir(dir);
            return true;
        }

        if (res == NULL && count == 0) {
            LOGMSG(l_ERROR, "Directory '%s' doesn't contain any regular files", hfuzz->inputFile);
            closedir(dir);
            return false;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", hfuzz->inputFile, res->d_name);
        struct stat st;
        if (stat(path, &st) == -1) {
            LOGMSG(l_WARN, "Couldn't stat() the '%s' file", path);
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            LOGMSG(l_DEBUG, "'%s' is not a regular file, skipping", path);
            continue;
        }

        if (st.st_size == 0ULL) {
            LOGMSG(l_DEBUG, "'%s' is empty", path);
            continue;
        }

        if (st.st_size > (off_t) hfuzz->maxFileSz) {
            LOGMSG(l_WARN,
                   "File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %"
                   PRId64, path, (int64_t) st.st_size, (int64_t) hfuzz->maxFileSz);
            continue;
        }

        if (!(hfuzz->files = realloc(hfuzz->files, sizeof(char *) * (count + 1)))) {
            LOGMSG_P(l_ERROR, "Couldn't allocate memory");
            closedir(dir);
            return false;
        }

        hfuzz->files[count] = strdup(path);
        if (!hfuzz->files[count]) {
            LOGMSG_P(l_ERROR, "Couldn't allocate memory");
            closedir(dir);
            return false;
        }
        hfuzz->fileCnt = ++count;
        LOGMSG(l_DEBUG, "Added '%s' to the list of input files", path);
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
        LOGMSG(l_INFO,
               "No input file corpus specified, the external command '%s' is responsible for creating the fuzz files",
               hfuzz->externalCommand);
        return true;
    }

    if (!hfuzz->files) {
        LOGMSG_P(l_ERROR, "Couldn't allocate memory");
        return false;
    }

    if (!hfuzz->inputFile) {
        LOGMSG(l_ERROR, "No input file/dir specified");
        return false;
    }

    struct stat st;
    if (stat(hfuzz->inputFile, &st) == -1) {
        LOGMSG_P(l_ERROR, "Couldn't stat the input file/dir '%s'", hfuzz->inputFile);
        return false;
    }

    if (st.st_size > (off_t) hfuzz->maxFileSz) {
        LOGMSG(l_ERROR,
               "File '%s' is bigger than maximal defined file size (-F): %" PRId64 " > %" PRId64,
               hfuzz->inputFile, (int64_t) st.st_size, (int64_t) hfuzz->maxFileSz);
        return false;
    }

    if (S_ISDIR(st.st_mode)) {
        return files_readdir(hfuzz);
    }

    if (!S_ISREG(st.st_mode)) {
        LOGMSG(l_ERROR, "'%s' is not a regular file, nor a directory", hfuzz->inputFile);
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
