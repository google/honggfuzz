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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

bool files_writeToFd(int fd, uint8_t * buf, off_t fileSz)
{
    off_t written = 0;
    while (written < fileSz) {
        ssize_t sz = write(fd, &buf[written], fileSz - written);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz < 0)
            return false;

        written += sz;
    }

    return true;
}

bool files_writeStrToFd(int fd, char *str)
{
    return files_writeToFd(fd, (uint8_t *) str, strlen(str));
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

void files_unmapFileCloseFd(void *ptr, off_t fileSz, int fd)
{
    munmap(ptr, _HF_PAGE_ALIGN_UP(fileSz));
    close(fd);
}

uint8_t *files_mapFileToRead(char *fileName, off_t * fileSz, int *fd)
{
    if ((*fd = open(fileName, O_RDONLY)) == -1) {
        LOGMSG_P(l_WARN, "Couldn't open() '%s' file in R/O mode", fileName);
        return NULL;
    }

    struct stat st;
    if (fstat(*fd, &st) == -1) {
        LOGMSG_P(l_WARN, "Couldn't stat() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    uint8_t *buf;
    if ((buf =
         mmap(NULL, _HF_PAGE_ALIGN_UP(st.st_size), PROT_READ | PROT_WRITE, MAP_PRIVATE, *fd,
              0)) == MAP_FAILED) {
        LOGMSG_P(l_WARN, "Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    LOGMSG(l_DEBUG, "mmap()'d '%llu' bytes for the file '%s' (original size: '%llu') at 0x%p",
           (unsigned long long)_HF_PAGE_ALIGN_UP(st.st_size), fileName,
           (unsigned long long)st.st_size, buf);
    *fileSz = st.st_size;
    return buf;
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

        if (st.st_size == 0) {
            LOGMSG(l_DEBUG, "'%s' is empty", path);
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
    if (hfuzz->createDynamically) {
        hfuzz->fileCnt = 1;
        hfuzz->files[0] = "GENERATED";
        LOGMSG(l_INFO, "Files will be created dynamically");
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
