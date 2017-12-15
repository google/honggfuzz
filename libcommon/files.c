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

#include "files.h"
#include "common.h"

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
#if defined(_HF_ARCH_LINUX)
#include <sys/syscall.h>
#endif /* defined(_HF_ARCH_LINUX) */
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

ssize_t files_readFileToBufMax(char* fileName, uint8_t* buf, size_t fileMaxSz) {
    int fd = open(fileName, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        PLOG_W("Couldn't open '%s' for R/O", fileName);
        return -1;
    }

    ssize_t readSz = files_readFromFd(fd, buf, fileMaxSz);
    if (readSz < 0) {
        LOG_W("Couldn't read '%s' to a buf", fileName);
    }
    close(fd);

    LOG_D("Read '%zu' bytes from '%s'", readSz, fileName);
    return readSz;
}

bool files_writeBufToFile(const char* fileName, const uint8_t* buf, size_t fileSz, int flags) {
    int fd = open(fileName, flags, 0644);
    if (fd == -1) {
        PLOG_W("Couldn't open '%s' for R/W", fileName);
        return false;
    }

    bool ret = files_writeToFd(fd, buf, fileSz);
    if (ret == false) {
        PLOG_W("Couldn't write '%zu' bytes to file '%s' (fd='%d')", fileSz, fileName, fd);
        unlink(fileName);
    } else {
        LOG_D("Written '%zu' bytes to '%s'", fileSz, fileName);
    }

    close(fd);
    return ret;
}

bool files_writeToFd(int fd, const uint8_t* buf, size_t fileSz) {
    size_t writtenSz = 0;
    while (writtenSz < fileSz) {
        ssize_t sz = write(fd, &buf[writtenSz], fileSz - writtenSz);
        if (sz < 0 && errno == EINTR) continue;

        if (sz < 0) return false;

        writtenSz += sz;
    }
    return true;
}

bool files_writeStrToFd(int fd, const char* str) {
    return files_writeToFd(fd, (const uint8_t*)str, strlen(str));
}

ssize_t files_readFromFd(int fd, uint8_t* buf, size_t fileSz) {
    size_t readSz = 0;
    while (readSz < fileSz) {
        ssize_t sz = read(fd, &buf[readSz], fileSz - readSz);
        if (sz < 0 && errno == EINTR) continue;

        if (sz == 0) break;

        if (sz < 0) return -1;

        readSz += sz;
    }
    return (ssize_t)readSz;
}

bool files_exists(const char* fileName) { return (access(fileName, F_OK) != -1); }

bool files_writePatternToFd(int fd, off_t size, unsigned char p) {
    void* buf = malloc(size);
    if (!buf) {
        PLOG_W("Couldn't allocate memory");
        return false;
    }

    memset(buf, p, (size_t)size);
    int ret = files_writeToFd(fd, buf, size);
    free(buf);

    return ret;
}

bool files_sendToSocketNB(int fd, const uint8_t* buf, size_t fileSz) {
    size_t writtenSz = 0;
    while (writtenSz < fileSz) {
        ssize_t sz = send(fd, &buf[writtenSz], fileSz - writtenSz, MSG_DONTWAIT);
        if (sz < 0 && errno == EINTR) continue;

        if (sz < 0) return false;

        writtenSz += sz;
    }
    return true;
}

bool files_sendToSocket(int fd, const uint8_t* buf, size_t fileSz) {
    int sendFlags = 0;
#ifdef _HF_ARCH_DARWIN
    sendFlags |= SO_NOSIGPIPE;
#else
    sendFlags |= MSG_NOSIGNAL;
#endif

    size_t writtenSz = 0;
    while (writtenSz < fileSz) {
        ssize_t sz = send(fd, &buf[writtenSz], fileSz - writtenSz, sendFlags);
        if (sz < 0 && errno == EINTR) continue;

        if (sz < 0) return false;

        writtenSz += sz;
    }
    return true;
}

const char* files_basename(const char* path) {
    const char* base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/*
 * dstExists argument can be used by caller for cases where existing destination
 * file requires special handling (e.g. save unique crashes)
 */
bool files_copyFile(const char* source, const char* destination, bool* dstExists, bool try_link) {
    if (dstExists) {
        *dstExists = false;
    }

    if (try_link) {
        if (link(source, destination) == 0) {
            return true;
        } else {
            if (errno == EEXIST) {
                // Should kick-in before MAC, so avoid the hassle
                if (dstExists) *dstExists = true;
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

    struct stat inSt;
    if (fstat(inFD, &inSt) == -1) {
        PLOG_W("Couldn't fstat(fd='%d' fileName='%s')", inFD, source);
        close(inFD);
        return false;
    }

    outFD = open(destination, dstOpenFlags, dstFilePerms);
    if (outFD == -1) {
        if (errno == EEXIST) {
            if (dstExists) *dstExists = true;
        }
        PLOG_D("Couldn't open '%s' destination", destination);
        close(inFD);
        return false;
    }
    close(outFD);

    uint8_t* inFileBuf = malloc(inSt.st_size);
    if (!inFileBuf) {
        PLOG_W("malloc(%zu) failed", (size_t)inSt.st_size);
        close(inFD);
        close(outFD);
        return false;
    }

    ssize_t readSz = files_readFromFd(inFD, inFileBuf, (size_t)inSt.st_size);
    if (readSz < 0) {
        PLOG_W("Couldn't read '%s' to a buf", source);
        free(inFileBuf);
        close(inFD);
        close(outFD);
        return false;
    }

    if (files_writeToFd(outFD, inFileBuf, readSz) == false) {
        PLOG_W("Couldn't write '%zu' bytes to file '%s' (fd='%d')", (size_t)readSz, destination,
            outFD);
        unlink(destination);
        free(inFileBuf);
        close(inFD);
        close(outFD);
        return false;
    }

    free(inFileBuf);
    close(inFD);
    close(outFD);
    return true;
}

/*
 * Reads symbols from src file (one per line) and append them to filterList. The
 * total number of added symbols is returned.
 *
 * Simple wildcard strings are also supported (e.g. mem*)
 */
size_t files_parseSymbolFilter(const char* srcFile, char*** filterList) {
    FILE* f = fopen(srcFile, "rb");
    if (f == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", srcFile);
        return 0;
    }

    char* lineptr = NULL;
    size_t symbolsRead = 0, n = 0;
    for (;;) {
        if (getline(&lineptr, &n, f) == -1) {
            break;
        }

        if (strlen(lineptr) < 3) {
            LOG_F("Input symbol '%s' too short (strlen < 3)", lineptr);
            symbolsRead = 0;
            break;
        }
        if ((*filterList = (char**)util_Realloc(
                 *filterList, (symbolsRead + 1) * sizeof((*filterList)[0]))) == NULL) {
            PLOG_W("realloc failed (sz=%zu)", (symbolsRead + 1) * sizeof((*filterList)[0]));
            symbolsRead = 0;
            break;
        }
        (*filterList)[symbolsRead] = malloc(strlen(lineptr));
        if (!(*filterList)[symbolsRead]) {
            PLOG_E("malloc(%zu) failed", strlen(lineptr));
            symbolsRead = 0;
            break;
        }
        strncpy((*filterList)[symbolsRead], lineptr, strlen(lineptr));
        symbolsRead++;
    }

    LOG_I("%zu filter symbols added to list", symbolsRead);
    fclose(f);
    free(lineptr);
    return symbolsRead;
}

uint8_t* files_mapFile(const char* fileName, off_t* fileSz, int* fd, bool isWritable) {
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

    uint8_t* buf;
    if ((buf = mmap(NULL, st.st_size, mmapProt, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
        PLOG_W("Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

uint8_t* files_mapFileShared(const char* fileName, off_t* fileSz, int* fd) {
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

    uint8_t* buf;
    if ((buf = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, *fd, 0)) == MAP_FAILED) {
        PLOG_W("Couldn't mmap() the '%s' file", fileName);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

void* files_mapSharedMem(size_t sz, int* fd, const char* dir) {
    *fd = -1;
#if defined(_HF_ARCH_LINUX) && defined(__NR_memfd_create)
#if !defined(MFD_CLOEXEC) /* It's not defined as we didn't include sys/memfd.h, but it's \
                             present with some Linux distros only */
#define MFD_CLOEXEC 0x0001U
#endif /* !defined(MFD_CLOEXEC) */
    *fd = syscall(__NR_memfd_create, "honggfuzz", (uintptr_t)MFD_CLOEXEC);
#endif /* defined(_HF_ARCH_LINUX) && defined(__NR_memfd_create) */
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
    void* ret = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if (ret == MAP_FAILED) {
        PLOG_W("mmap(sz=%zu, fd=%d)", sz, *fd);
        *fd = -1;
        close(*fd);
        return MAP_FAILED;
    }
    return ret;
}

bool files_readPidFromFile(const char* fileName, pid_t* pidPtr) {
    FILE* fPID = fopen(fileName, "rbe");
    if (fPID == NULL) {
        PLOG_W("Couldn't open '%s' - R/O mode", fileName);
        return false;
    }

    char* lineptr = NULL;
    size_t lineSz = 0;
    ssize_t ret = getline(&lineptr, &lineSz, fPID);
    fclose(fPID);
    if (ret == -1) {
        if (lineSz == 0) {
            LOG_W("Empty PID file (%s)", fileName);
            fclose(fPID);
            free(lineptr);
            return false;
        }
    }

    *pidPtr = atoi(lineptr);
    free(lineptr);
    if (*pidPtr < 1) {
        LOG_W("Invalid PID read from '%s' file", fileName);
        return false;
    }

    return true;
}
