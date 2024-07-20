/*
 *
 * honggfuzz - file operations
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
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

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#if defined(_HF_ARCH_LINUX)
#include <linux/memfd.h>
#endif /* defined(_HF_ARCH_LINUX) */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#if defined(_HF_ARCH_LINUX)
#include <sys/syscall.h>
#endif /* defined(_HF_ARCH_LINUX) */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "util.h"

ssize_t files_readFileToBufMax(const char* fname, uint8_t* buf, size_t fileMaxSz) {
    int fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        PLOG_W("Couldn't open '%s' for R/O", fname);
        return -1;
    }

    ssize_t readSz = files_readFromFd(fd, buf, fileMaxSz);
    if (readSz < 0) {
        PLOG_W("Couldn't read '%s' to a buf (size=%zu)", fname, fileMaxSz);
    }
    close(fd);

    LOG_D("Read %zu bytes (%zu requested) from '%s'", (size_t)readSz, fileMaxSz, fname);
    return readSz;
}

bool files_writeBufToFile(const char* fname, const uint8_t* buf, size_t fileSz, int flags) {
    int fd = TEMP_FAILURE_RETRY(open(fname, flags, 0644));
    if (fd == -1) {
        PLOG_W("Couldn't create/open '%s' for R/W", fname);
        return false;
    }

    bool ret = files_writeToFd(fd, buf, fileSz);
    if (!ret) {
        PLOG_W("Couldn't write '%zu' bytes to file '%s' (fd='%d')", fileSz, fname, fd);
        unlink(fname);
    } else {
        LOG_D("Written '%zu' bytes to '%s'", fileSz, fname);
    }

    close(fd);
    return ret;
}

bool files_writeStrToFile(const char* fname, const char* str, int flags) {
    return files_writeBufToFile(fname, (uint8_t*)str, strlen(str), flags);
}

int files_writeBufToTmpFile(const char* dir, const uint8_t* buf, size_t fileSz, int flags) {
    char template[PATH_MAX];
    snprintf(template, sizeof(template), "%s/hfuzz.XXXXXX", dir);
    int fd = mkostemp(template, flags);
    if (fd == -1) {
        PLOG_W("mkostemp('%s') failed", template);
        return -1;
    }
    if (unlink(template) == -1) {
        PLOG_W("unlink('%s')", template);
    }
    if (!files_writeToFd(fd, buf, fileSz)) {
        PLOG_W("Couldn't save data to the temporary file");
        close(fd);
        return -1;
    }
    if (lseek(fd, (off_t)0, SEEK_SET) == (off_t)-1) {
        PLOG_W("Couldn't rewind file '%s' fd=%d", template, fd);
        close(fd);
        return -1;
    }
    return fd;
}

bool files_writeToFd(int fd, const uint8_t* buf, size_t fileSz) {
    size_t writtenSz = 0;
    while (writtenSz < fileSz) {
        ssize_t sz = TEMP_FAILURE_RETRY(write(fd, &buf[writtenSz], fileSz - writtenSz));
        if (sz < 0) {
            return false;
        }
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
        ssize_t sz = TEMP_FAILURE_RETRY(read(fd, &buf[readSz], fileSz - readSz));
        if (sz == 0) {
            break;
        }
        if (sz < 0) {
            return -1;
        }
        readSz += sz;
    }
    return (ssize_t)readSz;
}

ssize_t files_readFromFdSeek(int fd, uint8_t* buf, size_t fileSz, off_t off) {
    if (lseek(fd, (off_t)0, SEEK_SET) == (off_t)-1) {
        PLOG_W("lseek(fd=%d, %lld, SEEK_SET)", fd, (long long int)off);
        return -1;
    }
    return files_readFromFd(fd, buf, fileSz);
}

bool files_exists(const char* fname) {
    return (access(fname, F_OK) != -1);
}

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
        ssize_t sz =
            TEMP_FAILURE_RETRY(send(fd, &buf[writtenSz], fileSz - writtenSz, MSG_DONTWAIT));
        if (sz < 0) {
            return false;
        }
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

/* Zero all bytes in the file */
bool files_resetFile(int fd, size_t sz) {
#if defined(_HF_ARCH_LINUX)
    if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, (off_t)0, (off_t)sz) != -1) {
        return true;
    }
    PLOG_W("fallocate(fd=%d, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, sz=%zu)", fd, sz);
#endif /* defined(_HF_ARCH_LINUX) */

    /* Fallback mode */
    if (TEMP_FAILURE_RETRY(ftruncate(fd, (off_t)0)) == -1) {
        PLOG_W("ftruncate(fd=%d, sz=0)", fd);
        return false;
    }
    if (TEMP_FAILURE_RETRY(ftruncate(fd, (off_t)sz)) == -1) {
        PLOG_W("ftruncate(fd=%d, sz=%zu)", fd, sz);
        return false;
    }
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

    char*  lineptr     = NULL;
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
        snprintf((*filterList)[symbolsRead], strlen(lineptr), "%s", lineptr);
        symbolsRead++;
    }

    LOG_I("%zu filter symbols added to list", symbolsRead);
    fclose(f);
    free(lineptr);
    return symbolsRead;
}

uint8_t* files_mapFile(const char* fname, off_t* fileSz, int* fd, bool isWritable) {
    int mmapProt = PROT_READ;
    if (isWritable) {
        mmapProt |= PROT_WRITE;
    }

    if ((*fd = TEMP_FAILURE_RETRY(open(fname, O_RDONLY))) == -1) {
        PLOG_W("Couldn't open() '%s' file in R/O mode", fname);
        return NULL;
    }

    struct stat st;
    if (fstat(*fd, &st) == -1) {
        PLOG_W("Couldn't stat() the '%s' file", fname);
        close(*fd);
        return NULL;
    }

    uint8_t* buf;
    if ((buf = mmap(NULL, st.st_size, mmapProt, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
        PLOG_W("Couldn't mmap() the '%s' file", fname);
        close(*fd);
        return NULL;
    }

    *fileSz = st.st_size;
    return buf;
}

/* mmap flags for various OSs, when mmap'ing a temporary file or a shared mem */
int files_getTmpMapFlags(int flag, bool nocore) {
#if defined(MAP_NOSYNC)
    /*
     * Some kind of bug in FreeBSD kernel. Without this flag, the shm_open() memory will cause a lot
     * of troubles to the calling process when mmap()'d
     */
    flag |= MAP_NOSYNC;
#endif /* defined(MAP_NOSYNC) */
#if defined(MAP_HASSEMAPHORE)
    /* Our shared/mmap'd pages can have mutexes in them */
    flag |= MAP_HASSEMAPHORE;
#endif /* defined(MAP_HASSEMAPHORE) */
    if (nocore) {
#if defined(MAP_CONCEAL)
        flag |= MAP_CONCEAL;
#endif /* defined(MAP_CONCEAL) */
#if defined(MAP_NOCORE)
        flag |= MAP_NOCORE;
#endif /* defined(MAP_NOCORE) */
    }
    return flag;
}

int files_createSharedMem(size_t sz, const char* name, bool exportmap) {
    int fd = -1;

    if (exportmap) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "./%s", name);
        if ((fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)) == -1) {
            PLOG_W("open('%s')", path);
            return -1;
        }
    }

#if defined(_HF_ARCH_LINUX)
    if (fd == -1) {
        fd = syscall(__NR_memfd_create, name, (uintptr_t)(MFD_CLOEXEC));
    }
#endif /* defined(_HF_ARCH_LINUX) */

/* SHM_ANON is available with some *BSD OSes */
#if defined(SHM_ANON)
    if (fd == -1) {
        if ((fd = shm_open(SHM_ANON, O_RDWR, 0600)) == -1) {
            PLOG_W("shm_open(SHM_ANON, O_RDWR, 0600)");
        }
    }
#endif /* defined(SHM_ANON) */

/* Use regular shm_open */
#if !defined(_HF_ARCH_DARWIN) && !defined(__ANDROID__)
    /* shm objects under MacOSX are 'a-typical' */
    if (fd == -1) {
        char           tmpname[PATH_MAX];
        struct timeval tv;
        gettimeofday(&tv, NULL);
        snprintf(tmpname, sizeof(tmpname), "/%s%lx%lx%d", name, (unsigned long)tv.tv_sec,
            (unsigned long)tv.tv_usec, (int)getpid());
        if ((fd = shm_open(tmpname, O_RDWR | O_CREAT | O_EXCL, 0600)) == -1) {
            PLOG_W("shm_open('%s', O_RDWR|O_CREAT|O_EXCL, 0600)", tmpname);
        } else {
            shm_unlink(tmpname);
        }
    }
#endif /* !defined(_HF_ARCH_DARWIN) && !defined(__ANDROID__) */

    /* As the last resort, create a file in /tmp */
    if (fd == -1) {
        char template[PATH_MAX];
        snprintf(template, sizeof(template), "/tmp/%s.XXXXXX", name);
        if ((fd = mkostemp(template, O_CLOEXEC)) == -1) {
            PLOG_W("mkstemp('%s')", template);
            return -1;
        }
        unlink(template);
    }

    if (TEMP_FAILURE_RETRY(ftruncate(fd, sz)) == -1) {
        PLOG_W("ftruncate(%d, %zu)", fd, sz);
        close(fd);
        return -1;
    }

    return fd;
}

void* files_mapSharedMem(size_t sz, int* fd, const char* name, bool nocore, bool exportmap) {
    *fd = files_createSharedMem(sz, name, exportmap);
    if (*fd == -1) {
        return NULL;
    }

    int   mflags = files_getTmpMapFlags(MAP_SHARED, /* nocore= */ true);
    void* ret    = mmap(NULL, sz, PROT_READ | PROT_WRITE, mflags, *fd, 0);
    if (ret == MAP_FAILED) {
        PLOG_W("mmap(sz=%zu, fd=%d)", sz, *fd);
        *fd = -1;
        close(*fd);
        return NULL;
    }
    if (posix_madvise(ret, sz, POSIX_MADV_RANDOM) == -1) {
        PLOG_W("posix_madvise(sz=%zu, POSIX_MADV_RANDOM)", sz);
    }
    if (nocore) {
#if defined(MADV_DONTDUMP)
        if (madvise(ret, sz, MADV_DONTDUMP) == -1) {
            PLOG_W("madvise(sz=%zu, MADV_DONTDUMP)", sz);
        }
#endif /* defined(MADV_DONTDUMP) */
#if defined(MADV_NOCORE)
        if (madvise(ret, sz, MADV_NOCORE) == -1) {
            PLOG_W("madvise(sz=%zu, MADV_NOCORE)", sz);
        }
#endif /* defined(MADV_NOCORE) */
    }
    return ret;
}

sa_family_t files_sockFamily(int sock) {
    struct sockaddr addr;
    socklen_t       addrlen = sizeof(addr);

    if (getsockname(sock, &addr, &addrlen) == -1) {
        PLOG_W("getsockname(sock=%d)", sock);
        return AF_UNSPEC;
    }

    return addr.sa_family;
}

const char* files_sockAddrToStr(const struct sockaddr* sa, const socklen_t len) {
    static __thread char str[4096];

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)sa;
        if (inet_ntop(sin->sin_family, &sin->sin_addr.s_addr, str, sizeof(str))) {
            util_ssnprintf(str, sizeof(str), "/%hd", ntohs(sin->sin_port));
        } else {
            snprintf(str, sizeof(str), "IPv4 addr conversion failed");
        }
        return str;
    }
    if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
        if (inet_ntop(sin6->sin6_family, sin6->sin6_addr.s6_addr, str, sizeof(str))) {
            util_ssnprintf(str, sizeof(str), "/%hd", ntohs(sin6->sin6_port));
        } else {
            snprintf(str, sizeof(str), "IPv6 addr conversion failed");
        }
        return str;
    }

    if (sa->sa_family == AF_UNIX) {
        if ((size_t)len <= offsetof(struct sockaddr_un, sun_path)) {
            snprintf(str, sizeof(str), "unix:<struct too short at %u bytes>", (unsigned)len);
            return str;
        }

        struct sockaddr_un* sun = (struct sockaddr_un*)sa;
        int                 pathlen;

        if (sun->sun_path[0] == '\0') {
            /* Abstract socket
             *
             * TODO: Handle null bytes in sun->sun_path (they have no
             * special significance unlike in C char arrays, see unix(7))
             */
            pathlen = strnlen(&sun->sun_path[1], len - offsetof(struct sockaddr_un, sun_path) - 1);

            snprintf(str, sizeof(str), "unix:abstract:%-*s", pathlen, &sun->sun_path[1]);
            return str;
        }

        pathlen = strnlen(sun->sun_path, len - offsetof(struct sockaddr_un, sun_path));

        snprintf(str, sizeof(str), "unix:%-*s", pathlen, sun->sun_path);
        return str;
    }

    snprintf(str, sizeof(str), "Unsupported sockaddr family=%d", (int)sa->sa_family);
    return str;
}
