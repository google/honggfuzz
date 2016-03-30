#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HF_FUZZ_FD 1023

static ssize_t readFromFd(int fd, uint8_t * buf, size_t len)
{
    ssize_t readSz = 0;
    while (readSz < len) {
        ssize_t sz = read(fd, &buf[readSz], len - readSz);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz <= 0)
            break;

        readSz += sz;
    }
    return len;
}

static bool readFromFdAll(int fd, uint8_t * buf, size_t len)
{
    return (readFromFd(fd, buf, len) == len);
}

static bool writeToFd(int fd, uint8_t * buf, size_t len)
{
    ssize_t writtenSz = 0;
    while (writtenSz < len) {
        ssize_t sz = write(fd, &buf[writtenSz], len - writtenSz);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz < 0)
            return false;

        writtenSz += sz;
    }
    return (writtenSz == len);
}

int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len);

int main(int argc, char **argv)
{
    for (;;) {
        uint8_t fname[PATH_MAX];
        if (readFromFdAll(HF_FUZZ_FD, fname, PATH_MAX) == false) {
            perror("readFromFdAll");
            exit(1);
        }

        int fd = open((char *)fname, O_RDONLY);
        if (fd == -1) {
            perror("open");
            exit(1);
        }

        uint8_t f[1024 * 1024];
        ssize_t rsz = readFromFd(fd, f, sizeof(f));
        if (rsz < 0) {
            perror("readFromFd");
            exit(1);
        }

        close(fd);

        LLVMFuzzerTestOneInput(f, rsz);

        uint8_t z = 'A';
        if (writeToFd(HF_FUZZ_FD, &z, sizeof(z)) == false) {
            perror("writeToFd");
            exit(1);
        }
        raise(SIGCONT);
    }
}
