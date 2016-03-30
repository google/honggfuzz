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

bool readFromFd(int fd, uint8_t * buf, size_t len)
{
    size_t readSz = 0;
    while (readSz < len) {
        ssize_t sz = read(fd, &buf[readSz], len - readSz);
        if (sz < 0 && errno == EINTR)
            continue;

        if (sz <= 0)
            break;

        readSz += sz;
    }
    return (readSz == len);
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

int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len);

int main(int argc, char **argv)
{
    for (;;) {
        char buf[PATH_MAX];
        if (read(1023, buf, PATH_MAX) != PATH_MAX) {
            perror("read");
            exit(1);
        }

        int fd = open(buf, O_RDONLY);
        if (fd == -1) {
            perror("open");
            exit(1);
        }

        uint8_t f[1024 * 1024];
        ssize_t rsz = read(fd, f, sizeof(f));
        if (rsz < 0) {
            perror("read");
            exit(1);
        }

        close(fd);

        LLVMFuzzerTestOneInput(f, rsz);

        char z = 'A';
        if (write(1023, &z, sizeof(z)) != sizeof(z)) {
            perror("write");
            exit(1);
        }
        raise(SIGCONT);
    }
}
