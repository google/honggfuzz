#include <errno.h>
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
#define HF_BUF_SIZE (1024 * 1024 * 16)

static inline ssize_t readFromFd(int fd, uint8_t * buf, size_t len)
{
    size_t readSz = 0;
    while (readSz < len) {
        ssize_t sz = read(fd, &buf[readSz], len - readSz);
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

static inline bool readFromFdAll(int fd, uint8_t * buf, size_t len)
{
    return (readFromFd(fd, buf, len) == (ssize_t) len);
}

static bool writeToFd(int fd, uint8_t * buf, size_t len)
{
    size_t writtenSz = 0;
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
__attribute__ ((weak))
int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv)
{
    uint8_t *buf = (uint8_t *) malloc(HF_BUF_SIZE);
    if (buf == NULL) {
        perror("malloc");
        _exit(1);
    }

    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }

    for (;;) {
        uint32_t rlen;
        if (readFromFdAll(HF_FUZZ_FD, (uint8_t *) & rlen, sizeof(rlen)) == false) {
            fprintf(stderr, "readFromFdAll(size) failed");
            _exit(1);
        }
        size_t len = (size_t) rlen;
        if (len > HF_BUF_SIZE) {
            fprintf(stderr, "len (%zu) > buf_size (%zu)", len, (size_t) HF_BUF_SIZE);
            _exit(1);
        }

        if (readFromFdAll(HF_FUZZ_FD, buf, len) == false) {
            fprintf(stderr, "readFromFdAll(buf) failed");
            _exit(1);
        }

        int ret = LLVMFuzzerTestOneInput(buf, len);
        if (ret != 0) {
            printf("LLVMFuzzerTestOneInput() returned '%d'", ret);
            _exit(1);
        }

        /*
         * Send the 'done' marker to the parent */
        uint8_t z = 'A';
        if (writeToFd(HF_FUZZ_FD, &z, sizeof(z)) == false) {
            fprintf(stderr, "readFromFdAll() failed");
            _exit(1);
        }
        /*
         * Inform the parent that we're done, so it can break out of its wait()
         * sleep cycle
         * */
        raise(SIGCONT);
    }
}
