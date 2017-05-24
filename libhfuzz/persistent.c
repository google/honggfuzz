#include "../libcommon/common.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../libcommon/log.h"
#include "../libcommon/files.h"

int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len) __attribute__ ((weak));
int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__ ((weak));

static uint8_t buf[_HF_PERF_BITMAP_SIZE_16M] = { 0 };

static inline bool readFromFdAll(int fd, uint8_t * buf, size_t len)
{
    return (files_readFromFd(fd, buf, len) == (ssize_t) len);
}

void HF_ITER(uint8_t ** buf_ptr, size_t * len_ptr)
{
    /*
     * Send the 'done' marker to the parent
     */
    static bool initialized = false;

    if (initialized == true) {
        static const uint8_t readyTag = 'A';
        if (files_writeToFd(_HF_PERSISTENT_FD, &readyTag, sizeof(readyTag)) == false) {
            LOG_F("readFromFdAll() failed");
        }
    }
    initialized = true;

    uint32_t rlen;
    if (readFromFdAll(_HF_PERSISTENT_FD, (uint8_t *) & rlen, sizeof(rlen)) == false) {
        LOG_F("readFromFdAll(size) failed");
    }
    size_t len = (size_t) rlen;
    if (len > _HF_PERF_BITMAP_SIZE_16M) {
        LOG_F("len (%zu) > buf_size (%zu)\n", len, (size_t) _HF_PERF_BITMAP_SIZE_16M);
    }

    if (readFromFdAll(_HF_PERSISTENT_FD, buf, len) == false) {
        LOG_F("readFromFdAll(buf) failed");
    }

    *buf_ptr = buf;
    *len_ptr = len;
}

static void runOneInput(uint8_t * buf, size_t len)
{
    int ret = LLVMFuzzerTestOneInput(buf, len);
    if (ret != 0) {
        LOG_F("LLVMFuzzerTestOneInput() returned '%d' instead of '0'", ret);
    }
}

/*
 * Declare it 'weak', so it can be safely linked with regular binaries which
 * implement their own main()
 */
__attribute__ ((weak))
int main(int argc, char **argv)
{
    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }
    if (LLVMFuzzerTestOneInput == NULL) {
        LOG_F("Define 'int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len)' in your "
              "code to make it work");
    }

    if (fcntl(_HF_PERSISTENT_FD, F_GETFD) == -1 && errno == EBADF) {
        LOG_I("Accepting input from stdin\n"
              "Usage for fuzzing: honggfuzz -P [flags] -- %s", argv[0]);

        ssize_t len = files_readFromFd(STDIN_FILENO, buf, sizeof(buf));
        if (len < 0) {
            LOG_E("Couldn't read data from stdin: %s", strerror(errno));
            return -1;
        }

        runOneInput(buf, len);
        return 0;
    }

    for (;;) {
        size_t len;
        uint8_t *buf;

        HF_ITER(&buf, &len);
        runOneInput(buf, len);
    }
}
