#include "libhfuzz/libhfuzz.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libcommon/common.h"
#include "libcommon/files.h"
#include "libcommon/log.h"

__attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len);
__attribute__((weak)) int LLVMFuzzerInitialize(int* argc UNUSED, char*** argv UNUSED) { return 0; }

/* FIXME(robertswiecki): Make it call mangle_Mangle() */
__attribute__((weak)) size_t LLVMFuzzerMutate(
    uint8_t* Data UNUSED, size_t Size UNUSED, size_t MaxSize UNUSED) {
    LOG_F("LLVMFuzzerMutate() is not supported in honggfuzz yet");
    return 0;
}

static uint8_t buf[_HF_PERF_BITMAP_SIZE_16M] = {0};

void HF_ITER(const uint8_t** buf_ptr, size_t* len_ptr) {
    /*
     * Send the 'done' marker to the parent
     */
    static bool initialized = false;

    if (initialized == true) {
        static const uint8_t readyTag = 'A';
        if (files_writeToFd(_HF_PERSISTENT_FD, &readyTag, sizeof(readyTag)) == false) {
            LOG_F("writeToFd(size=%zu) failed", sizeof(readyTag));
        }
    }
    initialized = true;

    uint32_t rlen;
    if (files_readFromFd(_HF_PERSISTENT_FD, (uint8_t*)&rlen, sizeof(rlen)) !=
        (ssize_t)sizeof(rlen)) {
        LOG_F("readFromFd(size=%zu) failed", sizeof(rlen));
    }
    size_t len = (size_t)rlen;
    if (len > _HF_PERF_BITMAP_SIZE_16M) {
        LOG_F("len (%zu) > buf_size (%zu)\n", len, (size_t)_HF_PERF_BITMAP_SIZE_16M);
    }

    if (files_readFromFd(_HF_PERSISTENT_FD, buf, len) != (ssize_t)len) {
        LOG_F("readFromFd(size=%zu) failed", len);
    }

    *buf_ptr = buf;
    *len_ptr = len;
}

static void runOneInput(const uint8_t* buf, size_t len) {
    int ret = LLVMFuzzerTestOneInput(buf, len);
    if (ret != 0) {
        LOG_F("LLVMFuzzerTestOneInput() returned '%d' instead of '0'", ret);
    }
}

/*
 * Declare it 'weak', so it can be safely linked with regular binaries which
 * implement their own main()
 */
#if !defined(__CYGWIN__)
__attribute__((weak))
#endif /* !defined(__CYGWIN__) */
int main(int argc, char** argv) {
    LLVMFuzzerInitialize(&argc, &argv);
    if (LLVMFuzzerTestOneInput == NULL) {
        LOG_F(
            "Define 'int LLVMFuzzerTestOneInput(uint8_t * buf, size_t len)' in your "
            "code to make it work");

        extern int hfuzz_module_instrument;
        extern int hfuzz_module_memorycmp;
        LOG_F(
            "This won't be displayed, it's used just to reference other modules in this archive: "
            "%d",
            hfuzz_module_instrument + hfuzz_module_memorycmp);
    }

    if (fcntl(_HF_PERSISTENT_FD, F_GETFD) == -1 && errno == EBADF) {
        int in_fd = STDIN_FILENO;
        const char* fname = "[STDIN]";
        if (argc > 1) {
            fname = argv[argc - 1];
            if ((in_fd = open(argv[argc - 1], O_RDONLY)) == -1) {
                PLOG_W("Cannot open '%s' as input, using stdin", argv[argc - 1]);
                in_fd = STDIN_FILENO;
                fname = "[STDIN]";
            }
        }

        LOG_I(
            "Accepting input from '%s'\n"
            "Usage for fuzzing: honggfuzz -P [flags] -- %s",
            fname, argv[0]);

        ssize_t len = files_readFromFd(in_fd, buf, sizeof(buf));
        if (len < 0) {
            LOG_E("Couldn't read data from stdin: %s", strerror(errno));
            return -1;
        }

        runOneInput(buf, len);
        return 0;
    }

    for (;;) {
        size_t len;
        const uint8_t* buf;

        HF_ITER(&buf, &len);
        runOneInput(buf, len);
    }
}
