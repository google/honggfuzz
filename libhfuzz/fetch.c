#include "libhfuzz/fetch.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"

/*
 * If this signature is visible inside a binary, it's probably a persistent-style fuzzing program.
 * This mode of discover is employed by honggfuzz
 */
__attribute__((visibility("default"))) __attribute__((used)) const char* LIBHFUZZ_module_fetch =
    _HF_PERSISTENT_SIG;

static const uint8_t* inputFile = NULL;
__attribute__((constructor)) static void init(void) {
    if (fcntl(_HF_INPUT_FD, F_GETFD) == -1 && errno == EBADF) {
        return;
    }
    if ((inputFile = mmap(NULL, _HF_INPUT_MAX_SIZE, PROT_READ, MAP_SHARED, _HF_INPUT_FD, 0)) ==
        MAP_FAILED) {
        PLOG_F("mmap(fd=%d, size=%zu) of the input file failed", _HF_INPUT_FD,
            (size_t)_HF_INPUT_MAX_SIZE);
    }
}

void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr) {
    if (!files_writeToFd(_HF_PERSISTENT_FD, &HFReadyTag, sizeof(HFReadyTag))) {
        LOG_F("writeToFd(size=%zu, readyTag) failed", sizeof(HFReadyTag));
    }

    uint64_t rcvLen;
    ssize_t sz = files_readFromFd(_HF_PERSISTENT_FD, (uint8_t*)&rcvLen, sizeof(rcvLen));
    if (sz == -1) {
        PLOG_F("readFromFd(fd=%d, size=%zu) failed", _HF_PERSISTENT_FD, sizeof(rcvLen));
    }
    if (sz != sizeof(rcvLen)) {
        LOG_F("readFromFd(fd=%d, size=%zu) failed, received=%zd bytes", _HF_PERSISTENT_FD,
            sizeof(rcvLen), sz);
    }

    *buf_ptr = inputFile;
    *len_ptr = (size_t)rcvLen;
}

bool fetchIsInputAvailable(void) {
    LOG_D("Current module: %s", LIBHFUZZ_module_fetch);
    return (inputFile != NULL);
}
