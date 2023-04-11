#include "libhfuzz/fetch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"

/*
 * If this signature is visible inside a binary, it's probably a persistent-style fuzzing program.
 * This discovery mode is employed by honggfuzz
 */
__attribute__((visibility("default"))) __attribute__((used)) const char* LIBHFUZZ_module_fetch =
    _HF_PERSISTENT_SIG;

static const uint8_t*                    inputFile = NULL;
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

/*
 * Instruct *SAN to treat the input buffer to be of a specific size, treating all accesses
 * beyond that as access violations
 */
static void fetchSanPoison(const uint8_t* buf, size_t len) {
/* MacOS X linker doesn't like those */
#if defined(_HF_ARCH_DARWIN) || defined(__APPLE__)
    return;
#endif /* defined(_HF_ARCH_DARWIN) */
    __attribute__((weak)) extern void __asan_unpoison_memory_region(const void* addr, size_t sz);
    __attribute__((weak)) extern void __msan_unpoison(const void* addr, size_t sz);

    /* Unpoison the whole area first */
    if (__asan_unpoison_memory_region) {
        __asan_unpoison_memory_region(buf, _HF_INPUT_MAX_SIZE);
    }
    if (__msan_unpoison) {
        __msan_unpoison(buf, _HF_INPUT_MAX_SIZE);
    }

    __attribute__((weak)) extern void __asan_poison_memory_region(const void* addr, size_t sz);
    __attribute__((weak)) extern void __msan_poison(const void* addr, size_t sz);
    /* Poison the remainder of the buffer (beyond len) */
    if (__asan_poison_memory_region) {
        __asan_poison_memory_region(&buf[len], _HF_INPUT_MAX_SIZE - len);
    }
    if (__msan_poison) {
        __msan_poison(&buf[len], _HF_INPUT_MAX_SIZE - len);
    }
}

void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr) {
    if (!files_writeToFd(_HF_PERSISTENT_FD, &HFReadyTag, sizeof(HFReadyTag))) {
        LOG_F("writeToFd(size=%zu, readyTag) failed", sizeof(HFReadyTag));
    }

    uint64_t rcvLen;
    ssize_t  sz = files_readFromFd(_HF_PERSISTENT_FD, (uint8_t*)&rcvLen, sizeof(rcvLen));
    if (sz == -1) {
        PLOG_F("readFromFd(fd=%d, size=%zu) failed", _HF_PERSISTENT_FD, sizeof(rcvLen));
    }
    if (sz != sizeof(rcvLen)) {
        LOG_F("readFromFd(fd=%d, size=%zu) failed, received=%zd bytes", _HF_PERSISTENT_FD,
            sizeof(rcvLen), sz);
    }

    *buf_ptr = inputFile;
    *len_ptr = (size_t)rcvLen;

    fetchSanPoison(inputFile, rcvLen);

    if (lseek(_HF_INPUT_FD, (off_t)0, SEEK_SET) == -1) {
        PLOG_W("lseek(_HF_INPUT_FD=%d, 0)", _HF_INPUT_FD);
    }
}

bool fetchIsInputAvailable(void) {
    LOG_D("Current module: %s", LIBHFUZZ_module_fetch);
    return (inputFile != NULL);
}
