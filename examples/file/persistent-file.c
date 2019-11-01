#ifdef __cplusplus
extern "C" {
#endif

#include <fcntl.h>
#include <libhfuzz/libhfuzz.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "magic.h"

/*
 * Compile as:
 * honggfuzz/hfuzz_cc/hfuzz-clang -I ./file-5.37/ honggfuzz/examples/file/persistent-file.c -o
 * persistent-file ./file-5.37/src/.libs/libmagic.a -lz
 */

magic_t ms = NULL;
int LLVMFuzzerInitialize(int* argc, char*** argv) {
    ms = magic_open(MAGIC_CONTINUE | MAGIC_CHECK | MAGIC_COMPRESS);
    if (ms == NULL) {
        fprintf(stderr, "magic_open() failed\n");
        abort();
        return 1;
    }
    const char* magic_file = "/usr/share/misc/magic.mgc";
    if (*argc > 1) {
        magic_file = (*argv)[1];
    }
    if (magic_load(ms, magic_file) == -1) {
        fprintf(stderr, "magic_load() failed: %s\n", magic_error(ms));
        magic_close(ms);
        abort();
        return 1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    const char* type = magic_buffer(ms, buf, len);
    if (type == NULL) {
        printf("Type: [unknown]: %s\n", magic_error(ms));
    } else {
        printf("Type: '%s'\n", type);
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
