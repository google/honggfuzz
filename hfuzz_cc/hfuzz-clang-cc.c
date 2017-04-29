#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ARGS_MAX 4096
#define __XSTR(x) #x
#define _XSTR(x) __XSTR(x)
#define CLANG_BIN "clang"
#define LHFUZZ_A_PATH "/tmp/libhfuzz.a"

__asm__("\n"
        "	.global lhfuzz_start\n"
        "	.global lhfuzz_end\n"
        "lhfuzz_start:\n" "	.incbin \"libhfuzz/libhfuzz.a\"\n" "lhfuzz_end:\n" "\n");

static char *getClangCC()
{
    const char *cc_path = getenv("HFUZZ_CC_PATH");
    if (cc_path != NULL) {
        return (char *)cc_path;
    }
    return (char *)CLANG_BIN;
}

static bool useASAN()
{
    if (getenv("HFUZZ_CC_ASAN") != NULL) {
        return true;
    }
    return false;
}

static bool useMSAN()
{
    if (getenv("HFUZZ_CC_MSAN") != NULL) {
        return true;
    }
    return false;
}

static bool useUBSAN()
{
    if (getenv("HFUZZ_CC_UBSAN") != NULL) {
        return true;
    }
    return false;
}

static bool isLDMode(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            return false;
        }
        if (strcmp(argv[i], "-E") == 0) {
            return false;
        }
        if (strcmp(argv[i], "-S") == 0) {
            return false;
        }
    }
    return true;
}

static int execCC(int argc, char **argv)
{
    if (useASAN()) {
        argv[argc++] = "-fsanitize=address";
    }
    if (useMSAN()) {
        argv[argc++] = "-fsanitize=memory";
    }
    if (useUBSAN()) {
        argv[argc++] = "-fsanitize=undefined";
    }

    argv[argc] = NULL;
    execvp(argv[0], argv);
    perror("execv");
    return EXIT_FAILURE;
}

static int ccMode(int argc, char **argv)
{
    char *args[4096];

    int j = 0;
    args[j++] = getClangCC();
    args[j++] = "-fsanitize-coverage=trace-pc-guard,trace-cmp,indirect-calls";
    args[j++] = "-funroll-loops";
    args[j++] = "-fno-inline";
    args[j++] = "-fno-builtin";

    for (int i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }

    return execCC(j, args);
}

static bool writeToFd(int fd, const uint8_t * buf, size_t len)
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

static bool getLibHfuzz(void)
{
    extern uint8_t lhfuzz_start;
    extern uint8_t lhfuzz_end;

    ptrdiff_t len = (uintptr_t) & lhfuzz_end - (uintptr_t) & lhfuzz_start;

    /* Does the library exist and is of the expected size */
    struct stat st;
    if (stat(LHFUZZ_A_PATH, &st) != -1) {
        if (st.st_size == len) {
            return true;
        }
    }

    char template[] = "/tmp/libhfuzz.a.XXXXXX";
    int fd = mkostemp(template, O_CLOEXEC);
    if (fd == -1) {
        perror("mkostemp('/tmp/libhfuzz.a.XXXXXX')");
        return false;
    }

    bool ret = writeToFd(fd, &lhfuzz_start, len);
    close(fd);
    if (!ret) {
        fprintf(stderr, "Couldn't write to '%s'", template);
        close(fd);
        return false;
    }

    if (rename(template, LHFUZZ_A_PATH) == -1) {
        unlink(template);
        fprintf(stderr, "Couldn't rename('%s', '%s')", template, LHFUZZ_A_PATH);
        return false;
    }

    return true;
}

static int ldMode(int argc, char **argv)
{
    if (!getLibHfuzz()) {
        return EXIT_FAILURE;
    }

    char *args[4096];

    int j = 0;
    args[j++] = getClangCC();
    args[j++] = "-Wl,--whole-archive";
    args[j++] = LHFUZZ_A_PATH;
    args[j++] = "-Wl,--no-whole-archive";
    args[j++] = "-fsanitize-coverage=trace-pc-guard,trace-cmp,indirect-calls";
    args[j++] = "-funroll-loops";
    args[j++] = "-fno-inline";
    args[j++] = "-fno-builtin";

    int i;
    for (i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }
    args[j++] = LHFUZZ_A_PATH;

    return execCC(j, args);
}

int main(int argc, char **argv)
{
    if (argc > (ARGS_MAX - 4)) {
        fprintf(stderr, "Too many positional arguments\n");
        return EXIT_FAILURE;
    }

    if (isLDMode(argc, argv)) {
        return ldMode(argc, argv);
    }
    return ccMode(argc, argv);
}
