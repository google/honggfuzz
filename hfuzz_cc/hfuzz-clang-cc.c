#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(_HF_BUILD_DIR)
#error "_HF_BUILD_DIR not defined"
#endif

#define ARGS_MAX 4096
#define __XSTR(x) #x
#define _XSTR(x) __XSTR(x)
#define CLANG_BIN "clang"

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

static bool containsDashC(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            return true;
        }
    }
    return false;
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

static int ldMode(int argc, char **argv)
{
    char *args[4096];

    char lHFuzzPath[PATH_MAX];
    snprintf(lHFuzzPath, sizeof(lHFuzzPath), "%s/libhfuzz/libhfuzz.a", _XSTR(_HF_BUILD_DIR));

    int j = 0;
    args[j++] = getClangCC();
    args[j++] = "-Wl,--whole-archive";
    args[j++] = lHFuzzPath;
    args[j++] = "-Wl,--no-whole-archive";
    args[j++] = "-fsanitize-coverage=trace-pc-guard,trace-cmp,indirect-calls";
    args[j++] = "-funroll-loops";
    args[j++] = "-fno-inline";
    args[j++] = "-fno-builtin";

    int i;
    for (i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }
    args[j++] = lHFuzzPath;

    return execCC(j, args);
}

int main(int argc, char **argv)
{
    if (argc > (ARGS_MAX - 4)) {
        fprintf(stderr, "Too many positional arguments\n");
        return EXIT_FAILURE;
    }

    if (containsDashC(argc, argv)) {
        return ccMode(argc, argv);
    }
    return ldMode(argc, argv);
}
