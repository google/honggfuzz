#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
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
#include "libcommon/util.h"

#define ARGS_MAX 4096
#define __XSTR(x) #x
#define _XSTR(x) __XSTR(x)

static char lhfuzzPath[PATH_MAX] = {0};

static bool isCXX = false;
static bool isGCC = false;

/* Embed libhfuzz.a inside this binary */
__asm__(
    "\n"
    "   .global lhfuzz_start\n"
    "   .global lhfuzz_end\n"
    "lhfuzz_start:\n"
    "   .incbin \"libhfuzz/libhfuzz.a\"\n"
    "lhfuzz_end:\n"
    "\n");

static bool useASAN() {
    if (getenv("HFUZZ_CC_ASAN") != NULL) {
        return true;
    }
    return false;
}

static bool useMSAN() {
    if (getenv("HFUZZ_CC_MSAN") != NULL) {
        return true;
    }
    return false;
}

static bool useUBSAN() {
    if (getenv("HFUZZ_CC_UBSAN") != NULL) {
        return true;
    }
    return false;
}

static bool isLDMode(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            return false;
        }
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

static int execCC(int argc, char** argv) {
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

    if (isCXX) {
        const char* cxx_path = getenv("HFUZZ_CXX_PATH");
        if (cxx_path != NULL) {
            execvp(cxx_path, argv);
            PLOG_E("execvp('%s')", cxx_path);
            return EXIT_FAILURE;
        }
    } else {
        const char* cc_path = getenv("HFUZZ_CC_PATH");
        if (cc_path != NULL) {
            execvp(cc_path, argv);
            PLOG_E("execvp('%s')", cc_path);
            return EXIT_FAILURE;
        }
    }

    if (isGCC) {
        if (isCXX) {
            execvp("g++", argv);
            execvp("gcc", argv);
        } else {
            execvp("gcc", argv);
        }
    } else {
        if (isCXX) {
            execvp("clang++-devel", argv);
            execvp("clang++-7.0", argv);
            execvp("clang++-6.0", argv);
            execvp("clang++-5.0", argv);
            execvp("clang++-4.0", argv);
            execvp("clang++", argv);
            execvp("clang", argv);
        } else {
            execvp("clang-devel", argv);
            execvp("clang-7.0", argv);
            execvp("clang-6.0", argv);
            execvp("clang-5.0", argv);
            execvp("clang-4.0", argv);
            execvp("clang", argv);
        }
    }

    PLOG_E("execvp('%s')", argv[0]);
    return EXIT_FAILURE;
}

/* It'll point back to the libhfuzz's source tree */
char* getIncPaths(void) {
#if !defined(_HFUZZ_INC_PATH)
#error "You need to define _HFUZZ_INC_PATH"
#endif

    static char path[PATH_MAX];
    snprintf(path, sizeof(path), "-I%s/includes/", _XSTR(_HFUZZ_INC_PATH));
    return path;
}

static void commonOpts(int* j, char** args) {
    args[(*j)++] = getIncPaths();
    if (isGCC) {
        /* That's the best gcc-6/7 currently offers */
        args[(*j)++] = "-fsanitize-coverage=trace-pc";
    } else {
        args[(*j)++] = "-Wno-unused-command-line-argument";
        args[(*j)++] = "-fsanitize-coverage=trace-pc-guard,trace-cmp,indirect-calls";
        args[(*j)++] = "-mllvm";
        args[(*j)++] = "-sanitizer-coverage-prune-blocks=0";
        args[(*j)++] = "-mllvm";
        args[(*j)++] = "-sanitizer-coverage-level=3";
    }

    /*
     * Make the execution flow more explicit, allowing for more code blocks
     * (and better code coverage estimates)
     */
    args[(*j)++] = "-fno-inline";
    args[(*j)++] = "-fno-builtin";
    args[(*j)++] = "-fno-omit-frame-pointer";
    args[(*j)++] = "-D__NO_STRING_INLINES";

    if (getenv("HFUZZ_FORCE_M32")) {
        args[(*j)++] = "-m32";
    }
}

static bool getLibHfuzz(void) {
    const char* lhfuzzEnvLoc = getenv("HFUZZ_LHFUZZ_PATH");
    if (lhfuzzEnvLoc) {
        snprintf(lhfuzzPath, sizeof(lhfuzzPath), "%s", lhfuzzEnvLoc);
        return true;
    }

    extern uint8_t lhfuzz_start __asm__("lhfuzz_start");
    extern uint8_t lhfuzz_end __asm__("lhfuzz_end");
    ptrdiff_t len = (uintptr_t)&lhfuzz_end - (uintptr_t)&lhfuzz_start;
    if (lhfuzzPath[0] == 0) {
        uint64_t crc64 = util_CRC64(&lhfuzz_start, len);
        snprintf(
            lhfuzzPath, sizeof(lhfuzzPath), "/tmp/libhfuzz.%d.%" PRIx64 ".a", geteuid(), crc64);
    }

    /* Does the library exist, belongs to the user and is of the expected size */
    struct stat st;
    if (stat(lhfuzzPath, &st) != -1) {
        if (st.st_size == len && st.st_uid == geteuid()) {
            return true;
        }
    }

    /* If not, provide it with atomic rename() */
    char template[] = "/tmp/libhfuzz.a.XXXXXX";
    int fd = mkostemp(template, O_CLOEXEC);
    if (fd == -1) {
        PLOG_E("mkostemp('%s')", template);
        return false;
    }
    defer { close(fd); };

    bool ret = files_writeToFd(fd, &lhfuzz_start, len);
    if (!ret) {
        PLOG_E("Couldn't write to '%s'", template);
        return false;
    }

    if (rename(template, lhfuzzPath) == -1) {
        PLOG_E("Couldn't rename('%s', '%s')", template, lhfuzzPath);
        unlink(template);
        return false;
    }

    return true;
}

static int ccMode(int argc, char** argv) {
    char* args[ARGS_MAX];

    int j = 0;
    if (isCXX) {
        args[j++] = "c++";
    } else {
        args[j++] = "cc";
    }
    commonOpts(&j, args);

    for (int i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }

    return execCC(j, args);
}

static int ldMode(int argc, char** argv) {
    if (!getLibHfuzz()) {
        return EXIT_FAILURE;
    }

    char* args[ARGS_MAX];

    int j = 0;
    if (isCXX) {
        args[j++] = "c++";
    } else {
        args[j++] = "cc";
    }

    /* Intercept common *cmp functions */
    args[j++] = "-Wl,--wrap=strcmp";
    args[j++] = "-Wl,--wrap=strcasecmp";
    args[j++] = "-Wl,--wrap=strncmp";
    args[j++] = "-Wl,--wrap=strncasecmp";
    args[j++] = "-Wl,--wrap=strstr";
    args[j++] = "-Wl,--wrap=strcasestr";
    args[j++] = "-Wl,--wrap=memcmp";
    args[j++] = "-Wl,--wrap=bcmp";
    args[j++] = "-Wl,--wrap=memmem";
    /* Apache's httpd mem/str cmp functions */
    args[j++] = "-Wl,--wrap=ap_cstr_casecmp";
    args[j++] = "-Wl,--wrap=ap_cstr_casecmpn";
    args[j++] = "-Wl,--wrap=ap_strcasestr";
    args[j++] = "-Wl,--wrap=apr_cstr_casecmp";
    args[j++] = "-Wl,--wrap=apr_cstr_casecmpn";
    /* Frequently used time-constant *SSL functions */
    args[j++] = "-Wl,--wrap=CRYPTO_memcmp";
    args[j++] = "-Wl,--wrap=OPENSSL_memcmp";
    args[j++] = "-Wl,--wrap=OPENSSL_strcasecmp";
    args[j++] = "-Wl,--wrap=OPENSSL_strncasecmp";
    /* Frequently used libXML2 functions */
    args[j++] = "-Wl,--wrap=xmlStrncmp";
    args[j++] = "-Wl,--wrap=xmlStrcmp";
    args[j++] = "-Wl,--wrap=xmlStrEqual";
    args[j++] = "-Wl,--wrap=xmlStrcasecmp";
    args[j++] = "-Wl,--wrap=xmlStrncasecmp";
    args[j++] = "-Wl,--wrap=xmlStrstr";
    args[j++] = "-Wl,--wrap=xmlStrcasestr";

    commonOpts(&j, args);

    for (int i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }

    args[j++] = lhfuzzPath;
    args[j++] = "-lpthread";

    return execCC(j, args);
}

int main(int argc, char** argv) {
    if (strstr(basename(util_StrDup(argv[0])), "++") != NULL) {
        isCXX = true;
    }
    if (strstr(basename(util_StrDup(argv[0])), "-gcc") != NULL) {
        isGCC = true;
    }
    if (strstr(basename(util_StrDup(argv[0])), "-g++") != NULL) {
        isGCC = true;
    }
    if (argc <= 1) {
        LOG_I("'%s': No arguments provided", argv[0]);
        return execCC(argc, argv);
    }
    if (argc > (ARGS_MAX - 128)) {
        LOG_F("'%s': Too many positional arguments: %d", argv[0], argc);
        return EXIT_FAILURE;
    }

    if (isLDMode(argc, argv)) {
        return ldMode(argc, argv);
    }
    return ccMode(argc, argv);
}
