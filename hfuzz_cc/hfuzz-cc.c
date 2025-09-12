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
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#define ARGS_MAX 4096

static bool isCXX                     = false;
static bool isGCC                     = false;
static bool usePCGuard                = true;
static bool hasCmdLineFSanitizeFuzzer = false;

/* Embed libhf/.a inside this binary */
__asm__("\n"
#if !defined(_HF_ARCH_DARWIN) && !defined(__APPLE__)
        "   .section .rodata\n"
#endif /* _HF_ARCH_DARWIN */
        "   .global lhfuzz_start\n"
        "   .global lhfuzz_end\n"
        "lhfuzz_start:\n"
        "   .incbin \"libhfuzz/libhfuzz.a\"\n"
        "lhfuzz_end:\n"
        "\n"
        "   .global lhfnetdriver_start\n"
        "   .global lhfnetdriver_end\n"
        "lhfnetdriver_start:\n"
        "   .incbin \"libhfnetdriver/libhfnetdriver.a\"\n"
        "lhfnetdriver_end:\n"
        "\n"
        "   .global lhfcommon_start\n"
        "   .global lhfcommon_end\n"
        "lhfcommon_start:\n"
        "   .incbin \"libhfcommon/libhfcommon.a\"\n"
        "lhfcommon_end:\n"
        "\n");

static const char* _basename(const char* path) {
    static __thread char fname[PATH_MAX];
    /* basename() can modify the argument (sic!) */
    snprintf(fname, sizeof(fname), "%s", path);
    return basename(fname);
}

static bool useASAN() {
    if (getenv("HFUZZ_CC_ASAN")) {
        return true;
    }
    return false;
}

static bool useMSAN() {
    if (getenv("HFUZZ_CC_MSAN")) {
        return true;
    }
    return false;
}

static bool useUBSAN() {
    if (getenv("HFUZZ_CC_UBSAN")) {
        return true;
    }
    return false;
}

static bool useM32() {
    if (getenv("HFUZZ_FORCE_M32")) {
        return true;
    }
    return false;
}

static bool useBelowGCC8() {
    if (getenv("HFUZZ_CC_USE_GCC_BELOW_8")) {
        return true;
    }
    return false;
}

static bool isVersionMode(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            return true;
        }
        if (strcmp(argv[i], "--target-help") == 0) {
            return true;
        }
        if (strcmp(argv[i], "--help") == 0) {
            return true;
        }
    }
    return false;
}

static bool isLDMode(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            return false;
        }
        if (strcmp(argv[i], "--target-help") == 0) {
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

static bool isExecutableBuild(int argc, char** argv) {
    bool  shared_flag     = false;
    char* output_filename = NULL;

    for (int i = 0; i < argc; i++) {
        // Check for Linux shared or macOS dynamic library flags.
        if (strcmp(argv[i], "-shared") == 0 || strcmp(argv[i], "--shared") == 0 ||
            strcmp(argv[i], "-dynamiclib") == 0) {
            shared_flag = true;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_filename = argv[i + 1];
        }
    }

    if (shared_flag) {
        return false;
    }

    if (output_filename != NULL) {
        const char* ext = strrchr(output_filename, '.');
        if (ext != NULL && (strcmp(ext, ".so") == 0 || strcmp(ext, ".dylib") == 0)) {
            return false;
        }
    }

    return true;
}

static bool hasFSanitizeFuzzer(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (util_strStartsWith(argv[i], "-fsanitize=") && strstr(argv[i], "fuzzer")) {
            return true;
        }
    }
    return false;
}

static int hf_execvp(const char* file, char** argv) {
    argv[0] = (char*)file;
    return execvp(file, argv);
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
        argv[argc++] = "-fno-sanitize-recover=undefined";
    }
    argv[argc] = NULL;

    if (isCXX) {
        const char* cxx_path = getenv("HFUZZ_CXX_PATH");
        if (cxx_path != NULL) {
            hf_execvp(cxx_path, argv);
            PLOG_E("execvp('%s')", cxx_path);
            return EXIT_FAILURE;
        }
    } else {
        const char* cc_path = getenv("HFUZZ_CC_PATH");
        if (cc_path != NULL) {
            hf_execvp(cc_path, argv);
            PLOG_E("execvp('%s')", cc_path);
            return EXIT_FAILURE;
        }
    }

    if (isGCC) {
        if (isCXX) {
            hf_execvp("g++", argv);
            hf_execvp("gcc", argv);
        } else {
            hf_execvp("gcc", argv);
        }
    } else {
        if (isCXX) {
            /* Try the default one, then the newest ones (hopefully) in order */
            hf_execvp("clang++", argv);
            hf_execvp("clang++-22.0", argv);
            hf_execvp("clang++-22", argv);
            hf_execvp("clang++-21.0", argv);
            hf_execvp("clang++-21", argv);
            hf_execvp("clang++-20.0", argv);
            hf_execvp("clang++-20", argv);
            hf_execvp("clang++-19.0", argv);
            hf_execvp("clang++-19", argv);
            hf_execvp("clang++-18.0", argv);
            hf_execvp("clang++-18", argv);
            hf_execvp("clang++-17.0", argv);
            hf_execvp("clang++-17", argv);
            hf_execvp("clang++-16.0", argv);
            hf_execvp("clang++-16", argv);
            hf_execvp("clang++-15.0", argv);
            hf_execvp("clang++-15", argv);
            hf_execvp("clang++-14.0", argv);
            hf_execvp("clang++-14", argv);
            hf_execvp("clang++-13.0", argv);
            hf_execvp("clang++-13", argv);
            hf_execvp("clang++-12.0", argv);
            hf_execvp("clang++-12", argv);
            hf_execvp("clang++12", argv);
            hf_execvp("clang++-11.0", argv);
            hf_execvp("clang++-11", argv);
            hf_execvp("clang++11", argv);
            hf_execvp("clang++-10.0", argv);
            hf_execvp("clang++-10", argv);
            hf_execvp("clang++10", argv);
            hf_execvp("clang++-9.0", argv);
            hf_execvp("clang++-9", argv);
            hf_execvp("clang++9", argv);
            hf_execvp("clang++-8.0", argv);
            hf_execvp("clang++-8", argv);
            hf_execvp("clang++8", argv);
            hf_execvp("clang++-7.0", argv);
            hf_execvp("clang++-7", argv);
            hf_execvp("clang++7", argv);
            hf_execvp("clang", argv);
            hf_execvp("clang++", argv);
        } else {
            /* Try the default one, then the newest ones (hopefully) in order */
            hf_execvp("clang", argv);
            hf_execvp("clang-22.0", argv);
            hf_execvp("clang-22", argv);
            hf_execvp("clang-21.0", argv);
            hf_execvp("clang-21", argv);
            hf_execvp("clang-20.0", argv);
            hf_execvp("clang-20", argv);
            hf_execvp("clang-19.0", argv);
            hf_execvp("clang-19", argv);
            hf_execvp("clang-18.0", argv);
            hf_execvp("clang-18", argv);
            hf_execvp("clang-17.0", argv);
            hf_execvp("clang-17", argv);
            hf_execvp("clang-16.0", argv);
            hf_execvp("clang-16", argv);
            hf_execvp("clang-15.0", argv);
            hf_execvp("clang-15", argv);
            hf_execvp("clang-14.0", argv);
            hf_execvp("clang-14", argv);
            hf_execvp("clang-13.0", argv);
            hf_execvp("clang-13", argv);
            hf_execvp("clang-12.0", argv);
            hf_execvp("clang-12", argv);
            hf_execvp("clang12", argv);
            hf_execvp("clang-11.0", argv);
            hf_execvp("clang-11", argv);
            hf_execvp("clang11", argv);
            hf_execvp("clang-10.0", argv);
            hf_execvp("clang-10", argv);
            hf_execvp("clang10", argv);
            hf_execvp("clang-9.0", argv);
            hf_execvp("clang-9", argv);
            hf_execvp("clang9", argv);
            hf_execvp("clang-8.0", argv);
            hf_execvp("clang-8", argv);
            hf_execvp("clang8", argv);
            hf_execvp("clang-7.0", argv);
            hf_execvp("clang-7", argv);
            hf_execvp("clang7", argv);
            hf_execvp("clang", argv);
        }
    }

    PLOG_F("execvp('%s')", argv[0]);
    return EXIT_FAILURE;
}

/* It'll point back to the libhfuzz's source tree */
char* getIncPaths(void) {
#if !defined(_HFUZZ_INC_PATH)
#error                                                                                             \
    "You need to define _HFUZZ_INC_PATH to a directory with the directory called 'includes', containing honggfuzz's lib* includes. Typically it'd be the build/sources dir"
#endif

    static char path[PATH_MAX];
    snprintf(path, sizeof(path), "-I%s/includes/", HF_XSTR(_HFUZZ_INC_PATH));
    return path;
}

static bool getLibPath(
    const char* name, const char* env, const uint8_t* start, const uint8_t* end, char* path) {
    const char* libEnvLoc = getenv(env);
    if (libEnvLoc) {
        snprintf(path, PATH_MAX, "%s", libEnvLoc);
        return true;
    }

    ptrdiff_t len   = (uintptr_t)end - (uintptr_t)start;
    uint64_t  crc64 = util_CRC64(start, len);
    snprintf(path, PATH_MAX, "/tmp/%s.%d.%" PRIx64 ".a", name, geteuid(), crc64);

    /* Does the library exist, belongs to the user, and is of expected size? */
    struct stat st;
    if (stat(path, &st) != -1 && st.st_size == len && st.st_uid == geteuid()) {
        return true;
    }

    /* If not, create it with atomic rename() */
    char template[] = "/tmp/lib.honggfuzz.a.XXXXXX";
    int fd          = TEMP_FAILURE_RETRY(mkostemp(template, O_CLOEXEC));
    if (fd == -1) {
        PLOG_E("mkostemp('%s')", template);
        return false;
    }
    defer {
        close(fd);
    };

    if (!files_writeToFd(fd, start, len)) {
        PLOG_E("Couldn't write to '%s'", template);
        unlink(template);
        return false;
    }

    if (TEMP_FAILURE_RETRY(rename(template, path)) == -1) {
        PLOG_E("Couldn't rename('%s', '%s')", template, path);
        unlink(template);
        return false;
    }

    return true;
}

static char* getLibHFuzzPath() {
    extern uint8_t lhfuzz_start __asm__("lhfuzz_start");
    extern uint8_t lhfuzz_end __asm__("lhfuzz_end");

    static char path[PATH_MAX] = {};
    if (path[0]) {
        return path;
    }
    if (!getLibPath("libhfuzz", "HFUZZ_LHFUZZ_PATH", &lhfuzz_start, &lhfuzz_end, path)) {
        LOG_F("Couldn't create the temporary libhfuzz.a");
    }
    return path;
}

static char* getLibHFNetDriverPath() {
    extern uint8_t lhfnetdriver_start __asm__("lhfnetdriver_start");
    extern uint8_t lhfnetdriver_end __asm__("lhfnetdriver_end");

    static char path[PATH_MAX] = {};
    if (path[0]) {
        return path;
    }
    if (!getLibPath("libhfnetdriver", "HFUZZ_LHFNETDRIVER_PATH", &lhfnetdriver_start,
            &lhfnetdriver_end, path)) {
        LOG_F("Couldn't create the temporary libhfnetdriver.a");
    }
    return path;
}

static char* getLibHFCommonPath() {
    extern uint8_t lhfcommon_start __asm__("lhfcommon_start");
    extern uint8_t lhfcommon_end __asm__("lhfcommon_end");

    static char path[PATH_MAX] = {};
    if (path[0]) {
        return path;
    }
    if (!getLibPath(
            "libhfcommon", "HFUZZ_LHFCOMMON_PATH", &lhfcommon_start, &lhfcommon_end, path)) {
        LOG_F("Couldn't create the temporary libhcommon.a");
    }
    return path;
}

static void commonPreOpts(int* j, char** args) {
    args[(*j)++] = getIncPaths();

    if (!isGCC) {
        args[(*j)++] = "-Wno-unused-command-line-argument";
    }

    /*
     * Make the execution flow more explicit, allowing for more code blocks
     * (and better code coverage estimates)
     */
    if (isGCC) {
        args[(*j)++] = "-finline-limit=1000";
    } else {
        args[(*j)++] = "-mllvm";
        args[(*j)++] = "-inline-threshold=1000";
    }

    args[(*j)++] = "-fno-builtin";
    args[(*j)++] = "-fno-omit-frame-pointer";
    args[(*j)++] = "-D__NO_STRING_INLINES";

    /* Make it possible to use the libhfnetdriver */
    args[(*j)++] = "-DHFND_FUZZING_ENTRY_FUNCTION_CXX(x,y)="
                   "extern const char* LIBHFNETDRIVER_module_netdriver;"
                   "const char** LIBHFNETDRIVER_tmp1 = &LIBHFNETDRIVER_module_netdriver;"
                   "extern \"C\" int HonggfuzzNetDriver_main(x,y);"
                   "int HonggfuzzNetDriver_main(x,y)";
    args[(*j)++] = "-DHFND_FUZZING_ENTRY_FUNCTION(x,y)="
                   "extern const char* LIBHFNETDRIVER_module_netdriver;"
                   "const char** LIBHFNETDRIVER_tmp1 = &LIBHFNETDRIVER_module_netdriver;"
                   "int HonggfuzzNetDriver_main(x,y);"
                   "int HonggfuzzNetDriver_main(x,y)";

    if (useM32()) {
        args[(*j)++] = "-m32";
    }
}

static void commonPostOpts(int* j, char** args) {
    if (isGCC) {
        if (useBelowGCC8()) {
            /* trace-pc is the best that gcc-6/7 currently offers */
            args[(*j)++] = "-fsanitize-coverage=trace-pc";
        } else {
            /* gcc-8+ offers trace-cmp as well, but it's not that widely used yet */
            args[(*j)++] = "-fsanitize-coverage=trace-pc,trace-cmp";
        }
    } else {
        if (usePCGuard) {
            if (hasCmdLineFSanitizeFuzzer) {
                args[(*j)++] = "-fno-sanitize=fuzzer";
                args[(*j)++] = "-fno-sanitize=fuzzer-no-link";
            }
            args[(*j)++] = "-fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls";
        } else {
            args[(*j)++] = "-fno-sanitize-coverage=trace-pc-guard";
            args[(*j)++] = "-fno-sanitize=fuzzer";
            args[(*j)++] = "-fsanitize=fuzzer-no-link";
            args[(*j)++] = "-fsanitize-coverage=trace-cmp,trace-div,indirect-calls";
        }
    }
}

static int ccMode(int argc, char** argv) {
    char* args[ARGS_MAX];

    int j = 0;
    if (isCXX) {
        args[j++] = "c++";
    } else {
        args[j++] = "cc";
    }

    commonPreOpts(&j, args);

    for (int i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }

    commonPostOpts(&j, args);

    return execCC(j, args);
}

static int ldMode(int argc, char** argv) {
    char* args[ARGS_MAX];

    int j = 0;
    if (isCXX) {
        args[j++] = "c++";
    } else {
        args[j++] = "cc";
    }

    commonPreOpts(&j, args);

/* MacOS X linker doesn't like those */
#ifndef _HF_ARCH_DARWIN
    /* Intercept common *cmp functions */
    args[j++] = "-Wl,--wrap=strcmp";
    args[j++] = "-Wl,--wrap=strcasecmp";
    args[j++] = "-Wl,--wrap=stricmp";
    args[j++] = "-Wl,--wrap=strncmp";
    args[j++] = "-Wl,--wrap=strncasecmp";
    args[j++] = "-Wl,--wrap=strnicmp";
    args[j++] = "-Wl,--wrap=strstr";
    args[j++] = "-Wl,--wrap=strcasestr";
    args[j++] = "-Wl,--wrap=memcmp";
    args[j++] = "-Wl,--wrap=bcmp";
    args[j++] = "-Wl,--wrap=memmem";
    args[j++] = "-Wl,--wrap=strcpy";
    args[j++] = "-Wl,--wrap=strlcpy";
    /* Apache httpd */
    args[j++] = "-Wl,--wrap=ap_cstr_casecmp";
    args[j++] = "-Wl,--wrap=ap_cstr_casecmpn";
    args[j++] = "-Wl,--wrap=ap_strcasestr";
    args[j++] = "-Wl,--wrap=apr_cstr_casecmp";
    args[j++] = "-Wl,--wrap=apr_cstr_casecmpn";
    /* *SSL */
    args[j++] = "-Wl,--wrap=CRYPTO_memcmp";
    args[j++] = "-Wl,--wrap=OPENSSL_memcmp";
    args[j++] = "-Wl,--wrap=OPENSSL_strcasecmp";
    args[j++] = "-Wl,--wrap=OPENSSL_strncasecmp";
    args[j++] = "-Wl,--wrap=memcmpct";
    /* libXML2 */
    args[j++] = "-Wl,--wrap=xmlStrncmp";
    args[j++] = "-Wl,--wrap=xmlStrcmp";
    args[j++] = "-Wl,--wrap=xmlStrEqual";
    args[j++] = "-Wl,--wrap=xmlStrcasecmp";
    args[j++] = "-Wl,--wrap=xmlStrncasecmp";
    args[j++] = "-Wl,--wrap=xmlStrstr";
    args[j++] = "-Wl,--wrap=xmlStrcasestr";
    /* Samba */
    args[j++] = "-Wl,--wrap=memcmp_const_time";
    args[j++] = "-Wl,--wrap=strcsequal";
    /* LittleCMS */
    args[j++] = "-Wl,--wrap=cmsstrcasecmp";
    /* GLib */
    args[j++] = "-Wl,--wrap=g_strcmp0";
    args[j++] = "-Wl,--wrap=g_strcasecmp";
    args[j++] = "-Wl,--wrap=g_strncasecmp";
    args[j++] = "-Wl,--wrap=g_strstr_len";
    args[j++] = "-Wl,--wrap=g_ascii_strcasecmp";
    args[j++] = "-Wl,--wrap=g_ascii_strncasecmp";
    args[j++] = "-Wl,--wrap=g_str_has_prefix";
    args[j++] = "-Wl,--wrap=g_str_has_suffix";
    /* CUrl */
    args[j++] = "-Wl,--wrap=Curl_strcasecompare";
    args[j++] = "-Wl,--wrap=curl_strequal";
    args[j++] = "-Wl,--wrap=Curl_safe_strcasecompare";
    args[j++] = "-Wl,--wrap=Curl_strncasecompare";
    args[j++] = "-Wl,--wrap=curl_strnequal";
    /* SQLite3 */
    args[j++] = "-Wl,--wrap=sqlite3_stricmp";
    args[j++] = "-Wl,--wrap=sqlite3_strnicmp";
    args[j++] = "-Wl,--wrap=sqlite3StrICmp";
#endif /* _HF_ARCH_DARWIN */

    /* Pull modules defining the following symbols (if they exist) */
#ifdef _HF_ARCH_DARWIN
    args[j++] = "-Wl,-U,_HonggfuzzNetDriver_main";
    args[j++] = "-Wl,-U,_LIBHFUZZ_module_instrument";
    args[j++] = "-Wl,-U,_LIBHFUZZ_module_memorycmp";
#else  /* _HF_ARCH_DARWIN */
    args[j++] = "-Wl,-u,HonggfuzzNetDriver_main";
    args[j++] = "-Wl,-u,LIBHFUZZ_module_instrument";
    args[j++] = "-Wl,-u,LIBHFUZZ_module_memorycmp";
#endif /* _HF_ARCH_DARWIN */

    for (int i = 1; i < argc; i++) {
        args[j++] = argv[i];
    }

    /*
     * Disable enforcement of the programming language, in case it had been enabled explicitly,
     * e.g. via -xc
     */
    args[j++] = "-xnone";

    /* Reference standard honggfuzz libraries first (libhfuzz, libhfcommon and libhfnetdriver) */
    args[j++] = getLibHFNetDriverPath();

    /* Ensure to link libhfuzz to the fuzz test executable*/
    if (isExecutableBuild(argc, argv)) {
#if defined(_HF_ARCH_DARWIN)
        args[j++] = "-Wl,-force_load";
#else
        args[j++] = "-Wl,--whole-archive";
#endif
    }

    args[j++] = getLibHFuzzPath();

#if !defined(_HF_ARCH_DARWIN)
    if (isExecutableBuild(argc, argv)) {
        args[j++] = "-Wl,--no-whole-archive";
    }
#endif /* !defined(_HF_ARCH_DARWIN) */

    args[j++] = getLibHFCommonPath();

    /* Needed by libhfcommon */
    args[j++] = "-pthread";
#if !defined(__NetBSD__)
    args[j++] = "-ldl";
#endif /* !defined(__NetBSD__) */
#if !defined(_HF_ARCH_DARWIN) && !defined(__OpenBSD__)
    args[j++] = "-lrt";
#endif /* !defined(_HF_ARCH_DARWIN) && !defined(__OpenBSD__) */
#if defined(__ANDROID__) || defined(__m68k__)
    args[j++] = "-latomic";
#endif

    commonPostOpts(&j, args);

    return execCC(j, args);
}

static bool baseNameContains(const char* path, const char* str) {
    if (strstr(_basename(path), str)) {
        return true;
    }
    return false;
}

int main(int argc, char** argv) {
    if (baseNameContains(argv[0], "++")) {
        isCXX = true;
    }
    if (baseNameContains(argv[0], "-gcc")) {
        isGCC = true;
    }
    if (baseNameContains(argv[0], "-g++")) {
        isGCC = true;
    }
    if (baseNameContains(argv[0], "-pcguard-")) {
        usePCGuard = true;
    }
    if (baseNameContains(argv[0], "-8bitcnt-")) {
        usePCGuard = false;
    }
    hasCmdLineFSanitizeFuzzer = hasFSanitizeFuzzer(argc, argv);

    if (argc <= 1) {
        return execCC(argc, argv);
    }
    if (isVersionMode(argc, argv)) {
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
