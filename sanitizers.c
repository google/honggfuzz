#include "sanitizers.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmdline.h"
#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

/*
 * Common sanitizer flags if --sanitizers is enabled
 */
#define kSAN_COMMON                                                                                \
    "symbolize=1:"                                                                                 \
    "detect_leaks=0:"                                                                              \
    "disable_coredump=0:"                                                                          \
    "detect_odr_violation=0:"                                                                      \
    "allocator_may_return_null=1:"                                                                 \
    "allow_user_segv_handler=0:"                                                                   \
    "handle_segv=2:"                                                                               \
    "handle_sigbus=2:"                                                                             \
    "handle_abort=2:"                                                                              \
    "handle_sigill=2:"                                                                             \
    "handle_sigfpe=2:"                                                                             \
    "abort_on_error=1"

/* --{ ASan }-- */
/*
 * Sanitizer specific flags (notice that if enabled 'abort_on_error' has priority
 * over exitcode')
 */
#define kASAN_OPTS kSAN_COMMON

/* --{ UBSan }-- */
#define kUBSAN_OPTS kSAN_COMMON

/* --{ MSan }-- */
#define kMSAN_OPTS kSAN_COMMON ":wrap_signals=0:print_stats=1"

/* --{ LSan }-- */
#define kLSAN_OPTS kSAN_COMMON

/* If no sanitzer support was requested, simply abort() on errors */
#define kSAN_REGULAR                                                                               \
    "symbolize=1:"                                                                                 \
    "detect_leaks=0:"                                                                              \
    "disable_coredump=0:"                                                                          \
    "detect_odr_violation=0:"                                                                      \
    "allocator_may_return_null=1:"                                                                 \
    "allow_user_segv_handler=1:"                                                                   \
    "handle_segv=0:"                                                                               \
    "handle_sigbus=0:"                                                                             \
    "handle_abort=0:"                                                                              \
    "handle_sigill=0:"                                                                             \
    "handle_sigfpe=0:"                                                                             \
    "abort_on_error=1"

static void sanitizers_AddFlag(honggfuzz_t* hfuzz, const char* env, const char* val) {
    if (getenv(env)) {
        LOG_W("The '%s' envar is already set. Not overriding it!", env);
        return;
    }

    char buf[4096] = {};
    if (hfuzz->sanitizer.enable) {
        snprintf(buf, sizeof(buf), "%s=%s:log_path=%s/%s", env, val, hfuzz->io.workDir, kLOGPREFIX);
    } else {
        snprintf(buf, sizeof(buf), "%s=%s:log_path=%s/%s", env, kSAN_REGULAR, hfuzz->io.workDir,
            kLOGPREFIX);
    }
    /*
     * It will make ASAN to start background thread to check RSS mem use, which
     * will prevent the NetDrvier from using unshare(CLONE_NEWNET), which cannot
     * be used in multi-threaded contexts
     */
    if (!hfuzz->exe.netDriver && hfuzz->exe.rssLimit) {
        util_ssnprintf(buf, sizeof(buf), ":soft_rss_limit_mb=%" PRId64, hfuzz->exe.rssLimit);
    }

    cmdlineAddEnv(hfuzz, buf);
    LOG_D("%s", buf);
}

bool sanitizers_Init(honggfuzz_t* hfuzz) {
    sanitizers_AddFlag(hfuzz, "ASAN_OPTIONS", kASAN_OPTS);
    sanitizers_AddFlag(hfuzz, "UBSAN_OPTIONS", kUBSAN_OPTS);
    sanitizers_AddFlag(hfuzz, "MSAN_OPTIONS", kMSAN_OPTS);
    sanitizers_AddFlag(hfuzz, "LSAN_OPTIONS", kLSAN_OPTS);

    return true;
}

/* Get numeric value of the /proc/<pid>/status "Tgid: <PID>" field */
static pid_t sanitizers_PidForTid(pid_t pid) {
    char status_path[PATH_MAX];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", (int)pid);
    FILE* f = fopen(status_path, "rb");
    if (UNLIKELY(!f)) {
        return pid;
    }
    defer {
        fclose(f);
    };
    char*  lineptr = NULL;
    size_t n       = 0;
    defer {
        free(lineptr);
    };

    while (getline(&lineptr, &n, f) > 0) {
        int retpid;
        if (sscanf(lineptr, "Tgid:%d", &retpid) == 1) {
            LOG_D("Tid %d has Pid %d", (int)pid, retpid);
            return (pid_t)retpid;
        }
    }
    return pid;
}

size_t sanitizers_parseReport(run_t* run, pid_t pid, funcs_t* funcs, uint64_t* pc,
    uint64_t* crashAddr, char description[HF_STR_LEN]) {
    char        crashReport[PATH_MAX];
    const char* crashReportCpy = crashReport;

    /* Under Linux the crash is seen in TID, but the sanitizer report is created for PID */
    pid = sanitizers_PidForTid(pid);
    snprintf(crashReport, sizeof(crashReport), "%s/%s.%d", run->global->io.workDir, kLOGPREFIX,
        (int)pid);

    FILE* fReport = fopen(crashReport, "rb");
    if (fReport == NULL) {
        PLOG_D("fopen('%s', 'rb')", crashReport);
        return 0;
    }
    defer {
        fclose(fReport);
        if (run->global->sanitizer.del_report) {
            unlink(crashReportCpy);
        }
    };

    bool         headerFound = false;
    bool         frameFound  = false;
    unsigned int frameIdx    = 0;

    char*  lineptr = NULL;
    size_t n       = 0;
    defer {
        free(lineptr);
    };
    for (;;) {
        if (getline(&lineptr, &n, fReport) == -1) {
            break;
        }

        /* First step is to identify header */
        if (!headerFound) {
            int reportpid = 0;
            if (sscanf(lineptr, "==%d==ERROR: ", &reportpid) != 1) {
                continue;
            }
            if (reportpid != pid) {
                LOG_W(
                    "SAN report found in '%s', but its PID:%d is different from the needed PID:%d",
                    crashReport, reportpid, (int)pid);
                break;
            }
            headerFound = true;
            sscanf(lineptr,
                "==%*d==ERROR: %*[^:]: %*[^ ] on address 0x%" PRIx64 " at pc 0x%" PRIx64, crashAddr,
                pc);
            sscanf(lineptr,
                "==%*d==ERROR: %*[^:]: %*[^ ] on %*s address 0x%" PRIx64 " (pc 0x%" PRIx64,
                crashAddr, pc);
            sscanf(lineptr, "==%*d==ERROR: %" HF_XSTR(HF_STR_LEN_MINUS_1) "[^\n]", description);
        } else {
            char* pLineLC = lineptr;
            /* Trim leading spaces */
            while (*pLineLC != '\0' && isspace((unsigned char)*pLineLC)) {
                ++pLineLC;
            }

            /* End separator for crash thread stack trace is an empty line */
            if ((*pLineLC == '\0') && (frameIdx != 0)) {
                break;
            }

            if (sscanf(pLineLC, "#%u", &frameIdx) != 1) {
                continue;
            }
            if (frameIdx >= _HF_MAX_FUNCS) {
                frameIdx = _HF_MAX_FUNCS - 1;
                break;
            }

            frameFound = true;
            snprintf(funcs[frameIdx].func, sizeof(funcs[frameIdx].func), "UNKNOWN");

            /*
             * Frames with demangled symbols and with debug info
             *     A::A(std::vector<std::__cxx11::basic_string<char, std::char_traits<char>,
             * std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char,
             * std::char_traits<char>, std::allocator<char> > > >) /home/fuzz/test/fork.cc:12:51
             */
            if (sscanf(pLineLC,
                    "#%*u 0x%p in %" HF_XSTR(_HF_FUNC_NAME_SZ_MINUS_1) "[^)]) %" HF_XSTR(
                        _HF_FUNC_NAME_SZ_MINUS_1) "[^:]:%zu",
                    &funcs[frameIdx].pc, funcs[frameIdx].func, funcs[frameIdx].file,
                    &funcs[frameIdx].line) == 4) {
                util_ssnprintf(funcs[frameIdx].func, sizeof(funcs[frameIdx].func), ")");
                continue;
            }

            /*
             * Frames with demangled symbols but w/o debug info
             *     #0 0x59d74e in printf_common(void*, char const*, __va_list_tag*)
             * (/home/smbd/smbd+0x59d74e)
             */
            if (sscanf(pLineLC, "#%*u 0x%p in %" HF_XSTR(_HF_FUNC_NAME_SZ_MINUS_1) "[^)]) (%[^)])",
                    &funcs[frameIdx].pc, funcs[frameIdx].func, funcs[frameIdx].module) == 3) {
                util_ssnprintf(funcs[frameIdx].func, sizeof(funcs[frameIdx].func), ")");
                continue;
            }
            /*
             * Frames with symbols but w/o debug info
             *     #0 0x7ffff59a3668 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x9668)
             */
            if (sscanf(pLineLC,
                    "#%*u 0x%p in %" HF_XSTR(_HF_FUNC_NAME_SZ_MINUS_1) "s%*[^(](%" HF_XSTR(
                        HF_STR_LEN_MINUS_1) "[^)]",
                    &funcs[frameIdx].pc, funcs[frameIdx].func, funcs[frameIdx].module) == 3) {
                continue;
            }
            /*
             * Frames with symbols and with debug info
             *     #0 0x1e94738 in smb2_signing_decrypt_pdu /home/test/signing.c:617:3
             */
            if (sscanf(pLineLC,
                    "#%*u 0x%p in %" HF_XSTR(_HF_FUNC_NAME_SZ_MINUS_1) "[^ ] %" HF_XSTR(
                        HF_STR_LEN_MINUS_1) "[^:\n]:%zu",
                    &funcs[frameIdx].pc, funcs[frameIdx].func, funcs[frameIdx].file,
                    &funcs[frameIdx].line) == 4) {
                continue;
            }
            /*
             * Frames w/o symbols
             *     #0 0x565584f4  (/mnt/z/test+0x34f4)
             */
            if (sscanf(pLineLC, "#%*u 0x%p%*[^(](%" HF_XSTR(HF_STR_LEN_MINUS_1) "[^)\n]",
                    &funcs[frameIdx].pc, funcs[frameIdx].module) == 2) {
                continue;
            }
            /*
             * Frames w/o symbols, but with debug info
             *     #0 0x7ffff57cf08f  /build/glibc-bBRi4l/.../erms.S:199
             */
            if (sscanf(pLineLC, "#%*u 0x%p  %" HF_XSTR(HF_STR_LEN_MINUS_1) "[^:]:%zu",
                    &funcs[frameIdx].pc, funcs[frameIdx].file, &funcs[frameIdx].line) == 3) {
                continue;
            }
        }
    }

    return (!frameFound) ? 0 : (frameIdx + 1);
}

/*
 * Size in characters required to store a string representation of a
 * register value (0xdeadbeef style))
 */
#define REGSIZEINCHAR (2 * sizeof(uint64_t) + 3)

uint64_t sanitizers_hashCallstack(run_t* run, funcs_t* funcs, size_t funcCnt, bool enableMasking) {
    size_t numFrames = 7;
    /*
     * If sanitizer fuzzing enabled increase number of major frames, since top 7-9 frames will be
     * occupied with sanitizer runtime library & libc symbols
     */
    if (run->global->sanitizer.enable) {
        numFrames = 14;
    }

    uint64_t hash = 0;
    for (size_t i = 0; i < funcCnt && i < numFrames; i++) {
        /*
         * Convert PC to char array to be compatible with hash function
         */
        char pcStr[REGSIZEINCHAR] = {0};
        snprintf(pcStr, REGSIZEINCHAR, "0x%016" PRIx64, (uint64_t)(long)funcs[i].pc);

        /*
         * Hash the last three nibbles
         */
        hash ^= util_hash(&pcStr[strlen(pcStr) - 3], 3);
    }

    /*
     * If only one frame, hash is not safe to be used for uniqueness. We mask it
     * here with a constant prefix, so analyzers can pick it up and create filenames
     * accordingly. 'enableMasking' is controlling masking for cases where it should
     * not be enabled (e.g. fuzzer worker is from verifier).
     */
    if (enableMasking && funcCnt == 1) {
        hash |= _HF_SINGLE_FRAME_MASK;
    }

    return hash;
}
