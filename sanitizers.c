#include "sanitizers.h"

#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cmdline.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

/*
 * All clang sanitizers, except ASan, can be activated for target binaries
 * with or without the matching runtime library (libcompiler_rt). If runtime
 * libraries are included in target fuzzing environment, we can benefit from the
 * various Die() callbacks and abort/exit logic manipulation. However, some
 * setups (e.g. Android production ARM/ARM64 devices) enable sanitizers, such as
 * UBSan, without the runtime libraries. As such, their default ftrap is activated
 * which is for most cases a SIGABRT. For these cases end-user needs to enable
 * SIGABRT monitoring flag, otherwise these crashes will be missed.
 *
 * Normally SIGABRT is not a wanted signal to monitor for Android, since it produces
 * lots of useless crashes due to way Android process termination hacks work. As
 * a result the sanitizer's 'abort_on_error' flag cannot be utilized since it
 * invokes abort() internally. In order to not lose crashes a custom exitcode can
 * be registered and monitored. Since exitcode is a global flag, it's assumed
 * that target is compiled with only one sanitizer type enabled at a time.
 *
 * For cases where clang runtime library linking is not an option, SIGABRT should
 * be monitored even for noisy targets, such as the Android OS, since no viable
 * alternative exists.
 *
 * There might be cases where ASan instrumented targets crash while generating
 * reports for detected errors (inside __asan_report_error() proc). Under such
 * scenarios target fails to exit or SIGABRT (AsanDie() proc) as defined in
 * ASAN_OPTIONS flags, leaving garbage logs. An attempt is made to parse such
 * logs for cases where enough data are written to identify potentially missed
 * crashes. If ASan internal error results into a SIGSEGV being raised, it
 * will get caught from ptrace API, handling the discovered ASan internal crash.
 */

/*
 * Common sanitizer flags
 *
 * symbolize: Disable symbolication since it changes logs (which are parsed) format
 */
#define kSAN_COMMON                \
    "symbolize=1:"                 \
    "detect_leaks=0:"              \
    "disable_coredump=0:"          \
    "detect_odr_violation=0:"      \
    "allocator_may_return_null=1:" \
    "allow_user_segv_handler=0:"   \
    "handle_segv=2:"               \
    "handle_sigbus=2:"             \
    "handle_abort=2:"              \
    "handle_sigill=2:"             \
    "handle_sigfpe=2:"             \
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
#define kSAN_REGULAR               \
    "symbolize=1:"                 \
    "detect_leaks=0:"              \
    "disable_coredump=0:"          \
    "detect_odr_violation=0:"      \
    "allocator_may_return_null=1:" \
    "allow_user_segv_handler=1:"   \
    "handle_segv=0:"               \
    "handle_sigbus=0:"             \
    "handle_abort=0:"              \
    "handle_sigill=0:"             \
    "handle_sigfpe=0:"             \
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

size_t sanitizers_parseReport(run_t* run, pid_t pid, funcs_t* funcs, uint64_t* pc,
    uint64_t* crashAddr, const char** op, char description[HF_STR_LEN]) {
    char crashReport[PATH_MAX];
    const char* crashReportCpy = crashReport;
    snprintf(
        crashReport, sizeof(crashReport), "%s/%s.%d", run->global->io.workDir, kLOGPREFIX, pid);

    FILE* fReport = fopen(crashReport, "rb");
    if (fReport == NULL) {
        PLOG_D("Couldn't open '%s' - R/O mode", crashReport);
        return 0;
    }
    defer {
        fclose(fReport);
        if (run->global->sanitizer.del_report) {
            unlink(crashReportCpy);
        }
    };

    bool headerFound = false;
    unsigned int frameIdx = 0;

    char *lineptr = NULL, *cAddr = NULL;
    size_t n = 0;
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
            if (sscanf(lineptr, "==%d==ERROR: AddressSanitizer:", &reportpid) != 1) {
                continue;
            }
            if (reportpid != pid) {
                LOG_W(
                    "SAN report found in '%s', but its PID:%d is different from the needed PID:%d",
                    crashReport, reportpid, pid);
                break;
            }
            headerFound = true;
            sscanf(lineptr,
                "==%*d==ERROR: AddressSanitizer: %*[^ ] on address 0x%" PRIx64 " at pc 0x%" PRIx64,
                pc, crashAddr);
            sscanf(lineptr,
                "==%*d==ERROR: AddressSanitizer: %*[^ ] on %*s address 0x%" PRIx64
                " (pc 0x%" PRIx64,
                crashAddr, pc);
            sscanf(lineptr, "==%*d==ERROR: AddressSanitizer: %" HF_XSTR(HF_STR_LEN_MINUS_1) "[^\n]",
                description);
        } else {
            char* pLineLC = lineptr;
            /* Trim leading spaces */
            while (*pLineLC != '\0' && isspace(*pLineLC)) {
                ++pLineLC;
            }

            /* End separator for crash thread stack trace is an empty line */
            if ((*pLineLC == '\0') && (frameIdx != 0)) {
                break;
            }

            /* If available parse the type of error (READ/WRITE) */
            if (cAddr && strstr(pLineLC, cAddr)) {
                if (strncmp(pLineLC, "READ", 4) == 0) {
                    *op = "READ";
                } else if (strncmp(pLineLC, "WRITE", 5) == 0) {
                    *op = "WRITE";
                }
                cAddr = NULL;
            }

            if (sscanf(pLineLC, "#%u", &frameIdx) != 1) {
                continue;
            }
            if (frameIdx >= _HF_MAX_FUNCS) {
                frameIdx = _HF_MAX_FUNCS - 1;
                break;
            }

            /*
             * Frames with symbols but w/o debug info
             *     #33 0x7ffff59a3668 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x9668)
             */
            if (sscanf(pLineLC,
                    "#%*u 0x%p in %" HF_XSTR(_HF_FUNC_NAME_SZ_MINUS_1) "s%*[^(](%" HF_XSTR(
                        HF_STR_LEN_MINUS_1) "s",
                    &funcs[frameIdx].pc, funcs[frameIdx].func, funcs[frameIdx].mapName) == 3) {
                continue;
            }
            /*
             * Frames with symbols and with debug info
             *     #0 0x1e94738 in smb2_signing_decrypt_pdu
             * /home/test/libcli/smb/smb2_signing.c:617:3
             */
            if (sscanf(pLineLC,
                    "#%*u 0x%p in %" HF_XSTR(_HF_FUNC_NAME_SZ_MINUS_1) "[^ ] %" HF_XSTR(
                        HF_STR_LEN_MINUS_1) "[^:\n]:%zu",
                    &funcs[frameIdx].pc, funcs[frameIdx].func, funcs[frameIdx].mapName,
                    &funcs[frameIdx].line) == 4) {
                continue;
            }
            /*
             * Frames w/o symbols
             *     #2 0x565584f4  (/mnt/z/test+0x34f4)
             */
            if (sscanf(pLineLC, "#%*u 0x%p%*[^(](%" HF_XSTR(HF_STR_LEN_MINUS_1) "[^)\n]",
                    &funcs[frameIdx].pc, funcs[frameIdx].mapName) == 2) {
                continue;
            }
        }
    }

    return (frameIdx + 1);
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
