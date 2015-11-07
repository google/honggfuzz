/*

   honggfuzz - cmdline parsing

   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "cmdline.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "log.h"

#define AB ANSI_BOLD
#define AC ANSI_CLEAR
#define ANSI_BOLD "\033[1m"
#define ANSI_CLEAR "\033[0m"

struct custom_option {
    struct option opt;
    const char *descr;
};

static bool checkFor_FILE_PLACEHOLDER(char **args)
{
    for (int x = 0; args[x]; x++) {
        if (strstr(args[x], _HF_FILE_PLACEHOLDER))
            return true;
    }
    return false;
}

static const char *cmdlineYesNo(bool yes)
{
    return (yes ? "true" : "false");
}

static void cmdlineHelp(const char *pname, struct custom_option *opts)
{
    LOG_HELP_BOLD("Usage: %s [options] -- path_to_command [args]", pname);
    LOG_HELP_BOLD("Options:");
    for (int i = 0; opts[i].opt.name; i++) {
        if (isprint(opts[i].opt.val)) {
            LOG_HELP_BOLD(" --%s%s%c %s", opts[i].opt.name,
                          "|-", opts[i].opt.val,
                          opts[i].opt.has_arg == required_argument ? "[val]" : "");
        } else {
            LOG_HELP_BOLD(" --%s %s", opts[i].opt.name,
                          opts[i].opt.has_arg == required_argument ? "[val]" : "");
        }
        LOG_HELP("\t%s", opts[i].descr);
    }
    LOG_HELP_BOLD("\nExamples:");
    LOG_HELP(" Run the binary over a mutated file chosen from the directory");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER);
    LOG_HELP(" As above, provide input over STDIN:");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -s -- /usr/bin/djpeg" AC);
#if defined(_HF_ARCH_LINUX)
    LOG_HELP(" Run the binary over a dynamic file, maximize total no. of instructions:");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_instr -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize total no. of branches:");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_branch -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize unique code blocks (coverage):");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_ip -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize unique branches (edges):");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_ip_addr -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize custom counters (experimental):");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_custom -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
#endif                          /* defined(_HF_ARCH_LINUX) */
}

static void cmdlineUsage(const char *pname, struct custom_option *opts)
{
    cmdlineHelp(pname, opts);
    exit(0);
}

static bool cmdlineIsANumber(const char *s)
{
    if (!isdigit(s[0])) {
        return false;
    }
    for (int i = 0; s[i]; s++) {
        if (!isdigit(s[i]) && s[i] != 'x') {
            return false;
        }
    }
    return true;
}

rlim_t cmdlineParseRLimit(int res, const char *optarg, unsigned long mul)
{
    struct rlimit cur;
    if (getrlimit(res, &cur) == -1) {
        PLOG_F("getrlimit(%d)", res);
    }
    if (strcasecmp(optarg, "max") == 0) {
        return cur.rlim_max;
    }
    if (strcasecmp(optarg, "def") == 0) {
        return cur.rlim_cur;
    }
    if (cmdlineIsANumber(optarg) == false) {
        LOG_F("RLIMIT %d needs a numeric or 'max'/'def' value ('%s' provided)", res, optarg);
    }
    rlim_t val = strtoul(optarg, NULL, 0) * mul;
    if ((unsigned long)val == ULONG_MAX && errno != 0) {
        PLOG_F("strtoul('%s', 0)", optarg);
    }
    return val;
}

bool cmdlineParse(int argc, char *argv[], honggfuzz_t * hfuzz)
{
    /*  *INDENT-OFF* */
    (*hfuzz) = (honggfuzz_t) {
        .cmdline = NULL,
        .inputFile = NULL,
        .nullifyStdio = false,
        .useScreen = true,
        .fuzzStdin = false,
        .useVerifier = false,
        .saveUnique = true,
        .fileExtn = "fuzz",
        .workDir = ".",
        .flipRate = 0.001f,
        .externalCommand = NULL,
        .dictionaryFile = NULL,
        .dictionary = NULL,
        .dictionaryCnt = 0,
        .blacklistFile = NULL,
        .blacklistCnt = 0,
        .blacklist = NULL,
        .maxFileSz = (1024 * 1024),
        .tmOut = 3,
        .mutationsMax = 0,
        .threadsFinished = 0,
        .threadsMax = 2,
        .reportFile = NULL,
        .asLimit = 0ULL,
        .files = NULL,
        .fileCnt = 0,
        .lastCheckedFileIndex = 0,
        .pid = 0,
        .envs = {[0 ... (ARRAYSIZE(hfuzz->envs) - 1)] = NULL,},

        .timeStart = time(NULL),
        .mutationsCnt = 0,
        .crashesCnt = 0,
        .uniqueCrashesCnt = 0,
        .verifiedCrashesCnt = 0,
        .blCrashesCnt = 0,
        .timeoutedCnt = 0,

        .dynFileMethod = _HF_DYNFILE_NONE,
        .dynamicFileBest = NULL,
        .dynamicFileBestSz = 1,
        .hwCnts = {
                   .cpuInstrCnt = 0ULL,
                   .cpuBranchCnt = 0ULL,
                   .pcCnt = 0ULL,
                   .pathCnt = 0ULL,
                   .customCnt = 0ULL,
                   },
        .dynamicCutOffAddr = ~(0ULL),
        .dynamicFile_mutex = PTHREAD_MUTEX_INITIALIZER,

        .disableRandomization = true,
        .msanReportUMRS = false,
        .ignoreAddr = NULL,
    };
    /*  *INDENT-ON* */

    /*  *INDENT-OFF* */
    struct custom_option custom_opts[] = {
        {{"help", no_argument, NULL, 'h'}, "Help plz.."},
        {{"input", required_argument, NULL, 'f'}, "Path to the file corpus (file or a directory)"},
        {{"nullify_stdio", no_argument, NULL, 'q'}, "Null-ify children's stdin, stdout, stderr; make them quiet"},
        {{"stdin_input", no_argument, NULL, 's'}, "Provide fuzzing input on STDIN, instead of ___FILE___"},
        {{"save_all", no_argument, NULL, 'u'}, "Save all test-cases (not only the unique ones) by appending the current time-stamp to the filenames"},
        {{"logfile", required_argument, NULL, 'l'}, "Log file"},
        {{"verbose", no_argument, NULL, 'v'}, "Disable ANSI console; use simple log output"},
#if defined(_HF_ARCH_LINUX) || defined(_HF_ARCH_DARWIN)
        {{"verifier", no_argument, NULL, 'V'}, "Enable crashes verifier (default: disabled)"},
#endif
        {{"debug_level", required_argument, NULL, 'd'}, "Debug level (0 - FATAL ... 4 - DEBUG), (default: '3' [INFO])"},
        {{"extension", required_argument, NULL, 'e'}, "Input file extension (e.g. 'swf'), (default: 'fuzz')"},
        {{"wokspace", required_argument, NULL, 'W'}, "Workspace directory to save crashes & runtime files (default: '.')"},
        {{"flip_rate", required_argument, NULL, 'r'}, "Maximal flip rate, (default: '0.001')"},
        {{"wordlist", required_argument, NULL, 'w'}, "Wordlist file (tokens delimited by NUL-bytes)"},
        {{"stackhash_bl", required_argument, NULL, 'B'}, "Stackhashes blacklist file (one entry per line)"},
        {{"mutate_cmd", required_argument, NULL, 'c'}, "External command modifying the input corpus of files, instead of -r/-m parameters"},
        {{"timeout", required_argument, NULL, 't'}, "Timeout in seconds (default: '3')"},
        {{"threads", required_argument, NULL, 'n'}, "Number of concurrent fuzzing threads (default: '2')"},
        {{"iterations", required_argument, NULL, 'N'}, "Number of fuzzing iterations (default: '0' [no limit])"},
        {{"rlimit_as", required_argument, NULL, 0x100}, "Per process memory limit in MiB (default: '0' [no limit])"},
        {{"report", required_argument, NULL, 'R'}, "Per process memory limit in MiB (default: '" _HF_REPORT_FILE "')"},
        {{"max_file_size", required_argument, NULL, 'F'}, "Maximal size of files processed by the fuzzer in bytes (default: '1048576')"},
        {{"env", required_argument, NULL, 'E'}, "Pass this environment variable, can be used multiple times"},

#if defined(_HF_ARCH_LINUX)
        {{"linux_pid", required_argument, NULL, 'p'}, "[Linux] Attach to a pid (and its thread group)"},
        {{"linux_addr_low_limit", required_argument, NULL, 0x500}, "Address limit (from si.si_addr) below which crashes are not reported, (default: '0')"},
        {{"linux_keep_aslr", no_argument, NULL, 0x501}, "Don't disable ASLR randomization, might be useful with MSAN"},
        {{"linux_report_msan_umrs", no_argument, NULL, 0x502}, "Report MSAN's UMRS (uninitialized memory access)"},
        {{"linux_perf_ignore_above", required_argument, NULL, 0x503}, "Ignore perf events which report IPs above this address"},
        {{"linux_perf_instr", no_argument, NULL, 0x510}, "Use PERF_COUNT_HW_INSTRUCTIONS perf"},
        {{"linux_perf_branch", no_argument, NULL, 0x511}, "Use PERF_COUNT_HW_BRANCH_INSTRUCTIONS perf"},
        {{"linux_perf_ip", no_argument, NULL, 0x512}, "Use PERF_SAMPLE_IP perf (newer Intel CPUs only)"},
        {{"linux_perf_ip_addr", no_argument, NULL, 0x513}, "Use PERF_SAMPLE_IP/PERF_SAMPLE_ADDR perf (newer Intel CPUs only)"},
        {{"linux_perf_custom", no_argument, NULL, 0x514}, "Custom counter (see the interceptor/ directory for examples)"},
#endif  // defined(_HF_ARCH_LINUX)
        {{0, 0, 0, 0}, NULL},
    };
    /*  *INDENT-ON* */

    struct option opts[ARRAYSIZE(custom_opts)];
    for (unsigned i = 0; i < ARRAYSIZE(custom_opts); i++) {
        opts[i] = custom_opts[i].opt;
    }

    enum llevel_t ll = INFO;
    const char *logfile = NULL;
    int opt_index = 0;
    for (;;) {
        int c = getopt_long(argc, argv, "-?hqvVsuf:d:e:W:r:c:F:t:R:n:N:l:p:g:E:w:B:", opts,
                            &opt_index);
        if (c < 0)
            break;

        switch (c) {
        case 'h':
        case '?':
            cmdlineUsage(argv[0], custom_opts);
            break;
        case 'f':
            hfuzz->inputFile = optarg;
            break;
        case 'q':
            hfuzz->nullifyStdio = true;
            break;
        case 'v':
            hfuzz->useScreen = false;
            break;
        case 'V':
            hfuzz->useVerifier = true;
            break;
        case 's':
            hfuzz->fuzzStdin = true;
            break;
        case 'u':
            hfuzz->saveUnique = false;
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'd':
            ll = atoi(optarg);
            break;
        case 'e':
            hfuzz->fileExtn = optarg;
            break;
        case 'W':
            hfuzz->workDir = optarg;
            break;
        case 'r':
            hfuzz->flipRate = strtod(optarg, NULL);
            break;
        case 'c':
            hfuzz->externalCommand = optarg;
            break;
        case 'F':
            hfuzz->maxFileSz = strtoul(optarg, NULL, 0);
            break;
        case 't':
            hfuzz->tmOut = atol(optarg);
            break;
        case 'R':
            hfuzz->reportFile = optarg;
            break;
        case 'n':
            hfuzz->threadsMax = atol(optarg);
            break;
        case 'N':
            hfuzz->mutationsMax = atol(optarg);
            break;
        case 0x100:
            hfuzz->asLimit = strtoull(optarg, NULL, 0);
            break;
        case 'p':
            if (cmdlineIsANumber(optarg) == false) {
                LOG_E("-p '%s' is not a number", optarg);
                return false;
            }
            hfuzz->pid = atoi(optarg);
            if (hfuzz->pid < 1) {
                LOG_E("-p '%d' is invalid", hfuzz->pid);
                return false;
            }
            break;
        case 'E':
            for (size_t i = 0; i < ARRAYSIZE(hfuzz->envs); i++) {
                if (hfuzz->envs[i] == NULL) {
                    hfuzz->envs[i] = optarg;
                    break;
                }
            }
            break;
        case 'w':
            hfuzz->dictionaryFile = optarg;
            break;
        case 'B':
            hfuzz->blacklistFile = optarg;
            break;
        case 0x500:
            hfuzz->ignoreAddr = (void *)strtoul(optarg, NULL, 0);
            break;
        case 0x501:
            hfuzz->disableRandomization = false;
            break;
        case 0x502:
            hfuzz->msanReportUMRS = true;
            break;
        case 0x503:
            hfuzz->dynamicCutOffAddr = strtoull(optarg, NULL, 0);
            break;
        case 0x510:
            hfuzz->dynFileMethod |= _HF_DYNFILE_INSTR_COUNT;
            break;
        case 0x511:
            hfuzz->dynFileMethod |= _HF_DYNFILE_BRANCH_COUNT;
            break;
        case 0x512:
            hfuzz->dynFileMethod |= _HF_DYNFILE_UNIQUE_BLOCK_COUNT;
            break;
        case 0x513:
            hfuzz->dynFileMethod |= _HF_DYNFILE_UNIQUE_EDGE_COUNT;
            break;
        case 0x514:
            hfuzz->dynFileMethod |= _HF_DYNFILE_CUSTOM;
            break;
        default:
            cmdlineUsage(argv[0], custom_opts);
            return false;
            break;
        }
    }

    if (logInitLogFile(logfile, ll) == false) {
        return false;
    }

    hfuzz->cmdline = &argv[optind];
    if (hfuzz->cmdline[0] == NULL) {
        LOG_E("No fuzz command provided");
        cmdlineUsage(argv[0], custom_opts);
        return false;
    }

    if (hfuzz->dynamicFileBestSz > hfuzz->maxFileSz) {
        LOG_E("Initial dynamic file size cannot be larger than maximum file size (%zu > %zu)",
              hfuzz->dynamicFileBestSz, hfuzz->maxFileSz);
        return false;
    }

    if ((hfuzz->dynamicFileBest = malloc(hfuzz->maxFileSz)) == NULL) {
        LOG_E("malloc(%zu) failed", hfuzz->maxFileSz);
        return false;
    }

    if (!hfuzz->fuzzStdin && !checkFor_FILE_PLACEHOLDER(hfuzz->cmdline)) {
        LOG_E("You must specify '" _HF_FILE_PLACEHOLDER
              "' when the -s (stdin fuzzing) option is not set");
        return false;
    }

    if (strchr(hfuzz->fileExtn, '/')) {
        LOG_E("The file extension contains the '/' character: '%s'", hfuzz->fileExtn);
        return false;
    }

    if (hfuzz->pid > 0) {
        LOG_I("PID=%d specified, lowering maximum number of concurrent threads to 1", hfuzz->pid);
        hfuzz->threadsMax = 1;
    }

    if (hfuzz->flipRate == 0.0L && hfuzz->useVerifier) {
        LOG_I("Verifier enabled with 0.0flipRate, activating dry run mode");
    }

    LOG_I("inputFile '%s', nullifyStdio: %s, fuzzStdin: %s, saveUnique: %s, flipRate: %lf, "
          "externalCommand: '%s', tmOut: %ld, mutationsMax: %zu, threadsMax: %zu, fileExtn '%s', ignoreAddr: %p, "
          "memoryLimit: 0x%" PRIx64 "(MiB), fuzzExe: '%s', fuzzedPid: %d",
          hfuzz->inputFile,
          cmdlineYesNo(hfuzz->nullifyStdio), cmdlineYesNo(hfuzz->fuzzStdin),
          cmdlineYesNo(hfuzz->saveUnique), hfuzz->flipRate,
          hfuzz->externalCommand == NULL ? "NULL" : hfuzz->externalCommand, hfuzz->tmOut,
          hfuzz->mutationsMax, hfuzz->threadsMax, hfuzz->fileExtn, hfuzz->ignoreAddr,
          hfuzz->asLimit, hfuzz->cmdline[0], hfuzz->pid);

    return true;
}
