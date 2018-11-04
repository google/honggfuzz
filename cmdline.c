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
#include <sys/queue.h>
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "files.h"
#include "util.h"

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
        if (isprint(opts[i].opt.val) && opts[i].opt.val < 0x80) {
            LOG_HELP_BOLD(" --%s%s%c %s", opts[i].opt.name,
                          "|-", opts[i].opt.val,
                          opts[i].opt.has_arg == required_argument ? "VALUE" : "");
        } else {
            LOG_HELP_BOLD(" --%s %s", opts[i].opt.name,
                          opts[i].opt.has_arg == required_argument ? "VALUE" : "");
        }
        LOG_HELP("\t%s", opts[i].descr);
    }
    LOG_HELP_BOLD("\nExamples:");
    LOG_HELP(" Run the binary over a mutated file chosen from the directory");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER);
    LOG_HELP(" As above, provide input over STDIN:");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -s -- /usr/bin/djpeg");
    LOG_HELP(" Use SANCOV to maximize code coverage:");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -C -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Use compile-time instrumentation (libhfuzz/instrument.c):");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -z -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Use persistent mode (libhfuzz/persistent.c):");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -P -- /usr/bin/tiffinfo_persistent");
    LOG_HELP (" Use persistent mode (libhfuzz/persistent.c) and compile-time instrumentation (libhfuzz/instrument.c):");
    LOG_HELP_BOLD("  " PROG_NAME " -f input_dir -P -z -- /usr/bin/tiffinfo_persistent");
#if defined(_HF_ARCH_LINUX)
    LOG_HELP(" Run the binary over a dynamic file, maximize total no. of instructions:");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_instr -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize total no. of branches:");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_branch -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize unique code blocks via BTS:");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_bts_block -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
    LOG_HELP(" Run the binary over a dynamic file, maximize unique branches (edges) via BTS:");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_bts_edge -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER);
    LOG_HELP
        (" Run the binary over a dynamic file, maximize unique code blocks via Intel Processor Trace (requires libipt.so):");
    LOG_HELP_BOLD("  " PROG_NAME " --linux_perf_ipt_block -- /usr/bin/tiffinfo -D "
                  _HF_FILE_PLACEHOLDER);
#endif                          /* defined(_HF_ARCH_LINUX) */
}

static void cmdlineUsage(const char *pname, struct custom_option *opts)
{
    cmdlineHelp(pname, opts);
    exit(0);
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
    if (util_isANumber(optarg) == false) {
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
        .target = NULL,
        .cmdline_txt[0] = '\0',
        .inputDir = NULL,
        .nullifyStdio = false,
        .fuzzStdin = false,
        .saveUnique = true,
        .useScreen = true,
        .useVerifier = false,
        .keepext = false,
        .timeStart = time(NULL),
        .fileExtn = "fuzz",
        .workDir = ".",
        .covDir = NULL,
        .origFlipRate = 0.001f,
        .externalCommand = NULL,
        .postExternalCommand = NULL,
        .blacklistFile = NULL,
        .blacklistCnt = 0,
        .blacklist = NULL,
        .maxFileSz = 0UL,
        .tmOut = 10,
        .mutationsMax = 0,
        .threadsFinished = 0,
        .threadsMax = (sysconf(_SC_NPROCESSORS_ONLN) <= 1) ? 1 : sysconf(_SC_NPROCESSORS_ONLN) / 2,
        .reportFile = NULL,
        .asLimit = 0ULL,
        .fileCnt = 0,
        .lastFileIndex = 0,
        .doneFileIndex = 0,
        .clearEnv = false,
        .envs = {
            [0 ... (ARRAYSIZE(hfuzz->envs) - 1)] = NULL,
        },
        .persistent = false,
        .tmout_vtalrm = false,
        .skipFeedbackOnTimeout = false,
        .terminating = false,
        
        .dictionaryFile = NULL,
        .dictionaryCnt = 0,

        .state = _HF_STATE_UNSET,
        .feedback = NULL,
        .bbFd = -1,
        .dynfileq_mutex = PTHREAD_MUTEX_INITIALIZER,
        .dynfileqCnt = 0U,

        .mutationsCnt = 0,
        .crashesCnt = 0,
        .uniqueCrashesCnt = 0,
        .verifiedCrashesCnt = 0,
        .blCrashesCnt = 0,
        .timeoutedCnt = 0,

        .pc_list = {0},
        .stack_list = {0},
        .pc_index = 0,
        .stack_index = 0,

        .dynFileMethod = _HF_DYNFILE_NONE,
        .sanCovCnts = {
            .hitBBCnt = 0ULL,
            .totalBBCnt = 0ULL,
            .dsoCnt = 0ULL,
            .iDsoCnt = 0ULL,
            .newBBCnt = 0ULL,
            .lastBBTime = 0ULL,
            .crashesCnt = 0ULL,
        },

        .sanCov_mutex = PTHREAD_MUTEX_INITIALIZER,
        .sanOpts = {
            .asanOpts = NULL,
            .msanOpts = NULL,
            .ubsanOpts = NULL,
        },
        .useSanCov = false,
        .covMetadata = NULL,
        .msanReportUMRS = false,

        .report_mutex = PTHREAD_MUTEX_INITIALIZER,

        /* Linux code */
        .linux = {
            .hwCnts = {
                .cpuInstrCnt = 0ULL,
                .cpuBranchCnt = 0ULL,
                .bbCnt = 0ULL,
                .newBBCnt = 0ULL,
                .softCntPc = 0ULL,
                .softCntCmp = 0ULL,
            },
            .dynamicCutOffAddr = ~(0ULL),
            .disableRandomization = true,
            .ignoreAddr = NULL,
            .numMajorFrames = 7,
            .pid = 0,
            .pidFile = NULL,
            .pidCmd = NULL,
            .symsBlFile = NULL,
            .symsBlCnt = 0,
            .symsBl = NULL,
            .symsWlFile = NULL,
            .symsWlCnt = 0,
            .symsWl = NULL,
        },
    };
    /*  *INDENT-ON* */

    TAILQ_INIT(&hfuzz->dynfileq);
    TAILQ_INIT(&hfuzz->dictq);
    TAILQ_INIT(&hfuzz->fileq);
  
    printf("\n");
    printf("  ██████╗ ██╗██╗   ██╗███████╗██╗   ██╗███████╗███████╗ \n");
    printf("  ██╔══██╗██║██║   ██║██╔════╝██║   ██║╚══███╔╝╚══███╔╝ \n");
    printf("  ██████╔╝██║██║   ██║█████╗  ██║   ██║  ███╔╝   ███╔╝  \n");
    printf("  ██╔══██╗██║██║   ██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝   \n");
    printf("  ██║  ██║██║╚██████╔╝██║     ╚██████╔╝███████╗███████╗ \n");
    printf("  ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝ \n");
    printf("\n");                                                     

    /*  *INDENT-OFF* */
    struct custom_option custom_opts[] = {
        {{"help", no_argument, NULL, 'h'}, "Help plz.."},
        {{"input", required_argument, NULL, 'f'}, "Path to a directory containing initial file corpus"},
        {{"nullify_stdio", no_argument, NULL, 'q'}, "Null-ify children's stdin, stdout, stderr; make them quiet"},
        {{"timeout", required_argument, NULL, 't'}, "Timeout in seconds (default: '10')"},
        {{"threads", required_argument, NULL, 'n'}, "Number of concurrent fuzzing threads (default: number of CPUs / 2)"},
        {{"stdin_input", no_argument, NULL, 's'}, "Provide fuzzing input on STDIN, instead of @@"},
        {{"mutation_rate", required_argument, NULL, 'r'}, "Maximal mutation rate in relation to the file size, (default: '0.001')"},
        {{"logfile", required_argument, NULL, 'l'}, "Log file"},
        {{"verbose", no_argument, NULL, 'v'}, "Disable ANSI console; use simple log output"},
        {{"verifier", no_argument, NULL, 'V'}, "Enable crashes verifier"},
        {{"debug_level", required_argument, NULL, 'd'}, "Debug level (0 - FATAL ... 4 - DEBUG), (default: '3' [INFO])"},
        {{"extension", required_argument, NULL, 'e'}, "Input file extension (e.g. 'swf'), (default: 'fuzz')"},
        {{"workspace", required_argument, NULL, 'W'}, "Workspace directory to save crashes & runtime files (default: '.')"},
        {{"covdir", required_argument, NULL, 0x103}, "New coverage is written to a separate directory (default: use the input directory)"},
        {{"wordlist", required_argument, NULL, 'w'}, "Wordlist file (tokens delimited by NUL-bytes)"},
        {{"stackhash_bl", required_argument, NULL, 'B'}, "Stackhashes blacklist file (one entry per line)"},
        {{"mutate_cmd", required_argument, NULL, 'c'}, "External command producing fuzz files (instead of internal mutators)"},
        {{"pprocess_cmd", required_argument, NULL, 0x104}, "External command postprocessing files produced by internal mutators"},
        {{"iterations", required_argument, NULL, 'N'}, "Number of fuzzing iterations (default: '0' [no limit])"},
        {{"rlimit_as", required_argument, NULL, 0x100}, "Per process memory limit in MiB (default: '0' [no limit])"},
        {{"report", required_argument, NULL, 'R'}, "Write report to this file (default: '" _HF_REPORT_FILE "')"},
        {{"max_file_size", required_argument, NULL, 'F'}, "Maximal size of files processed by the fuzzer in bytes (default: '1048576')"},
        {{"clear_env", no_argument, NULL, 0x101}, "Clear all environment variables before executing the binary"},
        {{"env", required_argument, NULL, 'E'}, "Pass this environment variable, can be used multiple times"},
        {{"save_all", no_argument, NULL, 'u'}, "Save all test-cases (not only the unique ones) by appending the current time-stamp to the filenames"},
        {{"monitor_sigabrt", required_argument, NULL, 0x105 }, "Monitor SIGABRT (default: 'false for Android - 'true for other platforms)" },
        {{"sancov", no_argument, NULL, 'C'}, "Enable sanitizer coverage feedback"},
        {{"instrument", no_argument, NULL, 'z'}, "Enable compile-time instrumentation (link with libhfuzz/libhfuzz.a)"},
        {{"msan_report_umrs", no_argument, NULL, 0x102}, "Report MSAN's UMRS (uninitialized memory access)"},
        {{"persistent", no_argument, NULL, 'P'}, "Enable persistent fuzzing (link with libhfuzz/libhfuzz.a)"},

#if defined(_HF_ARCH_LINUX)
        {{"linux_symbols_bl", required_argument, NULL, 0x504}, "Symbols blacklist filter file (one entry per line)"},
        {{"linux_symbols_wl", required_argument, NULL, 0x505}, "Symbols whitelist filter file (one entry per line)"},
        {{"linux_pid", required_argument, NULL, 'p'}, "Attach to a pid (and its thread group)"},
        {{"linux_file_pid", required_argument, NULL, 0x502}, "Attach to pid (and its thread group) read from file"},
        {{"linux_addr_low_limit", required_argument, NULL, 0x500}, "Address limit (from si.si_addr) below which crashes are not reported, (default: '0')"},
        {{"linux_keep_aslr", no_argument, NULL, 0x501}, "Don't disable ASLR randomization, might be useful with MSAN"},
        {{"linux_perf_ignore_above", required_argument, NULL, 0x503}, "Ignore perf events which report IPs above this address"},
        {{"linux_perf_instr", no_argument, NULL, 0x510}, "Use PERF_COUNT_HW_INSTRUCTIONS perf"},
        {{"linux_perf_branch", no_argument, NULL, 0x511}, "Use PERF_COUNT_HW_BRANCH_INSTRUCTIONS perf"},
        {{"linux_perf_bts_block", no_argument, NULL, 0x512}, "Use Intel BTS to count unique blocks"},
        {{"linux_perf_bts_edge", no_argument, NULL, 0x513}, "Use Intel BTS to count unique edges"},
        {{"linux_perf_ipt_block", no_argument, NULL, 0x514}, "Use Intel Processor Trace to count unique blocks (requires libipt.so)"},
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
        int c = getopt_long(argc, argv, "-?hqvVsuPf:d:e:W:r:c:F:t:R:n:N:l:p:g:E:w:B:Cz", opts,
                            &opt_index);
        if (c < 0)
            break;

        switch (c) {
        case 'h':
        case '?':
            cmdlineUsage(argv[0], custom_opts);
            break;
        case 'f':
            hfuzz->inputDir = optarg;
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
            hfuzz->origFlipRate = strtod(optarg, NULL);
            break;
        case 'c':
            hfuzz->externalCommand = optarg;
            break;
        case 'C':
            hfuzz->useSanCov = true;
            break;
        case 'z':
            hfuzz->dynFileMethod |= _HF_DYNFILE_SOFT;
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
        case 0x101:
            hfuzz->clearEnv = true;
            break;
        case 0x102:
            hfuzz->msanReportUMRS = true;
            break;
        case 0x103:
            hfuzz->covDir = optarg;
            break;
        case 0x104:
            hfuzz->postExternalCommand = optarg;
            break;
        case 0x105:
            if ((strcasecmp(optarg, "0") == 0) || (strcasecmp(optarg, "false") == 0)) {
                hfuzz->monitorSIGABRT = false;
            } else {
                hfuzz->monitorSIGABRT = true;
            }
            break;
        case 0x106:
            hfuzz->skipFeedbackOnTimeout = true;
            break;
        case 'P':
            hfuzz->persistent = true;
            break;
        case 'T':
            hfuzz->tmout_vtalrm = true;
            break;
        case 'p':
            if (util_isANumber(optarg) == false) {
                LOG_E("-p '%s' is not a number", optarg);
                return false;
            }
            hfuzz->linux.pid = atoi(optarg);
            if (hfuzz->linux.pid < 1) {
                LOG_E("-p '%d' is invalid", hfuzz->linux.pid);
                return false;
            }
            break;
        case 0x502:
            hfuzz->linux.pidFile = optarg;
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
            hfuzz->linux.ignoreAddr = (void *)strtoul(optarg, NULL, 0);
            break;
        case 0x501:
            hfuzz->linux.disableRandomization = false;
            break;
        case 0x503:
            hfuzz->linux.dynamicCutOffAddr = strtoull(optarg, NULL, 0);
            break;
        case 0x504:
            hfuzz->linux.symsBlFile = optarg;
            break;
        case 0x505:
            hfuzz->linux.symsWlFile = optarg;
            break;
        case 0x510:
            hfuzz->dynFileMethod |= _HF_DYNFILE_INSTR_COUNT;
            break;
        case 0x511:
            hfuzz->dynFileMethod |= _HF_DYNFILE_BRANCH_COUNT;
            break;
        case 0x512:
            hfuzz->dynFileMethod |= _HF_DYNFILE_BTS_BLOCK;
            break;
        case 0x513:
            hfuzz->dynFileMethod |= _HF_DYNFILE_BTS_EDGE;
            break;
        case 0x514:
            hfuzz->dynFileMethod |= _HF_DYNFILE_IPT_BLOCK;
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

    if (!hfuzz->fuzzStdin && !hfuzz->persistent && !checkFor_FILE_PLACEHOLDER(hfuzz->cmdline)) {
        LOG_E("You must specify '" _HF_FILE_PLACEHOLDER
              "' when the -s (stdin fuzzing) or --persistent options are not set");
        return false;
    }

    if (hfuzz->threadsMax >= _HF_THREAD_MAX) {
        LOG_E("Too many fuzzing threads specified %zu (>= _HF_THREAD_MAX (%u))", hfuzz->threadsMax,
              _HF_THREAD_MAX);
        return false;
    }

    if (strchr(hfuzz->fileExtn, '/')) {
        LOG_E("The file extension contains the '/' character: '%s'", hfuzz->fileExtn);
        return false;
    }

    if (hfuzz->workDir[0] != '.' || strlen(hfuzz->workDir) > 2) {
        if (!files_exists(hfuzz->workDir)) {
            LOG_E("Provided workspace directory '%s' doesn't exist", hfuzz->workDir);
            return false;
        }
    }

    if (hfuzz->linux.pid > 0 || hfuzz->linux.pidFile) {
        LOG_I("PID=%d specified, lowering maximum number of concurrent threads to 1",
              hfuzz->linux.pid);
        hfuzz->threadsMax = 1;
    }

    if (hfuzz->origFlipRate == 0.0L && hfuzz->useVerifier) {
        LOG_I("Verifier enabled with 0.0 flipRate, activating dry run mode");
    }

    LOG_I("inputDir '%s', nullifyStdio: %s, fuzzStdin: %s, saveUnique: %s, flipRate: %lf, "
          "externalCommand: '%s', tmOut: %ld, mutationsMax: %zu, threadsMax: %zu, fileExtn '%s', "
          "memoryLimit: 0x%" PRIx64 "(MiB), fuzzExe: '%s', fuzzedPid: %d",
          hfuzz->inputDir,
          cmdlineYesNo(hfuzz->nullifyStdio), cmdlineYesNo(hfuzz->fuzzStdin),
          cmdlineYesNo(hfuzz->saveUnique), hfuzz->origFlipRate,
          hfuzz->externalCommand == NULL ? "NULL" : hfuzz->externalCommand, hfuzz->tmOut,
          hfuzz->mutationsMax, hfuzz->threadsMax, hfuzz->fileExtn,
          hfuzz->asLimit, hfuzz->cmdline[0], hfuzz->linux.pid);

    snprintf(hfuzz->cmdline_txt, sizeof(hfuzz->cmdline_txt), "%s", hfuzz->cmdline[0]);
    for (size_t i = 1; hfuzz->cmdline[i]; i++) {
        util_ssnprintf(hfuzz->cmdline_txt, sizeof(hfuzz->cmdline_txt), " %s", hfuzz->cmdline[i]);
        //命令行过长时用省略号代替
        if (strlen(hfuzz->cmdline_txt) == (sizeof(hfuzz->cmdline_txt) - 1)) {
            hfuzz->cmdline_txt[sizeof(hfuzz->cmdline_txt) - 3] = '.';
            hfuzz->cmdline_txt[sizeof(hfuzz->cmdline_txt) - 2] = '.';
            hfuzz->cmdline_txt[sizeof(hfuzz->cmdline_txt) - 1] = '.';
        }
    }

    return true;
}
