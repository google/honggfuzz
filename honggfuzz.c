/*
 *
 * honggfuzz - the main file
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
 * Felix Gröbert <groebert@google.com>
 *
 * Copyright 2010-2015 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "files.h"
#include "fuzz.h"
#include "util.h"

#define AB ANSI_BOLD
#define AC ANSI_CLEAR
#define ANSI_BOLD "\033[1m"
#define ANSI_CLEAR "\033[0m"

static bool checkFor_FILE_PLACEHOLDER(char **args)
{
    for (int x = 0; args[x]; x++) {
        if (strstr(args[x], _HF_FILE_PLACEHOLDER))
            return true;
    }
    return false;
}

static void usage(bool exit_success)
{
    /*  *INDENT-OFF* */
    printf(AB PROG_NAME " version " PROG_VERSION " by " PROG_AUTHORS AC "\n");
    printf("%s",
           " [" AB "-f val" AC "] : input file corpus directory\n"
           "            (or a path to a single input file)\n"
           " [" AB "-h" AC "]     : this help\n"
           " [" AB "-q" AC "]     : null-ify children's stdin, stdout, stderr; make them quiet\n"
           "            (default: " AB "false" AC ")\n"
           " [" AB "-s" AC "]     : provide fuzzing input on STDIN, instead of a file argument\n"
           "            (default: " AB "false" AC ")\n"
           " [" AB "-u" AC "]     : save unique test-cases only, otherwise (if not used) append\n"
           "            current timestamp to the output filenames (default: " AB "false" AC ")\n"
           " [" AB "-v" AC "]     : display simple log messages on stdout instead of using ANSI\n"
           "            console (default: " AB "false" AC ")\n"
           " [" AB "-d val" AC "] : debug level (0 - FATAL ... 4 - DEBUG), (default: '" AB "3" AC
           "' [INFO])\n"
           " [" AB "-e val" AC "] : file extension (e.g. 'swf'), (default: '" AB "fuzz" AC "')\n"
           " [" AB "-W val" AC "] : Workspace directory to save crashes & runtime files\n"
           "            (default: current '.')\n"
           " [" AB "-r val" AC "] : flip rate, (default: '" AB "0.001" AC "')\n"
           " [" AB "-w val" AC "] : wordlist, (default: empty) [tokens delimited by NUL-bytes]\n"
           " [" AB "-c val" AC "] : external command modifying the input corpus of files,\n"
           "            instead of -r/-m (default: " AB "none" AC ")\n"
           " [" AB "-t val" AC "] : timeout (in secs), (default: '" AB "3" AC "' [0 - no timeout])\n"
           " [" AB "-a val" AC "] : address limit (from si.si_addr) below which crashes\n"
           "            are not reported, (default: '" AB "0" AC "' [suggested: 65535])\n"
           " [" AB "-n val" AC "] : number of concurrent fuzzing threads, (default: '" AB "2" AC "')\n"
           " [" AB "-N val" AC "] : number of fuzzing mutations, (default: '" AB "0" AC "' [infinite])\n"
           " [" AB "-l val" AC "] : per process memory limit in MiB, (default: '" AB "0" AC "' [no limit])\n"
           " [" AB "-R val" AC "] : write report to this file, (default: '" AB _HF_REPORT_FILE AC "')\n"
           " [" AB "-F val" AC "] : Maximal size of files created by the fuzzer (default '" AB "1048576" AC "')\n"
           " [" AB "-E val" AC "] : Pass this environment variable (default '" AB "empty" AC "')\n"
           "            can be used multiple times\n"
#if defined(_HF_ARCH_LINUX)
           " [" AB "-p val" AC "] : [Linux] attach to a pid (and its thread group), instead of \n"
           "            monitoring a previously created process, (default: '" AB "0" AC "' [none])\n"
           " [" AB "-LR" AC "]    : [Linux] Don't disable ASLR randomization, might be useful with MSAN\n"
           " [" AB "-LU" AC "]    : [Linux] Report MSAN's UMRS (uninitialized memory access)\n"
           " [" AB "-o val" AC "] : [Linux] cut-off address, don't record branches above that address\n"
           " [" AB "-D val" AC "] : [Linux] create a file dynamically with Linux perf counters,\n"
           "            can be used with or without the '-f' flag (initial file contents)\n"
           "            (default: " AB "none" AC ")\n"
           "            Available counters: \n"
           "               " AB "'i' " AC "- PERF_COUNT_HW_INSTRUCTIONS (total IPs)\n"
           "               " AB "'b' " AC "- PERF_COUNT_HW_BRANCH_INSTRUCTIONS (total jumps/calls)\n"
           "               " AB "'p' " AC "- PERF_SAMPLE_IP (unique code blocks)\n"
           "                     (newer Intel CPUs only)\n"
           "               " AB "'e' " AC "- PERF_SAMPLE_IP/PERF_SAMPLE_ADDR (unique branch edges)\n"
           "                     (newer Intel CPUs only)\n"
#endif /* defined(_HF_ARCH_LINUX) */
           "\nExamples:\n"
           " Run the binary over a mutated file chosen from the directory:\n"
           AB "  " PROG_NAME " -f input_dir -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER AC "\n"
           " As above, provide input over STDIN:\n"
           AB "  " PROG_NAME " -f input_dir -- /usr/bin/djpeg\n" AC
#if defined(_HF_ARCH_LINUX)
           " Run the binary over a dynamic file, maximize total no. of instructions:\n"
           AB "  " PROG_NAME " -Di -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER AC "\n"
           " Run the binary over a dynamic file, maximize total no. of branches:\n"
           AB "  " PROG_NAME " -Db -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER AC "\n"
           " Run the binary over a dynamic file, maximize unique code blocks (coverage):\n"
           AB "  " PROG_NAME " -Dp -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER AC "\n"
           " Run the binary over a dynamic file, maximize unique branches (edges):\n"
           AB "  " PROG_NAME " -De -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER AC "\n"
           " Run the binary over a dynamic file, maximize custom counters (experimental):\n"
           AB "  " PROG_NAME " -Df -- /usr/bin/tiffinfo -D " _HF_FILE_PLACEHOLDER AC "\n"
#endif /* defined(_HF_ARCH_LINUX) */
          );
    /*  *INDENT-ON* */

    if (exit_success) {
        exit(EXIT_SUCCESS);
    } else {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int c;
    int ll = l_INFO;
    honggfuzz_t hfuzz = {
        .cmdline = NULL,
        .inputFile = NULL,
        .nullifyStdio = false,
        .useScreen = true,
        .fuzzStdin = false,
        .saveUnique = false,
        .fileExtn = "fuzz",
        .workDir = ".",
        .flipRate = 0.001f,
        .externalCommand = NULL,
        .dictionaryFile = NULL,
        .dictionary = NULL,
        .dictionaryCnt = 0,
        .maxFileSz = (1024 * 1024),
        .tmOut = 3,
        .mutationsMax = 0,
        .threadsFinished = 0,
        .threadsMax = 2,
        .ignoreAddr = NULL,
        .reportFile = _HF_REPORT_FILE,
        .asLimit = 0ULL,
        .files = NULL,
        .fileCnt = 0,
        .pid = 0,
        .envs = {[0 ... (ARRAYSIZE(hfuzz.envs) - 1)] = NULL,},

        .timeStart = time(NULL),
        .mutationsCnt = 0,
        .crashesCnt = 0,
        .timeoutedCnt = 0,

        .dynFileMethod = _HF_DYNFILE_NONE,
        .dynamicFileBest = NULL,
        .dynamicFileBestSz = 1,
        .branchBestCnt = {[0 ... (ARRAYSIZE(hfuzz.branchBestCnt) - 1)] = 0,},
        .dynamicCutOffAddr = ~(0ULL),
        .dynamicFile_mutex = PTHREAD_MUTEX_INITIALIZER,

        .disableRandomization = true,
        .msanReportUMRS = false,
    };

    if (argc < 2) {
        usage(true);
    }

    for (;;) {
        c = getopt(argc, argv, "-?hqvsuf:d:e:W:r:c:F:D:t:a:R:n:N:l:p:g:o:E:w:L:");
        if (c < 0)
            break;

        switch (c) {
        case 'f':
            hfuzz.inputFile = optarg;
            break;
        case 'h':
        case '?':
            usage(true);
            break;
        case 'q':
            hfuzz.nullifyStdio = true;
            break;
        case 'v':
            hfuzz.useScreen = false;
            break;
        case 's':
            hfuzz.fuzzStdin = true;
            break;
        case 'u':
            hfuzz.saveUnique = true;
            break;
        case 'd':
            ll = atoi(optarg);
            break;
        case 'e':
            hfuzz.fileExtn = optarg;
            break;
        case 'W':
            hfuzz.workDir = optarg;
            break;
        case 'r':
            hfuzz.flipRate = strtod(optarg, NULL);
            break;
        case 'c':
            hfuzz.externalCommand = optarg;
            break;
        case 'F':
            hfuzz.maxFileSz = strtoul(optarg, NULL, 0);
            break;
        case 'D':
            switch (optarg[0]) {
            case 'i':
                hfuzz.dynFileMethod |= _HF_DYNFILE_INSTR_COUNT;
                break;
            case 'b':
                hfuzz.dynFileMethod |= _HF_DYNFILE_BRANCH_COUNT;
                break;
            case 'p':
                hfuzz.dynFileMethod |= _HF_DYNFILE_UNIQUE_BLOCK_COUNT;
                break;
            case 'e':
                hfuzz.dynFileMethod |= _HF_DYNFILE_UNIQUE_EDGE_COUNT;
                break;
            case 'f':
                hfuzz.dynFileMethod |= _HF_DYNFILE_CUSTOM;
                break;
            default:
                LOGMSG(l_ERROR, "Unknown -D mode");
                usage(EXIT_FAILURE);
                break;
            }
            break;
        case 't':
            hfuzz.tmOut = atol(optarg);
            break;
        case 'a':
            hfuzz.ignoreAddr = (void *)strtoul(optarg, NULL, 0);
            break;
        case 'R':
            hfuzz.reportFile = optarg;
            break;
        case 'n':
            hfuzz.threadsMax = atol(optarg);
            break;
        case 'N':
            hfuzz.mutationsMax = atol(optarg);
            break;
        case 'l':
            hfuzz.asLimit = strtoull(optarg, NULL, 0);
            break;
        case 'p':
            hfuzz.pid = atoi(optarg);
            break;
        case 'o':
            hfuzz.dynamicCutOffAddr = strtoull(optarg, NULL, 0);
            break;
        case 'E':
            for (size_t i = 0; i < ARRAYSIZE(hfuzz.envs); i++) {
                if (hfuzz.envs[i] == NULL) {
                    hfuzz.envs[i] = optarg;
                    break;
                }
            }
            break;
        case 'w':
            hfuzz.dictionaryFile = optarg;
            break;
        case 'L':
            switch (optarg[0]) {
            case 'R':
                hfuzz.disableRandomization = false;
                break;
            case 'U':
                hfuzz.msanReportUMRS = true;
                break;
            default:
                LOGMSG(l_ERROR, "Unknown -L switch");
                usage(EXIT_FAILURE);
            }
        default:
            break;
        }
    }
    hfuzz.cmdline = &argv[optind];

    log_setMinLevel(ll);

    if (hfuzz.dynamicFileBestSz > hfuzz.maxFileSz) {
        LOGMSG(l_FATAL,
               "Initial dynamic file size cannot be larger than maximum file size (%zu > %zu)",
               hfuzz.dynamicFileBestSz, hfuzz.maxFileSz);
    }

    if ((hfuzz.dynamicFileBest = malloc(hfuzz.maxFileSz)) == NULL) {
        LOGMSG(l_FATAL, "malloc(%zu) failed", hfuzz.maxFileSz);
    }

    if (!hfuzz.cmdline[0]) {
        LOGMSG(l_FATAL, "Please specify a binary to fuzz");
        usage(false);
    }

    if (!hfuzz.fuzzStdin && !checkFor_FILE_PLACEHOLDER(hfuzz.cmdline)) {
        LOGMSG(l_FATAL,
               "You must specify '" _HF_FILE_PLACEHOLDER
               "' when the -s (stdin fuzzing) option is not set");
        usage(false);
    }

    if (strchr(hfuzz.fileExtn, '/')) {
        LOGMSG(l_FATAL, "The file extension contains the '/' character: '%s'", hfuzz.fileExtn);
        usage(false);
    }

    if (hfuzz.pid > 0) {
        LOGMSG(l_INFO, "PID=%d specified, lowering maximum number of concurrent threads to 1",
               hfuzz.pid);
        hfuzz.threadsMax = 1;
    }

    LOGMSG(l_INFO,
           "debugLevel: %d, inputFile '%s', nullifyStdio: %d, fuzzStdin: %d, saveUnique: %d, flipRate: %lf, "
           "externalCommand: '%s', tmOut: %ld, mutationsMax: %ld, threadsMax: %ld, fileExtn '%s', ignoreAddr: %p, "
           "memoryLimit: %llu (MiB), fuzzExe: '%s', fuzzedPid: %d",
           ll, hfuzz.inputFile, hfuzz.nullifyStdio ? 1 : 0,
           hfuzz.fuzzStdin ? 1 : 0, hfuzz.saveUnique ? 1 : 0,
           hfuzz.flipRate,
           hfuzz.externalCommand == NULL ? "NULL" : hfuzz.externalCommand,
           hfuzz.tmOut, hfuzz.mutationsMax, hfuzz.threadsMax,
           hfuzz.fileExtn, hfuzz.ignoreAddr, hfuzz.asLimit, hfuzz.cmdline[0], hfuzz.pid);

    if (!files_init(&hfuzz)) {
        LOGMSG(l_FATAL, "Couldn't load input files");
        exit(EXIT_FAILURE);
    }

    if (hfuzz.dictionaryFile && (files_parseDictionary(&hfuzz) == false)) {
        LOGMSG(l_FATAL, "Couldn't parse dictionary file ('%s')", hfuzz.dictionaryFile);
    }

    /*
     * So far so good
     */
    fuzz_main(&hfuzz);

    free(hfuzz.dynamicFileBest);

    abort();                    /* NOTREACHED */
    return EXIT_SUCCESS;
}
