/*

   honggfuzz - the main file
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>
           Felix Gröbert <groebert@google.com>

   Copyright 2010-2015 by Google Inc. All Rights Reserved.

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
        if (!strcmp(args[x], FILE_PLACEHOLDER))
            return true;
    }
    return false;
}

static void usage(bool exit_success)
{
    /*  *INDENT-OFF* */
    printf("%s",
           " <" AB "-f val" AC ">: directory with input files (or a path to a single input file)\n"
           " [" AB "-h" AC "]: this help\n"
           " [" AB "-q" AC "]: null-ify children's stdin, stdout, stderr; make them quiet (default: " AB "false" AC ")\n"
           " [" AB "-s" AC "]: provide fuzzing input on STDIN, instead a file argument (default: " AB "false" AC ")\n"
           " [" AB "-u" AC "]: save unique test-cases only, otherwise (if not used) append\n"
           "       current timestamp to the output filenames (default: " AB "false" AC ")\n"
           " [" AB "-d val" AC "]: debug level (0 - FATAL ... 4 - DEBUG), (default: '" AB "3" AC
           "' [INFO])\n"
           " [" AB "-e val" AC "]: file extension (e.g swf), (default: '" AB "fuzz" AC "')\n"
           " [" AB "-r val" AC "]: flip rate, (default: '" AB "0.001" AC "')\n"
           " [" AB "-m val" AC "]: flip mode (-mB - byte, -mb - bit), (default: '" AB "-mB" AC "')\n"
           " [" AB "-c val" AC "]: an external command modifying the input corpus of files (instead of -r/-m)\n"
           " [" AB "-t val" AC "]: timeout (in secs), (default: '" AB "3" AC "' [0 - no timeout])\n"
           " [" AB "-a val" AC "]: address limit (from si.si_addr) below which crashes\n"
           "           are not reported, (default: '" AB "0" AC "' [suggested: 65535])\n"
           " [" AB "-n val" AC "]: number of concurrent fuzzing processes, (default: '" AB "5" AC "')\n"
           " [" AB "-N val" AC "]: number of fuzzing mutations, (default: '" AB "0" AC "' [infinte])\n"
           " [-" AB "l val" AC "]: per process memory limit in MiB, (default: '" AB "0" AC "' [no limit])\n"
#ifdef _HAVE_ARCH_LINUX
           " [" AB "-p val" AC
           "]: attach to a pid (a group thread), instead of monitoring\n"
           "           previously created process, default: '" AB "0" AC "' (none)\n"
#endif                          /* _HAVE_ARCH_LINUX */
           "Usage:"
           AB " " PROG_NAME " -f input_dir -- /usr/bin/tiffinfo -D " FILE_PLACEHOLDER AC "\n");
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
        .fuzzStdin = false,
        .saveUnique = false,
        .fileExtn = "fuzz",
        .flipRate = 0.001f,
        .flipMode = 'B',
        .externalCommand = NULL,
        .tmOut = 3,
        .mutationsMax = 0,
        .mutationsCnt = 0,
        .threadsMax = 5,
        .ignoreAddr = NULL,
        .asLimit = 0UL,
        .pid = 0,
        .files = NULL,
        .fileCnt = 0,
    };

    printf(AB PROG_NAME " version " PROG_VERSION " by " PROG_AUTHORS AC "\n");
    if (argc < 2) {
        usage(true);
    }

    for (;;) {
        c = getopt(argc, argv, "?hqsuf:d:e:r:m:c:t:a:n:N:l:p:");
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
        case 'r':
            hfuzz.flipRate = atof(optarg);
            break;
        case 'm':
            hfuzz.flipMode = optarg[0];
            break;
        case 'c':
            hfuzz.externalCommand = optarg;
            break;
        case 't':
            hfuzz.tmOut = atol(optarg);
            break;
        case 'a':
            hfuzz.ignoreAddr = (void *)strtoul(optarg, NULL, 0);
            break;
        case 'n':
            hfuzz.threadsMax = atol(optarg);
            break;
        case 'N':
            hfuzz.mutationsMax = atol(optarg);
            break;
        case 'l':
            hfuzz.asLimit = strtoul(optarg, NULL, 0);
            break;
        case 'p':
            hfuzz.pid = atoi(optarg);
            break;
        default:
            break;
        }
    }
    hfuzz.cmdline = &argv[optind];

    util_rndInit();
    log_setMinLevel(ll);

    if (!hfuzz.cmdline[0]) {
        LOGMSG(l_FATAL, "Please specify binary to fuzz");
        usage(false);
    }

    if (!hfuzz.fuzzStdin && !checkFor_FILE_PLACEHOLDER(hfuzz.cmdline)) {
        LOGMSG(l_FATAL,
               "You must specify '" FILE_PLACEHOLDER
               "' when the -s (stdin fuzzing) option is not set");
        usage(false);
    }

    if (hfuzz.pid) {
        LOGMSG(l_INFO, "External PID specified, concurrency disabled");
        hfuzz.threadsMax = 1;
    }

    if (strchr(hfuzz.fileExtn, '/')) {
        LOGMSG(l_FATAL, "The file extension contains the '/' character: '%s'", hfuzz.fileExtn);
        usage(false);
    }

    LOGMSG(l_INFO,
           "debugLevel: %d, inputFile '%s', nullifyStdio: %d, fuzzStdin: %d, saveUnique: %d, flipRate: %lf, "
           "flipMode: '%c', externalCommand: '%s', tmOut: %ld, mutationsMax: %ld, threadsMax: %ld, fileExtn '%s', ignoreAddr: %p, "
           "memoryLimit: %lu (MiB), fuzzExe: '%s', fuzzedPid: %d",
           ll, hfuzz.inputFile, hfuzz.nullifyStdio ? 1 : 0, hfuzz.fuzzStdin ? 1 : 0,
           hfuzz.saveUnique ? 1 : 0, hfuzz.flipRate,
           hfuzz.flipMode, hfuzz.externalCommand == NULL ? "NULL" : hfuzz.externalCommand,
           hfuzz.tmOut, hfuzz.mutationsMax, hfuzz.threadsMax, hfuzz.fileExtn, hfuzz.ignoreAddr,
           hfuzz.asLimit, hfuzz.cmdline[0], hfuzz.pid);

    if (!files_init(&hfuzz)) {
        LOGMSG(l_FATAL, "Couldn't load input files");
        exit(EXIT_FAILURE);
    }

    /*
     * So far so good
     */
    fuzz_main(&hfuzz);

    abort();                    /* NOTREACHED */
    return EXIT_SUCCESS;
}
