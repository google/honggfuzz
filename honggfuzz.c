/*

   honggfuzz - the main file
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>
           Felix Gröbert <groebert@google.com>

   Copyright 2010 by Google Inc. All Rights Reserved.

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <getopt.h>

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

static void usage(void
    )
{
    printf("%s",
           " <" AB "-f val" AC ">: input file (or input dir)\n"
           " [" AB "-h" AC "]: this help\n"
           " [" AB "-q" AC "]: null-ify children's stdin, stdout, stderr; make them quiet\n"
           " [" AB "-s" AC "]: standard input fuzz, instead of providing a file argument\n"
           " [" AB "-u" AC "]: save unique test-cases only, otherwise (if not used) append\n"
           "       current timestamp to the output filenames\n"
           " [" AB "-d val" AC "]: debug level (0 - FATAL ... 4 - DEBUG), default: '" AB "3" AC
           "' (INFO)\n" " [" AB "-e val" AC "]: file extension (e.g swf), default: '" AB "fuzz" AC
           "'\n" " [" AB "-r val" AC "]: flip rate, default: '" AB "0.001" AC "'\n" " [" AB "-m val"
           AC "]: flip mode (-mB - byte, -mb - bit), default: '" AB "-mB" AC "'\n" " [" AB "-c val"
           AC "]: command modifying input files externally (instead of -r/-m)\n" " [" AB "-t val" AC
           "]: timeout (in secs), default: '" AB "3" AC "' (0 - no timeout)\n" " [" AB "-a val" AC
           "]: address limit (from si.si_addr) below which crashes\n"
           "           are not reported, default: '" AB "0" AC "' (suggested: 65535)\n"
           " [" AB "-n val" AC "]: number of concurrent fuzzing processes, default: '" AB "5" AC "'\n"
           " [" AB "-N val" AC "]: number of fuzzing mutations, default: '" AB "0" AC "' (infintive)\n"
           " [-"
           AB "l val" AC "]: per process memory limit in MiB, default: '" AB "0" AC "' (no limit)\n"
#ifdef _HAVE_ARCH_PTRACE
           " [" AB "-p val" AC
           "]: attach to a pid (a group thread), instead of monitoring\n"
           "           previously created process, default: '" AB "0" AC "' (none)\n"
#endif                          /* _HAVE_ARCH_PTRACE */
           "usage:"
           AB " " PROG_NAME " -f input_dir -- /usr/bin/tiffinfo -D " FILE_PLACEHOLDER AC "\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int c;
    int ll = l_INFO;
    honggfuzz_t hfuzz;

    hfuzz.inputFile = NULL;
    hfuzz.nullifyStdio = false;
    hfuzz.fuzzStdin = false;
    hfuzz.saveUnique = false;
    hfuzz.fileExtn = "fuzz";
    hfuzz.flipRate = 0.001f;
    hfuzz.flipMode = 'B';
    hfuzz.externalCommand = NULL;
    hfuzz.tmOut = 3;
    hfuzz.ignoreAddr = (void *)0UL;
    hfuzz.mutationsMax = 0;
    hfuzz.mutationsCnt = 0;
    hfuzz.threadsMax = 5;
    hfuzz.asLimit = 0UL;
    hfuzz.cmdline = NULL;
    hfuzz.pid = 0;

    hfuzz.files = NULL;
    hfuzz.threadsCnt = 0;

    printf(AB PROG_NAME " version " PROG_VERSION " " PROG_AUTHORS AC "\n");
    if (argc < 2) {
        usage();
        exit(EXIT_SUCCESS);
    }

    for (;;) {
        c = getopt(argc, argv, "hqsuf:d:e:r:m:c:t:a:n:N:l:p:");
        if (c < 0)
            break;

        switch (c) {
        case 'f':
            hfuzz.inputFile = optarg;
            break;
        case 'h':
            usage();
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
            hfuzz.ignoreAddr = (void *)atol(optarg);
            break;
        case 'n':
            hfuzz.threadsMax = atol(optarg);
            break;
        case 'N':
            hfuzz.mutationsMax = atol(optarg);
            break;
        case 'l':
            hfuzz.asLimit = strtoul(optarg, NULL, 10);
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
        usage();
    }

    if (!hfuzz.fuzzStdin && !checkFor_FILE_PLACEHOLDER(hfuzz.cmdline)) {
        LOGMSG(l_FATAL,
               "You must specify '" FILE_PLACEHOLDER
               "' when the -s (stdin fuzzing) option is not set");
        usage();
    }

    if (hfuzz.pid) {
        LOGMSG(l_INFO, "External PID specified, concurrency disabled");
        hfuzz.threadsMax = 1;
    }

    if (strchr(hfuzz.fileExtn, '/')) {
        LOGMSG(l_FATAL, "The file extension contains the '/' character: '%s'", hfuzz.fileExtn);
        usage();
    }

    LOGMSG(l_INFO,
           "debugLevel: %d, inputFile '%s', nullifyStdio: %d, fuzzStdin: %d, saveUnique: %d, flipRate: %lf, "
           "flipMode: '%c', externalCommand: '%s', tmOut: %ld, mutationsMax: %ld, threadsMax: %ld, fileExtn '%s', ignoreAddr: %p, "
           "memoryLimit: %lu (MiB), fuzzExe: '%s', fuzzedPid: %d",
           ll, hfuzz.inputFile, hfuzz.nullifyStdio ? 1 : 0,
           hfuzz.fuzzStdin ? 1 : 0, hfuzz.saveUnique ? 1 : 0, hfuzz.flipRate, hfuzz.flipMode,
           hfuzz.externalCommand == NULL ? "NULL" : hfuzz.externalCommand, hfuzz.tmOut,
           hfuzz.mutationsMax, hfuzz.threadsMax, hfuzz.fileExtn, hfuzz.ignoreAddr, hfuzz.asLimit, hfuzz.cmdline[0],
           hfuzz.pid);

    if (!(hfuzz.fuzzers = malloc(sizeof(hfuzz.fuzzers[0]) * hfuzz.threadsMax))) {
        LOGMSG_P(l_FATAL, "Couldn't allocate memory");
        exit(EXIT_FAILURE);
    }
    memset(hfuzz.fuzzers, '\0', sizeof(hfuzz.fuzzers[0]) * hfuzz.threadsMax);

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
