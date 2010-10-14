/*

   honggfuzz - the main file
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>

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
           " <-f val>: input file (or input dir)\n"
           " [-h]: this help\n"
           " [-q]: null-ify children's stdin, stdout, stderr, make them quiet\n"
           " [-s]: standard input fuzz, instead of providing a file argument\n"
           " [-u]: save only unique test-cases\n"
           " [-d val]: debug level (0 - FATAL ... 4 - DEBUG), default: 3 (INFO)\n"
           " [-e val]: file extension (e.g swf), default: hfuz\n"
           " [-r val]: flip rate, default: 0.001\n"
           " [-m val]: flip mode (-mB - byte, -mb - bit), default: -mB\n"
           " [-c val]: command to modify input file externally (instead of -r/-m)\n"
           " [-t val]: timeout (in secs), default: 3 (0 - no timeout)\n"
           " [-a val]: address limit (from si.si_addr) below which crashes are not reported,\n"
           "           default: 0 (suggested: 65535)\n"
           " [-n val]: number of concurrent fuzzing processes, default: 10\n"
           " [-l val]: per process memory limit in MiB, default: 0 (no limit)\n"
           "usage:\033[1m " PROG_NAME " -f input_dir -- /usr/bin/tiffinfo -D " FILE_PLACEHOLDER
           "\033[0m\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    char c;
    int ll = l_INFO;
    honggfuzz_t hfuzz;

    hfuzz.inputFile = NULL;
    hfuzz.nullifyStdio = false;
    hfuzz.fuzzStdin = false;
    hfuzz.saveUnique = false;
    hfuzz.fileExtn = "hfuz";
    hfuzz.flipRate = 0.001f;
    hfuzz.flipMode = 'B';
    hfuzz.externalCommand = NULL;
    hfuzz.tmOut = 3;
    hfuzz.ignoreAddr = (void *)0UL;
    hfuzz.threadsMax = 10;
    hfuzz.asLimit = 0UL;
    hfuzz.cmdline = NULL;

    hfuzz.files = NULL;
    hfuzz.threadsCnt = 0;

    printf("\033[1m" PROG_NAME ", version " PROG_VERSION " " PROG_AUTHORS "\033[0m\n");
    if (argc < 2) {
        usage();
        exit(EXIT_SUCCESS);
    }

    for (;;) {
        c = getopt(argc, argv, "hqsuf:d:e:r:m:c:t:a:n:l:");
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
        case 'l':
            hfuzz.asLimit = strtoul(optarg, NULL, 10);
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
               "You must specify " FILE_PLACEHOLDER
               " when the -s (stdin fuzzing) option is not set");
        usage();
    }

    if (strchr(hfuzz.fileExtn, '/')) {
        LOGMSG(l_FATAL, "The file extension contains the '/' character: '%s'", hfuzz.fileExtn);
        usage();
    }

    LOGMSG(l_INFO,
           "debugLevel: %d, inputFile '%s', nullifyStdio: %d, fuzzStdin: %d, saveUnique: %d, flipRate: %lf, "
           "flipMode: '%c', externalCommand: '%s', tmOut: %ld, threadsMax: %ld, fileExtn '%s', ignoreAddr: %p, "
           "memoryLimit: %lu (MiB), fuzzExe: '%s',",
           ll, hfuzz.inputFile, hfuzz.nullifyStdio ? 1 : 0,
           hfuzz.fuzzStdin ? 1 : 0, hfuzz.saveUnique ? 1 : 0, hfuzz.flipRate, hfuzz.flipMode,
           hfuzz.externalCommand == NULL ? "NULL" : hfuzz.externalCommand, hfuzz.tmOut,
           hfuzz.threadsMax, hfuzz.fileExtn, hfuzz.ignoreAddr, hfuzz.asLimit, hfuzz.cmdline[0]);

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
