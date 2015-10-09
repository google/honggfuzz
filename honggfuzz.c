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

#include <inttypes.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "cmdline.h"
#include "log.h"
#include "files.h"
#include "fuzz.h"
#include "util.h"

int main(int argc, char **argv)
{
    honggfuzz_t hfuzz;
    if (cmdlineParse(argc, argv, &hfuzz) == false) {
        LOG_F("Parsing of the cmd-line arguments failed");
    }

    if (!files_init(&hfuzz)) {
        LOG_F("Couldn't load input files");
        exit(EXIT_FAILURE);
    }

    if (hfuzz.dictionaryFile && (files_parseDictionary(&hfuzz) == false)) {
        LOG_F("Couldn't parse dictionary file ('%s')", hfuzz.dictionaryFile);
    }

    if (hfuzz.blacklistFile && (files_parseBlacklist(&hfuzz) == false)) {
        LOG_F("Couldn't parse stackhash blacklist file ('%s')", hfuzz.blacklistFile);
    }

    /*
     * So far so good
     */
    fuzz_main(&hfuzz);

    abort();                    /* NOTREACHED */
    return EXIT_SUCCESS;
}
