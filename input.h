/*
 *
 * honggfuzz - fetching input for fuzzing
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
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

#ifndef _HF_INPUT_H_
#define _HF_INPUT_H_

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "honggfuzz.h"

extern void           input_setSize(run_t* run, size_t sz);
extern bool           input_getDirStatsAndRewind(honggfuzz_t* hfuzz);
extern bool           input_getNext(run_t* run, char fname[PATH_MAX], size_t* len, bool rewind);
extern bool           input_init(honggfuzz_t* hfuzz);
extern bool           input_parseDictionary(honggfuzz_t* hfuzz);
extern void           input_freeDictionary(honggfuzz_t* hfuzz);
extern bool           input_parseBlacklist(honggfuzz_t* hfuzz);
extern bool           input_writeCovFile(const char* dir, dynfile_t* dynfile);
extern void           input_addDynamicInput(run_t* run);
extern bool           input_inDynamicCorpus(run_t* run, const char* fname, size_t len);
extern void           input_renumerateInputs(honggfuzz_t* hfuzz);
extern bool           input_prepareDynamicInput(run_t* run, bool needs_mangle);
extern const uint8_t* input_getRandomInputAsBuf(run_t* run, size_t* len);
extern bool           input_prepareStaticFile(run_t* run, bool rewind, bool needs_mangle);
extern bool           input_removeStaticFile(const char* dir, const char* name);
extern bool           input_prepareExternalFile(run_t* run);
extern bool           input_postProcessFile(run_t* run, const char* cmd);
extern bool           input_prepareDynamicFileForMinimization(run_t* run);
extern bool           input_dynamicQueueGetNext(
              char fname[PATH_MAX], DIR* dynamicDirPtr, char* dynamicWorkDir);
extern void input_enqueueDynamicInputs(honggfuzz_t* hfuzz);

#endif /* ifndef _HF_INPUT_H_ */
