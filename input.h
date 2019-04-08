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

#include "honggfuzz.h"

extern void input_setSize(run_t* run, size_t sz);
extern bool input_getNext(run_t* run, char* fname, bool rewind);
extern bool input_init(honggfuzz_t* hfuzz);
extern bool input_parseDictionary(honggfuzz_t* hfuzz);
extern bool input_parseBlacklist(honggfuzz_t* hfuzz);
extern bool input_prepareDynamicInput(run_t* run, bool need_mangele);
extern bool input_prepareStaticFile(run_t* run, bool rewind, bool need_mangele);
extern bool input_prepareExternalFile(run_t* run);
extern bool input_postProcessFile(run_t* run);
extern bool input_feedbackMutateFile(run_t* run);

#endif /* ifndef _HF_INPUT_H_ */
