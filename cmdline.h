/*
 *
 *   honggfuzz - cmdline parsing
 *   -----------------------------------------
 *
 *   Copyright 2015 Google Inc. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#ifndef _HF_CMDLINE_H_
#define _HF_CMDLINE_H_

#include <sys/resource.h>
#include <sys/time.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"

rlim_t cmdlineParseRLimit(int res, const char* optarg, unsigned long mul);

bool cmdlineAddEnv(honggfuzz_t* hfuzz, char* env);

bool cmdlineParse(int argc, char* argv[], honggfuzz_t* hfuzz);

#endif /* _HF_CMDLINE_H_ */
