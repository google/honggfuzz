/*
 *
 * honggfuzz - fuzzing routines
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

#ifndef _HF_FUZZ_H_
#define _HF_FUZZ_H_

#include <pthread.h>

#include "honggfuzz.h"

extern void fuzz_threadsStart(honggfuzz_t* fuzz);
extern bool fuzz_isTerminating(void);
extern void fuzz_setTerminating(void);
extern bool fuzz_shouldTerminate(void);

#endif
