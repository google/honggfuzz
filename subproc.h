/*
 *
 * honggfuzz - routines dealing with subprocesses
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

#ifndef _HF_SUBPROC_H_
#define _HF_SUBPROC_H_

#include <pthread.h>

#include "honggfuzz.h"

/* Missing WIFCONTINUED in Android */
#ifndef WIFCONTINUED
#define WIFCONTINUED(x) WEXITSTATUS(0)
#endif

extern const char* subproc_StatusToStr(int status, char* str, size_t len);

extern bool subproc_Run(run_t* run);

extern bool subproc_persistentModeStateMachine(run_t* run);

extern uint8_t subproc_System(run_t* run, const char* const argv[]);

extern void subproc_checkTimeLimit(run_t* run);

extern void subproc_checkTermination(run_t* run);

bool subproc_runThread(
    honggfuzz_t* hfuzz, pthread_t* thread, void* (*thread_func)(void*), bool joinable);

#endif
