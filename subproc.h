/*
 *
 * honggfuzz - routines dealing with subprocesses
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
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

#ifndef _HF_SUBPROC_H_
#define _HF_SUBPROC_H_

#include <signal.h>
#include <sys/wait.h>

/* Missing WIFCONTINUED in Android */
#ifndef WIFCONTINUED
#define WIFCONTINUED(x) WEXITSTATUS(0)
#endif

#define SIGNAL_WAKE (SIGRTMIN + 1)

extern const char *subproc_StatusToStr(int status, char *str, size_t len);

extern bool subproc_PrepareExecv(honggfuzz_t * hfuzz, fuzzer_t * fuzzer, const char *fileName);

extern bool subproc_Run(honggfuzz_t * hfuzz, fuzzer_t * fuzzer);

extern bool subproc_persistentModeRoundDone(honggfuzz_t * hfuzz, fuzzer_t * fuzzer);

extern uint8_t subproc_System(const char *const argv[]);

extern void subproc_checkTimeLimit(honggfuzz_t * hfuzz, fuzzer_t * fuzzer);

#endif
