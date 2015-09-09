/*
 *
 * honggfuzz - architecture dependent code
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

#ifndef _LINUX_PTRACE_UTILS_H_
#define _LINUX_PTRACE_UTILS_H_

#define HF_MSAN_EXIT_CODE 103
#define HF_MSAN_EXIT_CODE_STR "103"

extern bool arch_ptraceEnable(honggfuzz_t * fuzz);
extern void arch_ptraceAnalyze(honggfuzz_t * fuzz, int status, pid_t pid, fuzzer_t * fuzzer);
extern bool arch_ptraceAttach(pid_t pid);
extern void arch_ptraceGetCustomPerf(honggfuzz_t * fuzz, pid_t pid, uint64_t * cnt);

#endif
