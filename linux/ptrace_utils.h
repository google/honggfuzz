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

/* 
 * SIGABRT is not a monitored signal for Android OS, since it produces lots of useless 
 * crashes due to way Android process termination hacks work. As a result the sanitizer's
 * 'abort_on_error' flag cannot be utilized since it invokes abort() internally. In order
 * to not lose crashes a custom exitcode is registered and monitored. Since exitcode is a
 * global flag, it's assumed that target is compiled with only one sanitizer enabled at a
 * time.
 */
#define HF_MSAN_EXIT_CODE   103
#define HF_ASAN_EXIT_CODE   104
#define HF_UBSAN_EXIT_CODE  105

/* Prefix for sanitizer report files */
#define kLOGPREFIX          ".hf.san"

extern bool arch_ptraceWaitForPidStop(pid_t pid);
extern bool arch_ptraceEnable(honggfuzz_t * hfuzz);
extern void arch_ptraceAnalyze(honggfuzz_t * hfuzz, int status, pid_t pid, fuzzer_t * fuzzer);
extern bool arch_ptraceAttach(pid_t pid);
extern void arch_ptraceDetach(pid_t pid);
extern void arch_ptraceGetCustomPerf(honggfuzz_t * hfuzz, pid_t pid, uint64_t * cnt);

#endif
