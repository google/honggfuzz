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

#ifndef _HF_LINUX_PTRACE_UTILS_H_
#define _HF_LINUX_PTRACE_UTILS_H_

#define _HF_DYNFILE_SUB_MASK 0xFFFUL    // Zero-set two MSB

/* Constant prefix used for single frame crashes stackhash masking */
#define _HF_SINGLE_FRAME_MASK  0xBADBAD0000000000

extern bool arch_ptraceWaitForPidStop(pid_t pid);
extern bool arch_ptraceEnable(honggfuzz_t * hfuzz);
extern void arch_ptraceAnalyze(honggfuzz_t * hfuzz, int status, pid_t pid, fuzzer_t * fuzzer);
extern void arch_ptraceExitAnalyze(honggfuzz_t * hfuzz, pid_t pid, fuzzer_t * fuzzer, int exitCode);
extern bool arch_ptraceAttach(honggfuzz_t * hfuzz, pid_t pid);
extern void arch_ptraceDetach(pid_t pid);
extern void arch_ptraceGetCustomPerf(honggfuzz_t * hfuzz, pid_t pid, uint64_t * cnt);
extern void arch_ptraceSetCustomPerf(honggfuzz_t * hfuzz, pid_t pid, uint64_t cnt);

#endif
