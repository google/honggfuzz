/*
 *
 * honggfuzz - tracing processes with ptrace()
 * -----------------------------------------
 *
 * Author: Kamil Rytarowski <n54@gmx.com>
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

#ifndef _HF_NETBSD_TRACE_H_
#define _HF_NETBSD_TRACE_H_

#include <inttypes.h>

#include "honggfuzz.h"

#define _HF_DYNFILE_SUB_MASK 0xFFFUL  // Zero-set two MSB

/* Constant prefix used for single frame crashes stackhash masking */
#define _HF_SINGLE_FRAME_MASK 0xBADBAD0000000000

extern bool arch_traceWaitForPidStop(pid_t pid);
extern bool arch_traceEnable(run_t* run);
extern void arch_traceAnalyze(run_t* run, int status, pid_t pid);
extern void arch_traceExitAnalyze(run_t* run, pid_t pid);
extern bool arch_traceAttach(run_t* run);
extern void arch_traceDetach(pid_t pid);
extern void arch_traceGetCustomPerf(run_t* run, pid_t pid, uint64_t* cnt);
extern void arch_traceSetCustomPerf(run_t* run, pid_t pid, uint64_t cnt);
extern void arch_traceSignalsInit(honggfuzz_t* hfuzz);

#endif
