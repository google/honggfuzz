/*
 *
 * honggfuzz - architecture dependent code
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

#ifndef _HF_LINUX_BFD_H_
#define _HF_LINUX_BFD_H_

#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>

#include "linux/unwind.h"

#define _HF_INSTR_SZ 64

#define PACKAGE 1
#define PACKAGE_VERSION 1

extern void arch_bfdResolveSyms(pid_t pid, funcs_t* funcs, size_t num);
extern void arch_bfdDisasm(pid_t pid, uint8_t* mem, size_t size, char* instr);

#endif
