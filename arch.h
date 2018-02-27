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

#ifndef _HF_ARCH_H_
#define _HF_ARCH_H_

#include "honggfuzz.h"

extern bool arch_launchChild(run_t* run);

extern bool arch_archInit(honggfuzz_t* fuzz);

extern bool arch_archThreadInit(run_t* run);

extern pid_t arch_fork(run_t* run);

extern void arch_reapChild(run_t* run);

extern void arch_prepareParent(run_t* run);

extern void arch_prepareParentAfterFork(run_t* run);

#endif /* _HF_ARCH_H_ */
