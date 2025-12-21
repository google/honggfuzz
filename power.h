/*
 *
 * honggfuzz - power schedule calculation
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2025 by Google Inc. All Rights Reserved.
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

#ifndef _HF_POWER_H_
#define _HF_POWER_H_

#include "honggfuzz.h"

/* The baseline energy level. Input with this energy will be fuzzed exactly once. */
#define POWER_BASE_ENERGY 256

extern uint64_t power_calculateEnergy(run_t* run, dynfile_t* dynfile);

#endif /* _HF_POWER_H_ */
