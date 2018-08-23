/*
 *
 * honggfuzz - sanitizers configuration
 * -----------------------------------------------
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

#ifndef _HF_SANITIZERS_H_
#define _HF_SANITIZERS_H_

#include "honggfuzz.h"

/* Exit code is common for all sanitizers */
#define HF_SAN_EXIT_CODE 103

/* Prefix for sanitizer report files */
#define kLOGPREFIX "HF.sanitizer.log"

extern bool sanitizers_Init(honggfuzz_t* hfuzz);

#endif /* _HF_SANITIZERS_H_ */
