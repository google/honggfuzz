/*
 *
 * honggfuzz - sanitizer coverage feedback parsing
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

#ifndef _HF_SANCOV_H_
#define _HF_SANCOV_H_

#include "honggfuzz.h"

/* Bitmap size */
#define _HF_SANCOV_BITMAP_SIZE 0x3FFFFFF

extern void sancov_Analyze(run_t* run);

extern bool sancov_Init(honggfuzz_t* hfuzz);

#endif /* _HF_SANCOV_H_ */
