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
#define kLOGPREFIX          "HF.sanitizer.log"

/* Bitmap size */
#define _HF_SANCOV_BITMAP_SIZE 0x3FFFFFF

/* Directory in workspace to store sanitizer coverage data */
#define _HF_SANCOV_DIR "HF_SANCOV"

extern void sancov_Analyze(honggfuzz_t * hfuzz, fuzzer_t * fuzzer);
extern bool sancov_Init(honggfuzz_t * hfuzz);
extern bool sancov_prepareExecve(honggfuzz_t * hfuzz);

#endif                          /* _HF_SANCOV_H_ */
