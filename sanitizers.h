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

#include <stdbool.h>
#include <stdint.h>

#include "honggfuzz.h"
#include "libhfcommon/util.h"

/* Prefix for sanitizer report files */
#define kLOGPREFIX "HF.sanitizer.log"

/* String buffer size for function names in stack traces produced from libunwind */
#define _HF_FUNC_NAME_SZ         256    // Should be alright for mangled C++ procs too
#define _HF_FUNC_NAME_SZ_MINUS_1 255    // For scanf()
#define _HF_MAX_FUNCS            80

/* Constant prefix used for single frame crashes stackhash masking */
#define _HF_SINGLE_FRAME_MASK 0xBADBAD0000000000

typedef struct {
    void* pc;

    /* If ASan custom parsing, function not available without symbolication */
    char func[_HF_FUNC_NAME_SZ];

    /*
     * If libuwind proc maps is used to retrieve map name
     * If ASan custom parsing it's retrieved from generated report file
     */
    char module[HF_STR_LEN];

    /*
     * Original source file
     */
    char file[HF_STR_LEN];

    /*
     * If libunwind + bfd symbolizer, line is actual symbol file line
     * If libunwind + custom (e.g. Android), line is offset from function symbol
     * If ASan custom parsing, line is offset from matching map load base address
     */
    size_t line;
} funcs_t;

extern bool     sanitizers_Init(honggfuzz_t* hfuzz);
extern size_t   sanitizers_parseReport(run_t* run, pid_t pid, funcs_t* funcs, uint64_t* pc,
      uint64_t* crashAddr, char description[HF_STR_LEN]);
extern uint64_t sanitizers_hashCallstack(
    run_t* run, funcs_t* funcs, size_t funcCnt, bool enableMasking);

#endif /* _HF_SANITIZERS_H_ */
