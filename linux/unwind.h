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

#ifndef _HF_LINUX_UNWIND_H_
#define _HF_LINUX_UNWIND_H_

#include <linux/limits.h>
#include <sys/types.h>

/* String buffer size for function names in stack traces produced from libunwind */
#define _HF_FUNC_NAME_SZ 256  // Should be alright for mangled C++ procs too

#define _HF_MAX_FUNCS 80
typedef struct {
    void* pc;

    /* If ASan custom parsing, function not available without symbolication */
    char func[_HF_FUNC_NAME_SZ];

    /*
     * If libuwind proc maps is used to retrieve map name
     * If ASan custom parsing it's retrieved from generated report file
     */
    char mapName[PATH_MAX];

    /*
     * If libunwind + bfd symbolizer, line is actual symbol file line
     * If libunwind + custom (e.g. Android), line is offset from function symbol
     * If ASan custom parsing, line is offset from matching map load base address
     */
    size_t line;
} funcs_t;

extern size_t arch_unwindStack(pid_t pid, funcs_t* funcs);
extern char* arch_btContainsSymbol(
    size_t symbolsListSz, char** symbolsList, size_t num_frames, funcs_t* funcs);

#endif
