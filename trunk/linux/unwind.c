/*
 * 
 * honggfuzz - architecture dependent code (LINUX/UNWIND)
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

#include "common.h"
#include "linux/unwind.h"

#include <libunwind-ptrace.h>

#include "log.h"

size_t arch_unwindStack(pid_t pid, funcs_t * funcs)
{
    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!as) {
        LOGMSG(l_ERROR, "unw_create_addr_space() failed");
        return 0U;
    }

    void *ui = _UPT_create(pid);
    if (ui == NULL) {
        LOGMSG(l_ERROR, "_UPT_create(%d) failed", pid);
        return 0U;
    }

    unw_cursor_t c;
    if (unw_init_remote(&c, as, ui) != 0) {
        LOGMSG(l_ERROR, "unw_init_remote() failed");
        return 0U;
    }

    size_t ret = 0;
    for (ret = 0; unw_step(&c) > 0; ret++) {
        unw_word_t ip;
        unw_get_reg(&c, UNW_REG_IP, &ip);
        funcs[ret].pc = (void *)ip;
    }

    unw_destroy_addr_space(as);
    _UPT_destroy(ui);

    return ret;
}
