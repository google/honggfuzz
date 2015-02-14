/*

   honggfuzz - architecture dependent code (LINUX/BFD)
   -----------------------------------------

   Author: Robert Swiecki <swiecki@google.com>

   Copyright 2010-2015 by Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include "common.h"
#include "linux/bfd.h"

#include <bfd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "files.h"
#include "log.h"
#include "util.h"

static bool arch_bfdInit(pid_t pid, bfd ** bfdh, asection ** section, asymbol *** syms)
{
    bfd_init();

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/exe", pid);

    *bfdh = bfd_openr(fname, 0);
    if (*bfdh == NULL) {
        LOGMSG(l_ERROR, "bfd_openr(%s) failed", fname);
        return false;
    }

    if (!bfd_check_format(*bfdh, bfd_object)) {
        LOGMSG(l_ERROR, "bfd_check_format() failed");
        return false;
    }

    int storage_needed = bfd_get_symtab_upper_bound(*bfdh);
    if (storage_needed <= 0) {
        LOGMSG(l_ERROR, "bfd_get_symtab_upper_bound() returned '%d'", storage_needed);
        return false;
    }

    *syms = (asymbol **) malloc(storage_needed);
    if (*syms == NULL) {
        LOGMSG_P(l_ERROR, "malloc(%d) failed", storage_needed);
        return false;
    }
    bfd_canonicalize_symtab(*bfdh, *syms);

    *section = bfd_get_section_by_name(*bfdh, ".text");
    if (*section == NULL) {
        LOGMSG(l_ERROR, "bfd_get_section_by_name('.text') failed");
        return false;
    }

    return true;
}

static void arch_bfdDestroy(asymbol ** syms)
{
    if (syms) {
        free(syms);
    }
    return;
}

void arch_bfdResolveSyms(pid_t pid, funcs_t * funcs, size_t num)
{
    bfd *bfdh = NULL;
    asection *section = NULL;
    asymbol **syms = NULL;

    if (arch_bfdInit(pid, &bfdh, &section, &syms)) {
        arch_bfdDestroy(syms);
    }

    const char *func;
    const char *file;
    unsigned int line;
    for (unsigned int i = 0; i < num; i++) {
        snprintf(funcs[i].func, sizeof(funcs->func), "[UNKNOWN]");
        if (funcs[i].pc == NULL) {
            continue;
        }
        long offset = (long)funcs[i].pc - section->vma;
        if ((offset < 0 || (unsigned long)offset > section->size)) {
            continue;
        }
        if (bfd_find_nearest_line(bfdh, section, syms, offset, &file, &func, &line)) {
            snprintf(funcs[i].func, sizeof(funcs->func), "%s", func);
        }
    }

    arch_bfdDestroy(syms);
}
