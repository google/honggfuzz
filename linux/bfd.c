/*
 *
 * honggfuzz - architecture dependent code (LINUX/BFD)
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
#include "linux/bfd.h"

#include <bfd.h>
#include <dis-asm.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "files.h"
#include "log.h"
#include "util.h"

typedef struct {
    bfd *bfdh;
    asection *section;
    asymbol **syms;
} bfd_t;

static bool arch_bfdInit(pid_t pid, bfd_t * bfdParams)
{
    bfd_init();

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/exe", pid);
    if ((bfdParams->bfdh = bfd_openr(fname, 0)) == NULL) {
        LOGMSG(l_ERROR, "bfd_openr(%s) failed", fname);
        return false;
    }

    if (!bfd_check_format(bfdParams->bfdh, bfd_object)) {
        LOGMSG(l_ERROR, "bfd_check_format() failed");
        return false;
    }

    int storage_needed = bfd_get_symtab_upper_bound(bfdParams->bfdh);
    if (storage_needed <= 0) {
        LOGMSG(l_ERROR, "bfd_get_symtab_upper_bound() returned '%d'", storage_needed);
        return false;
    }

    if ((bfdParams->syms = (asymbol **) malloc(storage_needed)) == NULL) {
        LOGMSG_P(l_ERROR, "malloc(%d) failed", storage_needed);
        return false;
    }
    bfd_canonicalize_symtab(bfdParams->bfdh, bfdParams->syms);

    if ((bfdParams->section = bfd_get_section_by_name(bfdParams->bfdh, ".text")) == NULL) {
        LOGMSG(l_ERROR, "bfd_get_section_by_name('.text') failed");
        return false;
    }

    return true;
}

static void arch_bfdDestroy(bfd_t * bfdParams)
{
    if (bfdParams->syms) {
        free(bfdParams->syms);
    }
    if (bfdParams->bfdh) {
        bfd_close(bfdParams->bfdh);
    }
    return;
}

void arch_bfdResolveSyms(pid_t pid, funcs_t * funcs, size_t num)
{
    bfd_t bfdParams = {
        .bfdh = NULL,
        .section = NULL,
        .syms = NULL,
    };

    if (arch_bfdInit(pid, &bfdParams) == false) {
        arch_bfdDestroy(&bfdParams);
        return;
    }

    const char *func;
    const char *file;
    unsigned int line;
    for (unsigned int i = 0; i < num; i++) {
        snprintf(funcs[i].func, sizeof(funcs->func), "[UNKNOWN]");
        if (funcs[i].pc == NULL) {
            continue;
        }
        long offset = (long)funcs[i].pc - bfdParams.section->vma;
        if ((offset < 0 || (unsigned long)offset > bfdParams.section->size)) {
            continue;
        }
        if (bfd_find_nearest_line
            (bfdParams.bfdh, bfdParams.section, bfdParams.syms, offset, &file, &func, &line)) {
            snprintf(funcs[i].func, sizeof(funcs->func), "%s", func);
            funcs[i].line = line;
        }
    }

    arch_bfdDestroy(&bfdParams);
    return;
}

static int arch_bfdFPrintF(void *buf, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int ret = util_vssnprintf(buf, _HF_INSTR_SZ, fmt, args);
    va_end(args);

    return ret;
}

void arch_bfdDisasm(pid_t pid, uint8_t * mem, size_t size, char *instr)
{
    bfd_init();

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/exe", pid);
    bfd *bfdh = bfd_openr(fname, NULL);
    if (bfdh == NULL) {
        LOGMSG(l_WARN, "bfd_openr('/proc/%d/exe') failed", pid);
        return;
    }

    if (!bfd_check_format(bfdh, bfd_object)) {
        LOGMSG(l_WARN, "bfd_check_format() failed");
        bfd_close(bfdh);
        return;
    }

    disassembler_ftype disassemble = disassembler(bfdh);
    if (disassemble == NULL) {
        LOGMSG(l_WARN, "disassembler() failed");
        bfd_close(bfdh);
        return;
    }

    struct disassemble_info info;
    init_disassemble_info(&info, instr, arch_bfdFPrintF);
    info.arch = bfd_get_arch(bfdh);
    info.mach = bfd_get_mach(bfdh);
    info.buffer = mem;
    info.buffer_length = size;
    info.section = NULL;
    disassemble_init_for_target(&info);

    strcpy(instr, "");
    if (disassemble(0, &info) <= 0) {
        snprintf(instr, _HF_INSTR_SZ, "[UNKNOWN]");
    }
    bfd_close(bfdh);
    return;
}
