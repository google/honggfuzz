/*
 *
 * honggfuzz - architecture dependent code (LINUX/BFD)
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

#if !defined(_HF_LINUX_NO_BFD)

#include "linux/bfd.h"

#include <bfd.h>
#include <dis-asm.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#if !defined(bfd_get_section_size)
#define bfd_get_section_size(section) bfd_section_size(section)
#endif /* !defined(bfd_get_section_size) */
#if !defined(bfd_get_section_vma)
#define bfd_get_section_vma(ptr, section) bfd_section_vma(section)
#endif /* !defined(bfd_get_section_size) */

typedef struct {
    bfd*      bfdh;
    asymbol** syms;
    asymbol** dsyms;
} bfd_t;

/* INFO: binutils (libbfd, libopcode) has an unstable public interface. */
/*
 * This is probably the only define which was added with binutils 2.29, so we use
 * it, do decide which disassembler() prototype from dis-asm.h to use.
 */
#if defined(FOR_EACH_DISASSEMBLER_OPTION)
#define _HF_BFD_GE_2_29
#endif /* defined(FOR_EACH_DISASSEMBLER_OPTION) */

static pthread_mutex_t arch_bfd_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool arch_bfdInit(pid_t pid, bfd_t* bfdParams) {
    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/exe", pid);
    if ((bfdParams->bfdh = bfd_openr(fname, 0)) == NULL) {
        LOG_E("bfd_openr(%s) failed", fname);
        return false;
    }

    if (!bfd_check_format(bfdParams->bfdh, bfd_object)) {
        LOG_E("bfd_check_format() failed");
        return false;
    }

    int storage_needed = bfd_get_symtab_upper_bound(bfdParams->bfdh);
    if (storage_needed <= 0) {
        LOG_E("bfd_get_symtab_upper_bound() returned '%d'", storage_needed);
        return false;
    }
    bfdParams->syms = (asymbol**)util_Calloc(storage_needed);
    bfd_canonicalize_symtab(bfdParams->bfdh, bfdParams->syms);

    storage_needed = bfd_get_dynamic_symtab_upper_bound(bfdParams->bfdh);
    if (storage_needed <= 0) {
        LOG_E("bfd_get_dynamic_symtab_upper_bound() returned '%d'", storage_needed);
        return false;
    }
    bfdParams->dsyms = (asymbol**)util_Calloc(storage_needed);
    bfd_canonicalize_dynamic_symtab(bfdParams->bfdh, bfdParams->dsyms);

    return true;
}

static void arch_bfdDestroy(bfd_t* bfdParams) {
    if (bfdParams->syms) {
        free(bfdParams->syms);
        bfdParams->syms = NULL;
    }
    if (bfdParams->dsyms) {
        free(bfdParams->dsyms);
        bfdParams->dsyms = NULL;
    }
    if (bfdParams->bfdh) {
        bfd_close(bfdParams->bfdh);
        bfdParams->bfdh = NULL;
    }
}

void arch_bfdDemangle(funcs_t* funcs, size_t funcCnt) {
    /* From -liberty, should be depended on by (included with) libbfd */
    __attribute__((weak)) char* cplus_demangle(const char* mangled, int options);
    if (!cplus_demangle) {
        return;
    }
    for (size_t i = 0; i < funcCnt; i++) {
        if (strncmp(funcs[i].func, "_Z", 2) == 0) {
            char* new_name = cplus_demangle(funcs[i].func, 0);
            if (new_name) {
                snprintf(funcs[i].func, sizeof(funcs[i].func), "%s", new_name);
                free(new_name);
            }
        }
    }
}

static struct bfd_section* arch_getSectionForPc(bfd* bfdh, uint64_t pc) {
    for (struct bfd_section* section = bfdh->sections; section; section = section->next) {
        uintptr_t vma = (uintptr_t)bfd_get_section_vma(bfdh, section);
        uintptr_t sz  = (uintptr_t)bfd_get_section_size(section);
        if ((pc > vma) && (pc < (vma + sz))) {
            return section;
        }
    }
    return NULL;
}

void arch_bfdResolveSyms(pid_t pid, funcs_t* funcs, size_t num) {
    /* Guess what? libbfd is not multi-threading safe */
    MX_SCOPED_LOCK(&arch_bfd_mutex);

    bfd_init();

    bfd_t bfdParams = {
        .bfdh  = NULL,
        .syms  = NULL,
        .dsyms = NULL,
    };

    if (!arch_bfdInit(pid, &bfdParams)) {
        return;
    }

    const char*  func;
    const char*  file;
    unsigned int line;
    for (unsigned int i = 0; i < num; i++) {
        snprintf(funcs[i].func, sizeof(funcs->func), "UNKNOWN");
        if (funcs[i].pc == NULL) {
            continue;
        }
        struct bfd_section* section = arch_getSectionForPc(bfdParams.bfdh, (uintptr_t)funcs[i].pc);
        if (section == NULL) {
            continue;
        }

        long sec_offset = (long)funcs[i].pc - bfd_get_section_vma(bfdParams.bfdh, section);

        if (bfd_find_nearest_line(
                bfdParams.bfdh, section, bfdParams.syms, sec_offset, &file, &func, &line) == TRUE) {
            snprintf(funcs[i].func, sizeof(funcs->func), "%s", func ? func : "");
            snprintf(funcs[i].file, sizeof(funcs->file), "%s", file ? file : "");
            funcs[i].line = line;
        }
        if (bfd_find_nearest_line(
                bfdParams.bfdh, section, bfdParams.syms, sec_offset, &file, &func, &line) == TRUE) {
            snprintf(funcs[i].func, sizeof(funcs->func), "%s", func ? func : "");
            snprintf(funcs[i].file, sizeof(funcs->file), "%s", file ? file : "");
            funcs[i].line = line;
        }
    }

    arch_bfdDestroy(&bfdParams);
}

static int arch_bfdFPrintF(void* buf, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = util_vssnprintf(buf, _HF_INSTR_SZ, fmt, args);
    va_end(args);

    return ret;
}

/*
 * The 'disassembler_style' is defined with newert dis-asm.h versions only. Use a fake identifier,
 * just to be able to define a function pointer.
 */
enum fake_disassembler_style {
    hf_fake_dis_asm_style_unused,
};
static int arch_bfdFPrintFStyled(
    void* buf, enum fake_disassembler_style style HF_ATTR_UNUSED, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = util_vssnprintf(buf, _HF_INSTR_SZ, fmt, args);
    va_end(args);

    return ret;
}

void arch_bfdDisasm(pid_t pid, uint8_t* mem, size_t size, char* instr) {
    MX_SCOPED_LOCK(&arch_bfd_mutex);

    bfd_init();

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "/proc/%d/exe", pid);
    bfd* bfdh = bfd_openr(fname, NULL);
    if (bfdh == NULL) {
        LOG_W("bfd_openr('/proc/%d/exe') failed", pid);
        return;
    }

    if (!bfd_check_format(bfdh, bfd_object)) {
        LOG_W("bfd_check_format() failed");
        bfd_close(bfdh);
        return;
    }
#if defined(_HF_BFD_GE_2_29)
    disassembler_ftype disassemble =
        disassembler(bfd_get_arch(bfdh), bfd_little_endian(bfdh) ? FALSE : TRUE, 0, NULL);
#else
    disassembler_ftype disassemble = disassembler(bfdh);
#endif    // defined(_HD_BFD_GE_2_29)
    if (disassemble == NULL) {
        LOG_W("disassembler() failed");
        bfd_close(bfdh);
        return;
    }

    struct disassemble_info info = {};

    /*
     * At some point in time the function init_disassemble_info() started taking 4 arguments instead
     * of 3. Add the 4th argument in all cases. Hopefully it'll work will all ABIs, and the 4th
     * argument will be discarded if needed.
     */

    void (*idi_4_args)(void*, void*, void*, void*) = (void*)init_disassemble_info;
    idi_4_args(&info, instr, arch_bfdFPrintF, arch_bfdFPrintFStyled);
    info.arch          = bfd_get_arch(bfdh);
    info.mach          = bfd_get_mach(bfdh);
    info.buffer        = mem;
    info.buffer_length = size;
    info.section       = NULL;
    info.endian        = bfd_little_endian(bfdh) ? BFD_ENDIAN_LITTLE : BFD_ENDIAN_BIG;
    disassemble_init_for_target(&info);

    strcpy(instr, "");
    if (disassemble(0, &info) <= 0) {
        snprintf(instr, _HF_INSTR_SZ, "[DIS-ASM_FAILURE]");
    }

    /* disassemble_free_target is available only since bfd/dis-asm 2019 */
    __attribute__((weak)) void disassemble_free_target(struct disassemble_info*);
    if (disassemble_free_target) {
        disassemble_free_target(&info);
    }
    bfd_close(bfdh);
}

#endif /*  !defined(_HF_LINUX_NO_BFD)  */
