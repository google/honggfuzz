/*
 *
 * honggfuzz - architecture dependent code (LINUX/UNWIND)
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

#include "linux/unwind.h"

#include <endian.h>
#include <libunwind-ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/log.h"

/*
 * WARNING: Ensure that _UPT-info structs are not shared between threads
 * http://www.nongnu.org/libunwind/man/libunwind-ptrace(3).html
 */

// libunwind error codes used for debugging
static const char* UNW_ER[] = {
    "UNW_ESUCCESS",     /* no error */
    "UNW_EUNSPEC",      /* unspecified (general) error */
    "UNW_ENOMEM",       /* out of memory */
    "UNW_EBADREG",      /* bad register number */
    "UNW_EREADONLYREG", /* attempt to write read-only register */
    "UNW_ESTOPUNWIND",  /* stop unwinding */
    "UNW_EINVALIDIP",   /* invalid IP */
    "UNW_EBADFRAME",    /* bad frame */
    "UNW_EINVAL",       /* unsupported operation or bad value */
    "UNW_EBADVERSION",  /* unwind info has unsupported version */
    "UNW_ENOINFO"       /* no unwind info found */
};

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[6];
    unsigned long offset;
    char dev[8];
    unsigned long inode;
    char name[PATH_MAX];
} procMap_t;

static procMap_t* arch_parsePidMaps(pid_t pid, size_t* mapsCount) {
    FILE* f = NULL;
    char fProcMaps[PATH_MAX] = {0};
    snprintf(fProcMaps, PATH_MAX, "/proc/%d/maps", pid);

    if ((f = fopen(fProcMaps, "rb")) == NULL) {
        PLOG_E("Couldn't open '%s' - R/O mode", fProcMaps);
        return 0;
    }
    defer {
        fclose(f);
    };

    *mapsCount = 0;
    procMap_t* mapsList = malloc(sizeof(procMap_t));
    if (mapsList == NULL) {
        PLOG_W("malloc(size='%zu')", sizeof(procMap_t));
        return NULL;
    }

    while (!feof(f)) {
        char buf[sizeof(procMap_t) + 1];
        if (fgets(buf, sizeof(buf), f) == 0) {
            break;
        }

        mapsList[*mapsCount].name[0] = '\0';
        sscanf(buf, "%lx-%lx %5s %lx %7s %ld %s", &mapsList[*mapsCount].start,
            &mapsList[*mapsCount].end, mapsList[*mapsCount].perms, &mapsList[*mapsCount].offset,
            mapsList[*mapsCount].dev, &mapsList[*mapsCount].inode, mapsList[*mapsCount].name);

        *mapsCount += 1;
        if ((mapsList = realloc(mapsList, (*mapsCount + 1) * sizeof(procMap_t))) == NULL) {
            PLOG_W("realloc failed (sz=%zu)", (*mapsCount + 1) * sizeof(procMap_t));
            free(mapsList);
            return NULL;
        }
    }

    return mapsList;
}

static char* arch_searchMaps(unsigned long addr, size_t mapsCnt, procMap_t* mapsList) {
    for (size_t i = 0; i < mapsCnt; i++) {
        if (addr >= mapsList[i].start && addr <= mapsList[i].end) {
            return mapsList[i].name;
        }

        /* Benefit from maps being sorted by address */
        if (addr < mapsList[i].start) {
            break;
        }
    }
    return NULL;
}

#ifndef __ANDROID__
size_t arch_unwindStack(pid_t pid, funcs_t* funcs) {
    size_t num_frames = 0, mapsCnt = 0;
    procMap_t* mapsList = arch_parsePidMaps(pid, &mapsCnt);
    defer {
        free(mapsList);
    };

    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!as) {
        LOG_E("[pid='%d'] unw_create_addr_space failed", pid);
        return num_frames;
    }
    defer {
        unw_destroy_addr_space(as);
    };

    void* ui = _UPT_create(pid);
    if (ui == NULL) {
        LOG_E("[pid='%d'] _UPT_create failed", pid);
        return num_frames;
    }
    defer {
        _UPT_destroy(ui);
    };

    unw_cursor_t c;
    int ret = unw_init_remote(&c, as, ui);
    if (ret < 0) {
        LOG_E("[pid='%d'] unw_init_remote failed (%s)", pid, UNW_ER[-ret]);
        return num_frames;
    }

    for (num_frames = 0; unw_step(&c) > 0 && num_frames < _HF_MAX_FUNCS; num_frames++) {
        unw_word_t ip;
        char* mapName = NULL;
        ret = unw_get_reg(&c, UNW_REG_IP, &ip);
        if (ret < 0) {
            LOG_E("[pid='%d'] [%zd] failed to read IP (%s)", pid, num_frames, UNW_ER[-ret]);
            funcs[num_frames].pc = 0;
        } else {
            funcs[num_frames].pc = (void*)(uintptr_t)ip;
        }
        if (mapsCnt > 0 && (mapName = arch_searchMaps(ip, mapsCnt, mapsList)) != NULL) {
            memcpy(funcs[num_frames].mapName, mapName, sizeof(funcs[num_frames].mapName));
        } else {
            strncpy(funcs[num_frames].mapName, "UNKNOWN", sizeof(funcs[num_frames].mapName));
        }
    }

    return num_frames;
}

#else  /* !defined(__ANDROID__) */
size_t arch_unwindStack(pid_t pid, funcs_t* funcs) {
    size_t num_frames = 0, mapsCnt = 0;
    procMap_t* mapsList = arch_parsePidMaps(pid, &mapsCnt);
    defer {
        free(mapsList);
    };

    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER);
    if (!as) {
        LOG_E("[pid='%d'] unw_create_addr_space failed", pid);
        return num_frames;
    }
    defer {
        unw_destroy_addr_space(as);
    };

    struct UPT_info* ui = (struct UPT_info*)_UPT_create(pid);
    if (ui == NULL) {
        LOG_E("[pid='%d'] _UPT_create failed", pid);
        return num_frames;
    }
    defer {
        _UPT_destroy(ui);
    };

    unw_cursor_t cursor;
    int ret = unw_init_remote(&cursor, as, ui);
    if (ret < 0) {
        LOG_E("[pid='%d'] unw_init_remote failed (%s)", pid, UNW_ER[-ret]);
        return num_frames;
    }

    do {
        char* mapName = NULL;
        unw_word_t pc = 0, offset = 0;
        char buf[_HF_FUNC_NAME_SZ] = {0};

        ret = unw_get_reg(&cursor, UNW_REG_IP, &pc);
        if (ret < 0) {
            LOG_E("[pid='%d'] [%zd] failed to read IP (%s)", pid, num_frames, UNW_ER[-ret]);
            // We don't want to try to extract info from an arbitrary IP
            // TODO: Maybe abort completely (goto out))
            goto skip_frame_info;
        }

        unw_proc_info_t frameInfo;
        ret = unw_get_proc_info(&cursor, &frameInfo);
        if (ret < 0) {
            LOG_D("[pid='%d'] [%zd] unw_get_proc_info (%s)", pid, num_frames, UNW_ER[-ret]);
            // Not safe to keep parsing frameInfo
            goto skip_frame_info;
        }

        ret = unw_get_proc_name(&cursor, buf, sizeof(buf), &offset);
        if (ret < 0) {
            LOG_D(
                "[pid='%d'] [%zd] unw_get_proc_name() failed (%s)", pid, num_frames, UNW_ER[-ret]);
            buf[0] = '\0';
        }

    skip_frame_info:
        // Compared to bfd, line var plays the role of offset from func_name
        // Reports format is adjusted accordingly to reflect in saved file
        funcs[num_frames].line = offset;
        funcs[num_frames].pc = (void*)pc;
        memcpy(funcs[num_frames].func, buf, sizeof(funcs[num_frames].func));
        if (mapsCnt > 0 && (mapName = arch_searchMaps(pc, mapsCnt, mapsList)) != NULL) {
            memcpy(funcs[num_frames].mapName, mapName, sizeof(funcs[num_frames].mapName));
        } else {
            strncpy(funcs[num_frames].mapName, "UNKNOWN", sizeof(funcs[num_frames].mapName));
        }

        num_frames++;

        ret = unw_step(&cursor);
    } while (ret > 0 && num_frames < _HF_MAX_FUNCS);

    return num_frames;
}
#endif /* defined(__ANDROID__) */

/*
 * Nested loop not most efficient approach, although it's assumed that list is
 * usually target specific and thus small.
 */
char* arch_btContainsSymbol(
    size_t symbolsListSz, char** symbolsList, size_t num_frames, funcs_t* funcs) {
    for (size_t frame = 0; frame < num_frames; frame++) {
        size_t len = strlen(funcs[frame].func);

        /* Try only for frames that have symbol name from backtrace */
        if (strlen(funcs[frame].func) > 0) {
            for (size_t i = 0; i < symbolsListSz; i++) {
                /* Wildcard symbol string special case */
                char* wOff = strchr(symbolsList[i], '*');
                if (wOff) {
                    /* Length always > 3 as checked at input file parsing step */
                    len = wOff - symbolsList[i] - 1;
                }

                if (strncmp(funcs[frame].func, symbolsList[i], len) == 0) {
                    return funcs[frame].func;
                }
            }
        }
    }
    return NULL;
}
