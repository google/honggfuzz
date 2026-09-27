/* Native Apple Silicon crash reporting. */
#ifndef HF_MAC_ARM64_H
#define HF_MAC_ARM64_H

#include <spawn.h>

#include "honggfuzz.h"
#include "sanitizers.h"

typedef struct mac_crash {
    pid_t             pid;
    int               signo;
    uint64_t          pc, address, hash, pcOffset;
    size_t            frameCount;
    funcs_t           frames[_HF_MAX_FUNCS];
    char              description[HF_STR_LEN];
    char              registers[4096];
    struct mac_image* images;
    size_t            imageCount;
    struct mac_crash* next;
} mac_crash_t;

bool         mac_arm64Init(size_t workers);
pid_t        mac_arm64Fork(void);
bool         mac_arm64Spawn(posix_spawnattr_t* attrs);
mac_crash_t* mac_arm64TakeCrash(pid_t pid);

#endif
