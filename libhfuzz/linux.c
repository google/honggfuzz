#include "libcommon/common.h"
#include "libhfuzz.h"

#include "libcommon/files.h"
#include "libcommon/log.h"
#include "libcommon/ns.h"

#if defined(_HF_ARCH_LINUX)

bool linuxEnterNs(uintptr_t cloneFlags) { return nsEnter(cloneFlags); }

bool linuxIfaceUp(const char* ifacename) { return nsIfaceUp(ifacename); }

bool linuxMountTmpfs(const char* dst) { return nsMountTmpfs(dst); }

#endif /* defined(_HF_ARCH_LINUX) */
