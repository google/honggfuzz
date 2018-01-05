#include "libhfcommon/common.h"
#include "libhfuzz.h"

#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"

#if defined(_HF_ARCH_LINUX)

bool linuxEnterNs(uintptr_t cloneFlags) { return nsEnter(cloneFlags); }

bool linuxIfaceUp(const char* ifacename) { return nsIfaceUp(ifacename); }

bool linuxMountTmpfs(const char* dst) { return nsMountTmpfs(dst); }

#endif /* defined(_HF_ARCH_LINUX) */
