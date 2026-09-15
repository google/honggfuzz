/* SPDX-License-Identifier: Apache-2.0 */
#include "mac/exception.h"

#include <mach/exception_types.h>
#include <mach/kern_return.h>
#if defined(__arm64__)
#include <mach/arm/exception.h>
#endif

const char* mac_exceptionToString(int exception) {
    switch (exception) {
    case EXC_BAD_ACCESS:
        return "EXC_BAD_ACCESS";
    case EXC_BAD_INSTRUCTION:
        return "EXC_BAD_INSTRUCTION";
    case EXC_ARITHMETIC:
        return "EXC_ARITHMETIC";
    case EXC_EMULATION:
        return "EXC_EMULATION";
    case EXC_SOFTWARE:
        return "EXC_SOFTWARE";
    case EXC_BREAKPOINT:
        return "EXC_BREAKPOINT";
    case EXC_SYSCALL:
        return "EXC_SYSCALL";
    case EXC_MACH_SYSCALL:
        return "EXC_MACH_SYSCALL";
    case EXC_RPC_ALERT:
        return "EXC_RPC_ALERT";
    case EXC_CRASH:
        return "EXC_CRASH";
    case EXC_RESOURCE:
        return "EXC_RESOURCE";
    case EXC_GUARD:
        return "EXC_GUARD";
    case EXC_CORPSE_NOTIFY:
        return "EXC_CORPSE_NOTIFY";
    default:
        return "UNKNOWN";
    }
}

const char* mac_exceptionReason(int exception, uint64_t code) {
    switch (exception) {
    case EXC_BAD_ACCESS:
        switch (code) {
        case KERN_INVALID_ADDRESS:
            return "KERN_INVALID_ADDRESS";
        case KERN_PROTECTION_FAILURE:
            return "KERN_PROTECTION_FAILURE";
        case KERN_MEMORY_FAILURE:
            return "KERN_MEMORY_FAILURE";
        case KERN_MEMORY_ERROR:
            return "KERN_MEMORY_ERROR";
#if defined(KERN_CODESIGN_ERROR)
        case KERN_CODESIGN_ERROR:
            return "KERN_CODESIGN_ERROR";
#endif
#if defined(__arm64__)
        case EXC_ARM_DA_ALIGN:
            return "EXC_ARM_DA_ALIGN";
        case EXC_ARM_DA_DEBUG:
            return "EXC_ARM_DA_DEBUG";
        case EXC_ARM_SP_ALIGN:
            return "EXC_ARM_SP_ALIGN";
        case EXC_ARM_SWP:
            return "EXC_ARM_SWP";
#if defined(EXC_ARM_PAC_FAIL)
        case EXC_ARM_PAC_FAIL:
            return "EXC_ARM_PAC_FAIL";
#endif
#if defined(EXC_ARM_MTE_TAGCHECK_FAIL)
        case EXC_ARM_MTE_TAGCHECK_FAIL:
            return "EXC_ARM_MTE_TAGCHECK_FAIL";
#endif
#if defined(EXC_ARM_MTE_CANONICAL_FAIL)
        case EXC_ARM_MTE_CANONICAL_FAIL:
            return "EXC_ARM_MTE_CANONICAL_FAIL";
#endif
#endif
        }
        break;
#if defined(__arm64__)
    case EXC_BAD_INSTRUCTION:
        switch (code) {
        case EXC_ARM_UNDEFINED:
            return "EXC_ARM_UNDEFINED";
#if defined(EXC_ARM_SME_DISALLOWED)
        case EXC_ARM_SME_DISALLOWED:
            return "EXC_ARM_SME_DISALLOWED";
#endif
        }
        break;
    case EXC_ARITHMETIC:
        switch (code) {
        case EXC_ARM_FP_UNDEFINED:
            return "EXC_ARM_FP_UNDEFINED";
        case EXC_ARM_FP_IO:
            return "EXC_ARM_FP_IO";
        case EXC_ARM_FP_DZ:
            return "EXC_ARM_FP_DZ";
        case EXC_ARM_FP_OF:
            return "EXC_ARM_FP_OF";
        case EXC_ARM_FP_UF:
            return "EXC_ARM_FP_UF";
        case EXC_ARM_FP_IX:
            return "EXC_ARM_FP_IX";
        case EXC_ARM_FP_ID:
            return "EXC_ARM_FP_ID";
        }
        break;
    case EXC_BREAKPOINT:
        if (code == EXC_ARM_BREAKPOINT) return "EXC_ARM_BREAKPOINT";
        break;
#endif
    case EXC_SOFTWARE:
        if (code == EXC_SOFT_SIGNAL) return "EXC_SOFT_SIGNAL";
        break;
    }
    return "UNKNOWN";
}
