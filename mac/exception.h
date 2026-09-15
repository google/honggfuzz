/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HF_MAC_EXCEPTION_H
#define HF_MAC_EXCEPTION_H

#include <stdint.h>

const char* mac_exceptionToString(int exception);
const char* mac_exceptionReason(int exception, uint64_t code);

#endif
