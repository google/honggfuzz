/*

   honggfuzz - utilities
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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>

extern void util_rndInit(void);

extern uint32_t util_rndGet(uint32_t min, uint32_t max);

extern void util_getLocalTime(const char *fmt, char *buf, size_t len);

extern void util_nullifyStdio(void);

extern bool util_redirectStdin(char *inputFile);

extern void util_recoverStdio(void);

extern uint64_t util_hash(const char *buf, size_t len);

#endif
