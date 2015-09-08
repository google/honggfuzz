/*
 *
 * honggfuzz - log messages
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

#ifndef _LOG_H_
#define _LOG_H_

#include <pthread.h>

typedef enum {
    l_FATAL = 0, l_ERROR, l_WARN, l_INFO, l_DEBUG
} log_level_t;

extern void log_setMinLevel(log_level_t dl);

extern void log_msg(log_level_t dl, bool perr, const char *file, const char *func, int line,
                    const char *fmt, ...);

extern void log_mutexLock(void);
extern void log_mutexUnLock(void);

#define LOGMSG(ll, ...) log_msg(ll, false, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);
#define LOGMSG_P(ll, ...) log_msg(ll, true, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);

#endif
