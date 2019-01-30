/*
 *
 *   honggfuzz - logging
 *   -----------------------------------------
 *
 *   Copyright 2014 Google Inc. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#ifndef _HF_COMMON_LOG_H_
#define _HF_COMMON_LOG_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

enum llevel_t { FATAL = 0, ERROR, WARNING, INFO, DEBUG, HELP, HELP_BOLD };

extern enum llevel_t log_level;

#define LOG_HELP(...) logLog(HELP, __FUNCTION__, __LINE__, false, __VA_ARGS__);
#define LOG_HELP_BOLD(...) logLog(HELP_BOLD, __FUNCTION__, __LINE__, false, __VA_ARGS__);

#define LOG_D(...)                                                 \
    if (log_level >= DEBUG) {                                      \
        logLog(DEBUG, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_I(...)                                                \
    if (log_level >= INFO) {                                      \
        logLog(INFO, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_W(...)                                                   \
    if (log_level >= WARNING) {                                      \
        logLog(WARNING, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_E(...)                                                 \
    if (log_level >= ERROR) {                                      \
        logLog(ERROR, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    }
#define LOG_F(...)                                             \
    logLog(FATAL, __FUNCTION__, __LINE__, false, __VA_ARGS__); \
    exit(EXIT_FAILURE);

#define PLOG_D(...)                                               \
    if (log_level >= DEBUG) {                                     \
        logLog(DEBUG, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_I(...)                                              \
    if (log_level >= INFO) {                                     \
        logLog(INFO, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_W(...)                                                 \
    if (log_level >= WARNING) {                                     \
        logLog(WARNING, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_E(...)                                               \
    if (log_level >= ERROR) {                                     \
        logLog(ERROR, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    }
#define PLOG_F(...)                                           \
    logLog(FATAL, __FUNCTION__, __LINE__, true, __VA_ARGS__); \
    exit(EXIT_FAILURE);

extern void logInitLogFile(const char* logfile, int fd, enum llevel_t ll);

extern void logLog(enum llevel_t ll, const char* fn, int ln, bool perr, const char* fmt, ...)
    __attribute__((format(printf, 5, 6)));

extern void logStop(int sig);

extern bool logIsTTY(void);

extern void logRedirectLogFD(int fd);

extern int logFd(void);

extern enum llevel_t logGetLevel(void);

extern pthread_mutex_t* logMutexGet(void);

void logMutexReset(void);

#endif /* ifndef _HF_COMMON_LOG_H_ */
