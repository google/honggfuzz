/*
 *
 * honggfuzz - routines dealing with subprocesses
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
 * Felix Gröbert <groebert@google.com>
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

#include "common.h"
#include "subproc.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "log.h"

const char *subproc_StatusToStr(int status, char *str, size_t len)
{
    if (WIFEXITED(status)) {
        snprintf(str, len, "EXITED, exit code: %d", WEXITSTATUS(status));
        return str;
    }

    if (WIFSIGNALED(status)) {
        snprintf(str, len, "SIGNALED, signal: %d (%s)", WTERMSIG(status),
                 strsignal(WTERMSIG(status)));
        return str;
    }
    if (WIFCONTINUED(status)) {
        snprintf(str, len, "CONTINUED");
        return str;
    }

    if (!WIFSTOPPED(status)) {
        snprintf(str, len, "UNKNOWN STATUS: %d", status);
        return str;
    }

    /* Must be in a stopped state */
    if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        snprintf(str, len, "STOPPED (linux syscall): %d (%s)", WSTOPSIG(status),
                 strsignal(WSTOPSIG(status)));
        return str;
    }
#if defined(PTRACE_EVENT_STOP)
#define __LINUX_WPTRACEEVENT(x) ((x & 0xff0000) >> 16)
    if (WSTOPSIG(status) == SIGTRAP && __LINUX_WPTRACEEVENT(status) != 0) {
        switch (__LINUX_WPTRACEEVENT(status)) {
        case PTRACE_EVENT_FORK:
            snprintf(str, len, "EVENT (Linux) - fork - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_VFORK:
            snprintf(str, len, "EVENT (Linux) - vfork - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_CLONE:
            snprintf(str, len, "EVENT (Linux) - clone - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_EXEC:
            snprintf(str, len, "EVENT (Linux) - exec - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_VFORK_DONE:
            snprintf(str, len, "EVENT (Linux) - vfork_done - with signal: %d (%s)",
                     WSTOPSIG(status), strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_EXIT:
            snprintf(str, len, "EVENT (Linux) - exit - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_SECCOMP:
            snprintf(str, len, "EVENT (Linux) - seccomp - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        case PTRACE_EVENT_STOP:
            snprintf(str, len, "EVENT (Linux) - stop - with signal: %d (%s)", WSTOPSIG(status),
                     strsignal(WSTOPSIG(status)));
            return str;
        default:
            snprintf(str, len, "EVENT (Linux) UNKNOWN (%d): with signal: %d (%s)",
                     __LINUX_WPTRACEEVENT(status), WSTOPSIG(status), strsignal(WSTOPSIG(status)));
            return str;
        }
    }
#endif                          /*  defined(PTRACE_EVENT_STOP)  */

    snprintf(str, len, "STOPPED with signal: %d (%s)", WSTOPSIG(status),
             strsignal(WSTOPSIG(status)));
    return str;
}
