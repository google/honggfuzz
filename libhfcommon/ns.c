/*
 *
 * honggfuzz - namespace-related utilities
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2017 by Google Inc. All Rights Reserved.
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

#include "libhfcommon/ns.h"

#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"

#if defined(_HF_ARCH_LINUX)

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

bool nsEnter(uintptr_t cloneFlags) {
    pid_t current_uid = getuid();
    gid_t current_gid = getgid();

    if (unshare(cloneFlags) == -1) {
        PLOG_E("unshare(0x%tx)", cloneFlags);
        if (cloneFlags | CLONE_NEWUSER) {
            LOG_W("Executing 'sysctl -w kernel.unprivileged_userns_clone=1' might help with this");
        }
        return false;
    }

    const char* deny_str = "deny";
    if (files_writeBufToFile("/proc/self/setgroups", (const uint8_t*)deny_str, strlen(deny_str),
            O_WRONLY) == false) {
        PLOG_E("Couldn't write to /proc/self/setgroups");
        return false;
    }

    char gid_map[4096];
    snprintf(gid_map, sizeof(gid_map), "%d %d 1", (int)current_gid, (int)current_gid);
    if (files_writeBufToFile(
            "/proc/self/gid_map", (const uint8_t*)gid_map, strlen(gid_map), O_WRONLY) == false) {
        PLOG_E("Couldn't write to /proc/self/gid_map");
        return false;
    }

    char uid_map[4096];
    snprintf(uid_map, sizeof(uid_map), "%d %d 1", (int)current_uid, (int)current_uid);
    if (files_writeBufToFile(
            "/proc/self/uid_map", (const uint8_t*)uid_map, strlen(uid_map), O_WRONLY) == false) {
        PLOG_E("Couldn't write to /proc/self/uid_map");
        return false;
    }

    if (setresgid(current_gid, current_gid, current_gid) == -1) {
        PLOG_E("setresgid(%d)", (int)current_gid);
        return false;
    }
    if (setresuid(current_uid, current_uid, current_uid) == -1) {
        PLOG_E("setresuid(%d)", (int)current_uid);
        return false;
    }

    return true;
}

bool nsIfaceUp(const char* ifacename) {
    int sock = socket(PF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (sock == -1) {
        if ((sock = socket(PF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)) == -1) {
            PLOG_E("socket(PF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP)");
            return false;
        }
    }

    struct ifreq ifr;
    memset(&ifr, '\0', sizeof(ifr));
    snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifacename);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
        PLOG_E("ioctl(iface='%s', SIOCGIFFLAGS, IFF_UP)", ifacename);
        close(sock);
        return false;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        PLOG_E("ioctl(iface='%s', SIOCGIFFLAGS, IFF_UP)", ifacename);
        close(sock);
        return false;
    }

    close(sock);
    return true;
}

bool nsMountTmpfs(const char* dst) {
    if (mount(NULL, dst, "tmpfs", 0, NULL) == -1) {
        PLOG_E("mount(dst='%s', tmpfs)", dst);
        return false;
    }
    return true;
}

#endif /* defined(_HF_ARCH_LINUX) */
