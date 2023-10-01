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

#include "ns.h"

#include "common.h"
#include "files.h"
#include "log.h"
#include "util.h"

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

bool nsSetup(uid_t origuid, gid_t origgid) {
    if (!files_writeStrToFile("/proc/self/setgroups", "deny", O_WRONLY)) {
        PLOG_E("Couldn't write to /proc/self/setgroups");
        return false;
    }

    char gid_map[4096];
    snprintf(gid_map, sizeof(gid_map), "%d %d 1", (int)origgid, (int)origgid);
    if (!files_writeStrToFile("/proc/self/gid_map", gid_map, O_WRONLY)) {
        PLOG_E("Couldn't write to /proc/self/gid_map");
        return false;
    }

    char uid_map[4096];
    snprintf(uid_map, sizeof(uid_map), "%d %d 1", (int)origuid, (int)origuid);
    if (!files_writeStrToFile("/proc/self/uid_map", uid_map, O_WRONLY)) {
        PLOG_E("Couldn't write to /proc/self/uid_map");
        return false;
    }

    if (setresgid(origgid, origgid, origgid) == -1) {
        PLOG_E("setresgid(%d)", (int)origgid);
        return false;
    }
    if (setresuid(origuid, origuid, origuid) == -1) {
        PLOG_E("setresuid(%d)", (int)origuid);
        return false;
    }

    return true;
}

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

    if (!nsSetup(current_uid, current_gid)) {
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
    util_memsetInline(&ifr, '\0', sizeof(ifr));
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

bool nsMountTmpfs(const char* dst, const char* opts) {
    if (mount(NULL, dst, "tmpfs", 0, opts) == -1) {
        PLOG_E("mount(dst='%s', tmpfs)", dst);
        return false;
    }
    return true;
}

#endif /* defined(_HF_ARCH_LINUX) */
