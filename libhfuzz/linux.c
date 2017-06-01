#include "../libcommon/common.h"
#include "../libcommon/log.h"
#include "../libcommon/files.h"

#include "libhfuzz.h"

#if defined(_HF_ARCH_LINUX)

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

bool linuxEnterNs(uintptr_t cloneFlags)
{
    pid_t current_uid = getuid();
    gid_t current_gid = getuid();

    if (unshare(cloneFlags) == -1) {
        PLOG_E("unshare(%tx)", cloneFlags);
        return false;
    }

    const char *deny_str = "deny";
    if (files_writeBufToFile
        ("/proc/self/setgroups", (const uint8_t *)deny_str, strlen(deny_str), O_WRONLY) == false) {
        PLOG_E("Couldn't write to /proc/self/setgroups");
        return false;
    }

    char gid_map[4096];
    snprintf(gid_map, sizeof(gid_map), "%d %d 1\n", (int)current_gid, (int)current_gid);
    if (files_writeBufToFile
        ("/proc/self/gid_map", (const uint8_t *)gid_map, strlen(gid_map), O_WRONLY) == false) {
        PLOG_E("Couldn't write to /proc/self/gid_map");
        return false;
    }

    char uid_map[4096];
    snprintf(uid_map, sizeof(uid_map), "%d %d 1\n", (int)current_uid, (int)current_uid);
    if (files_writeBufToFile
        ("/proc/self/uid_map", (const uint8_t *)uid_map, strlen(uid_map), O_WRONLY) == false) {
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

bool linuxIfaceUp(const char *ifacename)
{
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_IP);
    if (sock == -1) {
        PLOG_E("socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP)");
        return false;
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

bool linuxMountTmpfs(const char *dst)
{
    if (mount(NULL, dst, "tmpfs", 0, NULL) == -1) {
        PLOG_E("mount(dst='%s', tmpfs)", dst);
        return false;
    }
    return true;
}

#endif                          /* defined(_HF_ARCH_LINUX) */
