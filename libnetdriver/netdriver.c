#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(_HF_ARCH_LINUX)
#include <sched.h>
#endif /* defined(_HF_ARCH_LINUX) */

#include "libcommon/common.h"
#include "libcommon/log.h"
#include "libcommon/ns.h"

#define HF_TCP_PORT_ENV "_HF_TCP_PORT"

static int tcp_port = 8080;

int argc_cpy = 0;
char **argv_cpy = NULL;
static int callMain(const char *func, int argc, char **argv) {
    void *dlhandle = dlopen(NULL, RTLD_NOW);
    if (dlhandle == NULL) {
        LOG_F("dlopen(NULL, RTLD_NOW) failed:'%s'", dlerror());
    }

    dlerror();
    int (*f)(int, char **) = dlsym(dlhandle, func);
    char *error = dlerror();
    if (error != NULL) {
        LOG_F("Couldn't find the '%s' symbol:'%s'", func, error);
    }

    return f(argc, argv);
}

static void *mainThread(void *unsued UNUSED) {
    callMain("__real_main", argc_cpy, argv_cpy);
    LOG_F("__real_main exited");
    return NULL;
}

static void initThreads(void) {
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024 * 8);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&t, &attr, mainThread, NULL);
}

static void initNs(void) {
#if defined(_HF_ARCH_LINUX)
    if (nsEnter(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS) ==
        false) {
        PLOG_F("linuxEnterNs() failed");
    }
    if (nsIfaceUp("lo") == false) {
        PLOG_F("linuxIfaceUp('lo') failed");
    }
    if (nsMountTmpfs("/tmp") == false) {
        PLOG_F("linuxMountTmpfs('/tmp') failed");
    }
    return;
#endif /* defined(_HF_ARCH_LINUX) */
    LOG_W("The Honggfuzz net driver didn't enable namespaces for this platform");
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    __attribute__((weak)) int HonggfuzzNetDriverInit(int *argc UNUSED, char ***argv UNUSED);
    if (HonggfuzzNetDriverInit) {
        tcp_port = HonggfuzzNetDriverInit(argc, argv);
    }

    LOG_I("Honggfuzz Net Driver will use port:%d", tcp_port);
    argc_cpy = *argc;
    argv_cpy = *argv;

    initNs();
    initThreads();
    sleep(1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    if (tcp_port < 1) {
        LOG_F("Specified tcp_port (%d) cannot be < 1", tcp_port);
    }
    if (tcp_port > 65535) {
        LOG_F("Specified tcp_port (%d) cannot be > 65535", tcp_port);
    }

    int myfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (myfd == -1) {
        PLOG_F("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
    }

    int sz = (1024 * 1024);
    if (setsockopt(myfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) == -1) {
        PLOG_F("setsockopt(socket=%d, SOL_SOCKET, SO_SNDBUF, size=%d", myfd, sz);
    }

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(tcp_port);
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(myfd, &saddr, sizeof(saddr)) == -1) {
        PLOG_W("connect(sock=%d, 127.0.0.1:%" PRIu16 ") failed", myfd, tcp_port);
        sleep(1);
        return 1;
    }

    if (send(myfd, buf, len, MSG_NOSIGNAL) < 0) {
        PLOG_F("send(sock=%d, len=%zu) failed", myfd, len);
    }

    if (shutdown(myfd, SHUT_WR) == -1) {
        PLOG_F("shutdown(sock=%d, SHUT_WR)", myfd);
    }

    static char b[1024 * 1024];
    while (recv(myfd, b, sizeof(b), MSG_WAITALL) > 0)
        ;

    close(myfd);

    return 1;
}

int __wrap_main(int argc, char **argv) { return callMain("main", argc, argv); }
