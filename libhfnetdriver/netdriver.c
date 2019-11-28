#include "libhfnetdriver/netdriver.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#if defined(_HF_ARCH_LINUX)
#include <sched.h>
#endif /* defined(_HF_ARCH_LINUX) */

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"
#include "libhfcommon/util.h"

__attribute__((visibility("default"))) __attribute__((used))
const char *const LIBHFNETDRIVER_module_netdriver = _HF_NETDRIVER_SIG;

#define HFND_TCP_PORT_ENV "HFND_TCP_PORT"
#define HFND_SKIP_FUZZING_ENV "HFND_SKIP_FUZZING"

static char *initial_server_argv[] = {"fuzzer", NULL};

static struct {
    int argc_server;
    char **argv_server;
    struct sockaddr *saddr;
    socklen_t slen;
} hfnd_globals = {
    .argc_server = 1,
    .argv_server = initial_server_argv,
    .saddr = NULL,
    .slen = 0,
};

extern int HonggfuzzNetDriver_main(int argc, char **argv);

static void *netDriver_mainProgram(void *unused HF_ATTR_UNUSED) {
    int ret = HonggfuzzNetDriver_main(hfnd_globals.argc_server, hfnd_globals.argv_server);
    LOG_I("Honggfuzz Net Driver (pid=%d): HonggfuzzNetDriver_main() function exited with: %d",
        (int)getpid(), ret);
    _exit(ret);
}

static void netDriver_startOriginalProgramInThread(void) {
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024ULL * 1024ULL * 8ULL);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&t, &attr, netDriver_mainProgram, NULL) != 0) {
        PLOG_F("Couldn't create the 'netDriver_mainProgram' thread");
    }
}

#if defined(_HF_ARCH_LINUX)
static void netDriver_mountTmpfs(const char *path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        PLOG_F("mkdir('%s', 0755)", path);
    }
    if (!nsMountTmpfs(path, NULL)) {
        LOG_F("nsMountTmpfs('%s') failed", path);
    }
}
#endif /* defined(_HF_ARCH_LINUX) */

static void netDriver_initNsIfNeeded(void) {
    static bool initialized = false;
    if (initialized) {
        return;
    }
    initialized = true;

#if defined(_HF_ARCH_LINUX)
    if (!nsEnter(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS)) {
        LOG_F("nsEnter(CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWUTS) failed");
    }
    if (!nsIfaceUp("lo")) {
        LOG_F("nsIfaceUp('lo') failed");
    }

    char tmpdir[PATH_MAX] = {};
    int ret = HonggfuzzNetDriverTempdir(tmpdir, sizeof(tmpdir));
    if (ret < 0) {
        LOG_F("HonggfuzzNetDriverTempdir failed");
    }

    if (strlen(tmpdir) > 0) {
        netDriver_mountTmpfs(tmpdir);
    }

    /* Legacy path */
    netDriver_mountTmpfs(HFND_TMP_DIR_OLD);

    return;
#endif /* defined(_HF_ARCH_LINUX) */
    LOG_W("Honggfuzz Net Driver (pid=%d): Namespaces not enabled for this OS platform",
        (int)getpid());
}

/*
 * Try to bind the client socket to a random loopback address, to avoid problems with exhausted
 * ephemeral ports. We run out of them, because the TIME_WAIT state is imposed on recently closed
 * TCP connections originating from the same IP address (127.0.0.1), and connecting to the singular
 * IP address (again, 127.0.0.1) on a single port
 */
static void netDriver_bindToRndLoopback(int sock, sa_family_t sa_family) {
    if (sa_family != AF_INET) {
        return;
    }
    const struct sockaddr_in bsaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(0),
        .sin_addr.s_addr = htonl((((uint32_t)util_rnd64()) & 0x00FFFFFF) | 0x7F000000),
    };
    if (bind(sock, (struct sockaddr *)&bsaddr, sizeof(bsaddr)) == -1) {
        PLOG_W("Could not bind to a random IPv4 Loopback address");
    }
}

static int netDriver_sockConnAddr(const struct sockaddr *addr, socklen_t socklen) {
    int sock = socket(addr->sa_family, SOCK_STREAM, 0);
    if (sock == -1) {
        PLOG_W("socket(type=%d for dst_addr='%s', SOCK_STREAM, 0)", addr->sa_family,
            files_sockAddrToStr(addr, socklen));
        return -1;
    }
    if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) {
        int val = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, (socklen_t)sizeof(val)) == -1) {
            PLOG_W("setsockopt(sock=%d, SOL_SOCKET, SO_REUSEADDR, %d)", sock, val);
        }
#if defined(SOL_TCP) && defined(TCP_NODELAY)
        val = 1;
        if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val)) == -1) {
            PLOG_W("setsockopt(sock=%d, SOL_TCP, TCP_NODELAY, %d)", sock, val);
        }
#endif /* defined(SOL_TCP) && defined(TCP_NODELAY) */
#if defined(SOL_TCP) && defined(TCP_QUICKACK)
        val = 1;
        if (setsockopt(sock, SOL_TCP, TCP_QUICKACK, &val, (socklen_t)sizeof(val)) == -1) {
            PLOG_D("setsockopt(sock=%d, SOL_TCP, TCP_QUICKACK, %d)", sock, val);
        }
#endif /* defined(SOL_TCP) && defined(TCP_QUICKACK) */
    }

    netDriver_bindToRndLoopback(sock, addr->sa_family);

    LOG_D("Connecting to '%s'", files_sockAddrToStr(addr, socklen));
    if (TEMP_FAILURE_RETRY(connect(sock, addr, socklen)) == -1) {
        PLOG_W("connect(addr='%s')", files_sockAddrToStr(addr, socklen));
        close(sock);
        return -1;
    }
    return sock;
}

/*
 * Decide which TCP port should be used for sending inputs
 */
__attribute__((weak)) uint16_t HonggfuzzNetDriverPort(
    int argc HF_ATTR_UNUSED, char **argv HF_ATTR_UNUSED) {
    return 8080;
}

/*
 * The return value is a number of arguments passed returned to libfuzzer (if used)
 *
 * Define this function in your code to describe which arguments are passed to the fuzzed
 * TCP server, and which to the fuzzing engine.
 */
__attribute__((weak)) int HonggfuzzNetDriverArgsForServer(
    int argc, char **argv, int *server_argc, char ***server_argv) {
    /* If the used fuzzer is honggfuzz, simply pass all arguments to the TCP server */
    __attribute__((weak)) int HonggfuzzMain(int argc, char **argv);
    if (HonggfuzzMain) {
        *server_argc = argc;
        *server_argv = argv;
        return argc;
    }

    /*
     * For other fuzzing engines:
     * Split: ./httpdserver -max_input=10 -- --config /etc/httpd.confg
     * into:
     * The fuzzing engine (e.g. libfuzzer) will see "./httpdserver -max_input=10",
     * The httpdserver will see: "./httpdserver --config /etc/httpd.confg"
     */
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            /* Replace '--' with argv[0] */
            argv[i] = argv[0];
            *server_argc = argc - i;
            *server_argv = &argv[i];
            return i;
        }
    }

    LOG_I("Honggfuzz Net Driver (pid=%d): No '--' was found in the commandline, and therefore no "
          "arguments will be passed to the TCP server program",
        (int)getpid());
    *server_argc = 1;
    *server_argv = &argv[0];
    return argc;
}

/*
 * Retrieve path where to mount temporary filesystem (tmpfs) for the duration
 * of a main program. Return empty array (length 0) to not use tmpfs.
 */
__attribute__((weak)) int HonggfuzzNetDriverTempdir(char *str, size_t size) {
    return snprintf(str, size, "%s", HFND_TMP_DIR);
}

/*
 * Put a custom sockaddr here (e.g. based on AF_UNIX)
 */
__attribute__((weak)) socklen_t HonggfuzzNetDriverServerAddress(struct sockaddr **addr) {
    *addr = NULL;
    return 0;
}

uint16_t netDriver_getTCPPort(int argc, char **argv) {
    const char *port_str = getenv(HFND_TCP_PORT_ENV);
    if (port_str) {
        errno = 0;
        signed long portsl = strtol(port_str, NULL, 0);
        if (errno != 0) {
            PLOG_F("Couldn't convert '%s'='%s' to a number", HFND_TCP_PORT_ENV, port_str);
        }
        if (portsl < 1) {
            LOG_F("Specified TCP port '%s'='%s' (%ld) cannot be < 1", HFND_TCP_PORT_ENV, port_str,
                portsl);
        }
        if (portsl > 65535) {
            LOG_F("Specified TCP port '%s'='%s' (%ld) cannot be > 65535", HFND_TCP_PORT_ENV,
                port_str, portsl);
        }
        return (uint16_t)portsl;
    }

    return HonggfuzzNetDriverPort(argc, argv);
}

static void netDriver_waitForServerReady(int argc, char **argv) {
    for (;;) {
        struct sockaddr *addr;
        socklen_t slen = HonggfuzzNetDriverServerAddress(&addr);
        if (slen > 0) {
            /* User provided specific destination address */
            int fd = netDriver_sockConnAddr(addr, sizeof(addr));
            if (fd >= 0) {
                close(fd);
                hfnd_globals.saddr = addr;
                hfnd_globals.slen = slen;
                return;
            }
            LOG_I("Honggfuzz Net Driver (pid=%d): Waiting for the server process to start "
                  "accepting connections at '%s'",
                (int)getpid(), files_sockAddrToStr(addr, slen));
        } else {
            /* Try TCP4 and TCP6 connections */
            static __thread struct sockaddr_in addr4 = {
                .sin_family = PF_INET,
                .sin_port = 0,
                .sin_addr.s_addr = 0,
            };
            addr4.sin_port = htons(netDriver_getTCPPort(argc, argv));
            addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            int fd = netDriver_sockConnAddr((struct sockaddr *)&addr4, sizeof(addr4));
            if (fd >= 0) {
                close(fd);
                hfnd_globals.saddr = (struct sockaddr *)&addr4;
                hfnd_globals.slen = sizeof(addr4);
                return;
            }
            static __thread struct sockaddr_in6 addr6 = {
                .sin6_family = PF_INET6,
                .sin6_port = 0,
                .sin6_flowinfo = 0,
                .sin6_addr = {},
                .sin6_scope_id = 0,
            };
            addr6.sin6_port = htons(netDriver_getTCPPort(argc, argv));
            addr6.sin6_addr = in6addr_loopback;
            fd = netDriver_sockConnAddr((struct sockaddr *)&addr6, sizeof(addr6));
            if (fd >= 0) {
                close(fd);
                hfnd_globals.saddr = (struct sockaddr *)&addr6;
                hfnd_globals.slen = sizeof(addr6);
                return;
            }
            /* Other default protocols (e.g. AF_UNIX) can be added below */
            LOG_I("Honggfuzz Net Driver (pid=%d): Waiting for the TCP server process to start "
                  "accepting connections at TCP port: %hu",
                (int)getpid(), netDriver_getTCPPort(argc, argv));
        }
        util_sleepForMSec(500);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv(HFND_SKIP_FUZZING_ENV)) {
        LOG_I(
            "Honggfuzz Net Driver (pid=%d): '%s' is set, skipping fuzzing, calling main() directly",
            getpid(), HFND_SKIP_FUZZING_ENV);
        exit(HonggfuzzNetDriver_main(*argc, *argv));
    }

    /* Make sure LIBHFNETDRIVER_module_netdriver (NetDriver signature) is used */
    LOG_D("Module: %s", LIBHFNETDRIVER_module_netdriver);

    *argc = HonggfuzzNetDriverArgsForServer(
        *argc, *argv, &hfnd_globals.argc_server, &hfnd_globals.argv_server);

    netDriver_initNsIfNeeded();
    netDriver_startOriginalProgramInThread();
    netDriver_waitForServerReady(*argc, *argv);

    LOG_I("Honggfuzz Net Driver (pid=%d): The server process is ready to accept connections at "
          "'%s'. Fuzzing starts now!",
        (int)getpid(), files_sockAddrToStr(hfnd_globals.saddr, hfnd_globals.slen));

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    int sock = netDriver_sockConnAddr(hfnd_globals.saddr, hfnd_globals.slen);
    if (sock == -1) {
        LOG_F("Couldn't connect to the server socket at '%s'",
            files_sockAddrToStr(hfnd_globals.saddr, hfnd_globals.slen));
    }
    if (!files_sendToSocket(sock, buf, len)) {
        PLOG_W("files_sendToSocket(addr='%s', sock=%d, len=%zu) failed",
            files_sockAddrToStr(hfnd_globals.saddr, hfnd_globals.slen), sock, len);
        close(sock);
        return 0;
    }
    /*
     * Indicate EOF (via the FIN flag) to the TCP server
     *
     * Well-behaved TCP servers should process the input and respond/close the TCP connection at
     * this point
     */
    if (TEMP_FAILURE_RETRY(shutdown(sock, SHUT_WR)) == -1) {
        if (errno == ENOTCONN) {
            close(sock);
            return 0;
        }
        PLOG_F("shutdown(sock=%d, SHUT_WR)", sock);
    }

    /*
     * Try to read data from the server, assuming that an early TCP close would sometimes cause the
     * TCP server to drop the input data, instead of processing it. Use BSS to avoid putting
     * pressure on the stack size
     */
    static char b[1024ULL * 1024ULL * 4ULL];
    while (TEMP_FAILURE_RETRY(recv(sock, b, sizeof(b), MSG_WAITALL)) > 0)
        ;

    close(sock);

    return 0;
}
