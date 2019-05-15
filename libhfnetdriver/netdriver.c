#include "libhfnetdriver/netdriver.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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
    uint16_t tcp_port;
    sa_family_t sa_family;
} hfnd_globals = {
    .argc_server = 1,
    .argv_server = initial_server_argv,
    .tcp_port = 0,
    .sa_family = AF_UNSPEC,
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
    if (mkdir(HFND_TMP_DIR_OLD, 0755) == -1 && errno != EEXIST) {
        PLOG_F("mkdir('%s', 0755)", HFND_TMP_DIR_OLD);
    }
    if (mkdir(HFND_TMP_DIR, 0755) == -1 && errno != EEXIST) {
        PLOG_F("mkdir('%s', 0755)", HFND_TMP_DIR);
    }
    if (!nsMountTmpfs(HFND_TMP_DIR_OLD)) {
        LOG_F("nsMountTmpfs('%s') failed", HFND_TMP_DIR_OLD);
    }
    if (!nsMountTmpfs(HFND_TMP_DIR)) {
        LOG_F("nsMountTmpfs('%s') failed", HFND_TMP_DIR);
    }
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
        PLOG_D("socket(type=%d for dst_addr='%s', SOCK_STREAM, 0)", addr->sa_family,
            files_sockAddrToStr(addr));
        return -1;
    }
    int val = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, (socklen_t)sizeof(val)) == -1) {
        PLOG_W("setsockopt(sock=%d, SOL_SOCKET, SO_REUSEADDR, %d)", sock, val);
    }
#if defined(SOL_TCP) && defined(TCP_NODELAY)
    val = 1;
    if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val)) == -1) {
        PLOG_W("setsockopt(sock=%d, SOL_TCP, TCP_NODELAY, %d)", sock, val);
    }
#endif                         /* defined(SOL_TCP) && defined(TCP_NODELAY) */
    val = (1024ULL * 1024ULL); /* 1MiB */
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &val, (socklen_t)sizeof(val)) == -1) {
        PLOG_D("setsockopt(sock=%d, SOL_SOCKET, SO_SNDBUF, %d)", sock, val);
    }

    netDriver_bindToRndLoopback(sock, addr->sa_family);

    LOG_D("Connecting to '%s'", files_sockAddrToStr(addr));
    if (TEMP_FAILURE_RETRY(connect(sock, addr, socklen)) == -1) {
        PLOG_W("connect(addr='%s')", files_sockAddrToStr(addr));
        close(sock);
        return -1;
    }
    return sock;
}

int netDriver_sockConnLoopback(sa_family_t sa_family, uint16_t portno) {
    if (portno < 1) {
        LOG_F("Specified TCP port (%d) cannot be < 1", portno);
    }

    if (sa_family == AF_INET) {
        /* IPv4's 127.0.0.1 */
        const struct sockaddr_in saddr4 = {
            .sin_family = AF_INET,
            .sin_port = htons(portno),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };
        return netDriver_sockConnAddr((const struct sockaddr *)&saddr4, sizeof(saddr4));
    }

    if (sa_family == AF_INET6) {
        /* IPv6's ::1 */
        const struct sockaddr_in6 saddr6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(portno),
            .sin6_flowinfo = 0,
            .sin6_addr = in6addr_loopback,
            .sin6_scope_id = 0,
        };
        return netDriver_sockConnAddr((const struct sockaddr *)&saddr6, sizeof(saddr6));
    }

    LOG_E("Unknown SA_FAMILY=%d specified", (int)sa_family);
    return -1;
}

/*
 * Decide which TCP port should be used for sending inputs
 */
__attribute__((weak)) uint16_t HonggfuzzNetDriverPort(
    int argc HF_ATTR_UNUSED, char **argv HF_ATTR_UNUSED) {
    /* Return the default port (8080) */
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

static void netDriver_waitForServerReady(uint16_t portno) {
    for (;;) {
        int fd = -1;
        fd = netDriver_sockConnLoopback(AF_INET, portno);
        if (fd >= 0) {
            hfnd_globals.sa_family = AF_INET;
            close(fd);
            return;
        }
        fd = netDriver_sockConnLoopback(AF_INET6, portno);
        if (fd >= 0) {
            hfnd_globals.sa_family = AF_INET6;
            close(fd);
            return;
        }
        LOG_I(
            "Honggfuzz Net Driver (pid=%d): Waiting for the TCP server process to start accepting "
            "connections at TCP4:127.0.0.1:%" PRIu16 " or at TCP6:[::1]:%" PRIu16
            ". Sleeping for 0.5 seconds ...",
            (int)getpid(), portno, portno);

        util_sleepForMSec(500);
    }
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

__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv(HFND_SKIP_FUZZING_ENV)) {
        LOG_I(
            "Honggfuzz Net Driver (pid=%d): '%s' is set, skipping fuzzing, calling main() directly",
            getpid(), HFND_SKIP_FUZZING_ENV);
        exit(HonggfuzzNetDriver_main(*argc, *argv));
    }

    /* Make sure LIBHFNETDRIVER_module_netdriver (NetDriver signature) is used */
    LOG_D("Module: %s", LIBHFNETDRIVER_module_netdriver);

    hfnd_globals.tcp_port = netDriver_getTCPPort(*argc, *argv);
    *argc = HonggfuzzNetDriverArgsForServer(
        *argc, *argv, &hfnd_globals.argc_server, &hfnd_globals.argv_server);

    LOG_I(
        "Honggfuzz Net Driver (pid=%d): TCP port %d will be used. You can change the server's TCP "
        "port by setting the %s envvar",
        (int)getpid(), hfnd_globals.tcp_port, HFND_TCP_PORT_ENV);

    netDriver_initNsIfNeeded();
    netDriver_startOriginalProgramInThread();
    netDriver_waitForServerReady(hfnd_globals.tcp_port);

    LOG_I("Honggfuzz Net Driver (pid=%d): The TCP server process is ready to accept connections at "
          "%s:%" PRIu16 ". TCP fuzzing starts now!",
        (int)getpid(), (hfnd_globals.sa_family == AF_INET ? "TCP4:127.0.0.1" : "TCP6:[::1]"),
        hfnd_globals.tcp_port);

    return 0;
}

__attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    int sock = netDriver_sockConnLoopback(hfnd_globals.sa_family, hfnd_globals.tcp_port);
    if (sock == -1) {
        LOG_F("Couldn't connect to the server TCP port");
    }
    if (!files_sendToSocket(sock, buf, len)) {
        PLOG_W("files_sendToSocket(sock=%d, len=%zu) failed", sock, len);
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
