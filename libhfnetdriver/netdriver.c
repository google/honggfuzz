#include "libhfnetdriver/netdriver.h"

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(_HF_ARCH_LINUX)
#include <sched.h>
#endif /* defined(_HF_ARCH_LINUX) */

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"

#define HF_TCP_PORT_ENV "_HF_TCP_PORT"

static char *initial_server_argv[] = {"fuzzer"};

static struct {
    uint16_t tcp_port;
    int argc_server;
    char **argv_server;
} hfnd_globals = {
    .tcp_port = 8080,
    .argc_server = 1,
    .argv_server = initial_server_argv,
};

static void *netDriver_mainProgram(void *unused HF_ATTR_UNUSED) {
    /*
     * When redefining 'main' to 'HonggfuzzNetDriver_main' (e.g. with
     * -Dmain=HonggfuzzNetDriver_main), and compiling with a C++ compiler, the symbol will be
     * mangled (as opposed to the regular 'main')
     */
    __attribute__((weak)) int HonggfuzzNetDriver_main(int argc, char **argv);
    __attribute__((weak)) int _Z23HonggfuzzNetDriver_mainv(); /* C++: int(*)(void) */
    __attribute__((weak)) int _Z23HonggfuzzNetDriver_mainiPPc(
        int argc, char **argv); /* C++: (*)(int, char**) */
    __attribute__((weak)) int _Z23HonggfuzzNetDriver_mainiPPKc(
        int argc, char **argv); /* C++: (*)(int, const char**) */
    __attribute__((weak)) int _Z23HonggfuzzNetDriver_mainiPKPKc(
        int argc, char **argv); /* C++: (*)(int, const char* const*) */
    __attribute__((weak)) int _Z23HonggfuzzNetDriver_mainiPKPc(
        int argc, char **argv); /* C++: (*)(int, char* const*) */

    int ret = 0;
    /* Try both the standard C symbol and variants of the C++ (mangled) symbol */
    if (HonggfuzzNetDriver_main) {
        ret = HonggfuzzNetDriver_main(hfnd_globals.argc_server, hfnd_globals.argv_server);
    } else if (_Z23HonggfuzzNetDriver_mainv) {
        ret = _Z23HonggfuzzNetDriver_mainv();
    } else if (_Z23HonggfuzzNetDriver_mainiPPc) {
        ret = _Z23HonggfuzzNetDriver_mainiPPc(hfnd_globals.argc_server, hfnd_globals.argv_server);
    } else if (_Z23HonggfuzzNetDriver_mainiPPKc) {
        ret = _Z23HonggfuzzNetDriver_mainiPPKc(hfnd_globals.argc_server, hfnd_globals.argv_server);
    } else if (_Z23HonggfuzzNetDriver_mainiPKPKc) {
        ret = _Z23HonggfuzzNetDriver_mainiPKPKc(hfnd_globals.argc_server, hfnd_globals.argv_server);
    } else if (_Z23HonggfuzzNetDriver_mainiPKPc) {
        ret = _Z23HonggfuzzNetDriver_mainiPKPc(hfnd_globals.argc_server, hfnd_globals.argv_server);
    } else {
        LOG_F("'int HonggfuzzNetDriver_main(int argc, char **argv)' wasn't defined in the code");
    }
    LOG_I("Honggfuzz Net Driver (pid=%d): HonggfuzzNetDriver_main() function exited with: %d",
        (int)getpid(), ret);
    _exit(ret);
}

static void netDriver_startOriginalProgramInThread(void) {
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024 * 8);
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
    if (!nsMountTmpfs("/tmp")) {
        LOG_F("nsMountTmpfs('/tmp') failed");
    }
    return;
#endif /* defined(_HF_ARCH_LINUX) */
    LOG_W("Honggfuzz Net Driver (pid=%d): Namespaces not enabled for this OS platform",
        (int)getpid());
}

/*
 * Initialize namespaces before e.g. ASAN, which can spawn threads, what can use
 * unshare(CLONE_NEWUSER|...) to fail
 */
__attribute__((section(".preinit_array"), used)) void (*__local_libhfnetdriver_preinit)(
    void) = netDriver_initNsIfNeeded;

/*
 * ASAN BackgroundThread is also started from the .preinit_array, hijack the __asan_init symbol,
 * and call unshare() first
 */
void __wrap___asan_init(void) {
    netDriver_initNsIfNeeded();
    __attribute__((weak)) void __real___asan_init(void);
    if (__real___asan_init) {
        __real___asan_init();
    }
}

int netDriver_sockConn(uint16_t portno) {
    if (portno < 1) {
        LOG_F("Specified TCP port (%d) cannot be < 1", portno);
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock == -1) {
        PLOG_F("socket(AF_INET, SOCK_STREAM, IPPROTO_IP)");
    }

    int sz = (1024 * 1024);
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) == -1) {
        PLOG_F("setsockopt(socket=%d, SOL_SOCKET, SO_SNDBUF, size=%d", sock, sz);
    }

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(portno);
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (TEMP_FAILURE_RETRY(connect(sock, (const struct sockaddr *)&saddr, sizeof(saddr))) == -1) {
        PLOG_W("Honggfuzz Net Driver (pid=%d): connect('127.0.0.1:%" PRIu16 ")", (int)getpid(),
            portno);
        return -1;
    }

    return sock;
}

/*
 * Decide which TCP port should be used for sending inputs
 * Define this function in your code to provide custom TCP port choice
 */
__attribute__((weak)) uint16_t HonggfuzzNetDriverPort(
    int argc HF_ATTR_UNUSED, char **argv HF_ATTR_UNUSED) {
    const char *port_str = getenv(HF_TCP_PORT_ENV);
    if (port_str == NULL) {
        return hfnd_globals.tcp_port;
    }
    errno = 0;
    signed long portsl = strtol(port_str, NULL, 0);
    if (errno != 0) {
        PLOG_F("Couldn't convert '%s'='%s' to a number", HF_TCP_PORT_ENV, port_str);
    }

    if (portsl < 1) {
        LOG_F(
            "Specified TCP port '%s'='%s' (%ld) cannot be < 1", HF_TCP_PORT_ENV, port_str, portsl);
    }
    if (portsl > 65535) {
        LOG_F("Specified TCP port '%s'='%s' (%ld) cannot be > 65535", HF_TCP_PORT_ENV, port_str,
            portsl);
    }

    return (uint16_t)portsl;
}

/*
 * Split: ./httpdserver -max_input=10 -- --config /etc/httpd.confg
 * so:
 * This code (e.g. libfuzzer) will only see "./httpdserver -max_input=10",
 * while the httpdserver will only see: "./httpdserver --config /etc/httpd.confg"
 *
 * The return value is a number of arguments passed to libfuzzer (if used)
 *
 * Define this function in your code to manipulate the arguments as desired
 */
__attribute__((weak)) int HonggfuzzNetDriverArgsForServer(
    int argc, char **argv, int *server_argc, char ***server_argv) {
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            *server_argc = argc - i;
            *server_argv = &argv[i];
            return argc - i;
        }
    }

    LOG_I(
        "Honggfuzz Net Driver (pid=%d): No '--' was found in the commandline, and therefore no "
        "arguments will be passed to the TCP server program",
        (int)getpid());
    *server_argc = 1;
    *server_argv = &argv[0];
    return argc;
}

void netDriver_waitForServerReady(uint16_t portno) {
    for (;;) {
        int fd = netDriver_sockConn(portno);
        if (fd >= 0) {
            close(fd);
            break;
        }
        LOG_I(
            "Honggfuzz Net Driver (pid=%d): Waiting for the TCP server process to start accepting "
            "TCP connections at 127.0.0.1:%" PRIu16 " ...",
            (int)getpid(), portno);
        sleep(1);
    }

    LOG_I(
        "Honggfuzz Net Driver (pid=%d): The TCP server process ready to accept connections at "
        "127.0.0.1:%" PRIu16 ". TCP fuzzing starts now!",
        (int)getpid(), portno);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    hfnd_globals.tcp_port = HonggfuzzNetDriverPort(*argc, *argv);
    *argc = HonggfuzzNetDriverArgsForServer(
        *argc, *argv, &hfnd_globals.argc_server, &hfnd_globals.argv_server);

    LOG_I("Honggfuzz Net Driver (pid=%d): TCP port:%d will be used", (int)getpid(),
        hfnd_globals.tcp_port);

    netDriver_initNsIfNeeded();
    netDriver_startOriginalProgramInThread();
    netDriver_waitForServerReady(hfnd_globals.tcp_port);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    int sock = netDriver_sockConn(hfnd_globals.tcp_port);
    if (sock == -1) {
        LOG_F("Couldn't connect to the server TCP port");
    }
    if (TEMP_FAILURE_RETRY(send(sock, buf, len, MSG_NOSIGNAL)) == -1) {
        PLOG_F("send(sock=%d, len=%zu) failed", sock, len);
    }
    /*
     * Indicate EOF (via the FIN flag) to the TCP server
     *
     * Well-behaved TCP servers should process the input and responsd/close the TCP connection at
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
     * TCP server to drop the input data, instead of processing it
     */
    static char b[1024 * 1024 * 8];
    while (TEMP_FAILURE_RETRY(recv(sock, b, sizeof(b), MSG_WAITALL)) > 0)
        ;

    close(sock);

    return 0;
}
