#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(_HF_ARCH_LINUX)
#include <sched.h>
#endif /* defined(_HF_ARCH_LINUX) */

#include "libcommon/common.h"
#include "libcommon/log.h"
#include "libcommon/ns.h"

#define HF_TCP_PORT_ENV "_HF_TCP_PORT"

static uint16_t tcp_port = 8080;

int argc_server = 0;
char **argv_server = NULL;

static void *netDriver_getSymbol(const char *func) {
    dlerror(); /* Clear existing errors */
    void *f = dlsym(RTLD_DEFAULT, func);
    char *error = dlerror();
    if (f == NULL && error != NULL) {
        LOG_D("Couldn't find function '%s': %s", func, error);
        return NULL;
    }
    return f;
}

static void *netDriver_mainProgram(void *unused UNUSED) {
    int (*f)(int argc, char **argv) = netDriver_getSymbol("fuzzing_main");
    if (f == NULL) {
        /* FIXME: This can find libfuzzer's main() as well */
        f = netDriver_getSymbol("main");
    }
    if (f == NULL) {
        LOG_F("Couldn't find symbol address for the 'fuzzing_main' or 'main' functions");
    }
    int ret = f(argc_server, argv_server);
    LOG_I("Honggfuzz Net Driver (pid=%d): original main() function exited with: %d", (int)getpid(),
        ret);
    _exit(ret);
}

static void netDriver_startOriginalProgramInThread(void) {
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024 * 8);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&t, &attr, netDriver_mainProgram, NULL);
}

static void netDriver_initNs(void) {
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
    LOG_W("Honggfuzz Net Driver: Namespaces not enabled for this OS platform");
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
    while (connect(sock, (const struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        if (errno == EINTR) {
            continue;
        }
        PLOG_W("connect('127.0.0.1:%" PRIu16 ")", portno);
        return -1;
    }

    return sock;
}

/*
 * Decide which TCP port should be used for sending inputs
 * Define this function in your code to provide custom TCP port choice
 */
__attribute__((weak)) uint16_t HonggfuzzNetDriverPort(int argc UNUSED, char **argv UNUSED) {
    const char *port_str = getenv(HF_TCP_PORT_ENV);
    if (port_str == NULL) {
        return tcp_port;
    }
    return (uint16_t)atoi(port_str);
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
            argv[i] = argv[0]; /* Change '--' into argv[0], as it's the new argv[0] for the TCP
                                  server program */
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
    tcp_port = HonggfuzzNetDriverPort(*argc, *argv);
    *argc = HonggfuzzNetDriverArgsForServer(*argc, *argv, &argc_server, &argv_server);

    LOG_I("Honggfuzz Net Driver (pid=%d): TCP port:%d will be used", (int)getpid(), tcp_port);

    netDriver_startOriginalProgramInThread();
    netDriver_waitForServerReady(tcp_port);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
    int sock = netDriver_sockConn(tcp_port);
    if (sock == -1) {
        LOG_F("Couldn't connect to the server TCP port");
    }
    while (send(sock, buf, len, MSG_NOSIGNAL) == -1) {
        if (errno == EINTR) {
            continue;
        }
        PLOG_F("send(sock=%d, len=%zu) failed", sock, len);
    }
    /*
     * Indicate the end of input for the TCP server
     *
     * Well-behaved TCP servers should process the input at this point, and close the TCP connection
     */
    if (shutdown(sock, SHUT_WR)) {
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
    while (recv(sock, b, sizeof(b), MSG_WAITALL) > 0)
        ;

    close(sock);

    return 0;
}

/* Use -Wl,--wrap=main to redirect invocation of the whole program from main() to __wrap_main() */
int __wrap_main(int argc, char **argv) {
    netDriver_initNs();

    int (*f1)(int argc, char **argv) = netDriver_getSymbol("HonggfuzzMain");
    int (*f2)(int *argc, char ***argv, void *callback) =
        netDriver_getSymbol("_ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE");

    if (f1) {
        return f1(argc, argv);
    }
    if (f2) {
        return f2(&argc, &argv, LLVMFuzzerTestOneInput);
    }

    LOG_F("Couldn't find Honggfuzz nor LibFuzzer entry points");
    return 0;
}
