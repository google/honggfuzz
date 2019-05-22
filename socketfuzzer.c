#include "socketfuzzer.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "honggfuzz.h"
#include "libhfcommon/common.h"
#include "libhfcommon/files.h"
#include "libhfcommon/log.h"
#include "libhfcommon/ns.h"
#include "libhfcommon/util.h"

bool fuzz_waitForExternalInput(run_t* run) {
    /* tell the external fuzzer to do his thing */
    if (!fuzz_prepareSocketFuzzer(run)) {
        LOG_F("fuzz_prepareSocketFuzzer() failed");
    }

    /* the external fuzzer may inform us of a crash */
    int result = fuzz_waitforSocketFuzzer(run);
    if (result == 2) {
        return false;
    }

    return true;
}

bool fuzz_prepareSocketFuzzer(run_t* run) {
    // Notify fuzzer that he should send teh things
    LOG_D("fuzz_prepareSocketFuzzer: SEND Fuzz");
    return files_sendToSocket(
        run->global->socketFuzzer.clientSocket, (uint8_t*)"Fuzz", strlen("Fuzz"));
}

/* Return values:
    0: error
    1: okay
    2: target unresponsive
*/
int fuzz_waitforSocketFuzzer(run_t* run) {
    ssize_t ret;
    uint8_t buf[16];

    // Wait until the external fuzzer did his thing
    bzero(buf, 16);
    ret = files_readFromFd(run->global->socketFuzzer.clientSocket, buf, 4);
    LOG_D("fuzz_waitforSocketFuzzer: RECV: %s", buf);

    // We dont care what we receive, its just to block here
    if (ret < 0) {
        LOG_F("fuzz_waitforSocketFuzzer: received: %zu", ret);
    }

    if (memcmp(buf, "okay", 4) == 0) {
        return 1;
    } else if (memcmp(buf, "bad!", 4) == 0) {
        return 2;
    }

    return 0;
}

bool fuzz_notifySocketFuzzerNewCov(honggfuzz_t* hfuzz) {
    // Tell the fuzzer that the thing he sent reached new BB's
    bool ret = files_sendToSocket(hfuzz->socketFuzzer.clientSocket, (uint8_t*)"New!", 4);
    LOG_D("fuzz_notifySocketFuzzer: SEND: New!");
    if (!ret) {
        LOG_F("fuzz_notifySocketFuzzer");
    }

    return true;
}

bool fuzz_notifySocketFuzzerCrash(run_t* run) {
    bool ret = files_sendToSocket(run->global->socketFuzzer.clientSocket, (uint8_t*)"Cras", 4);
    LOG_D("fuzz_notifySocketFuzzer: SEND: Crash");
    if (!ret) {
        LOG_F("fuzz_notifySocketFuzzer");
    }

    return true;
}

bool setupSocketFuzzer(honggfuzz_t* run) {
    int s, len;
    socklen_t t;
    struct sockaddr_un local, remote;
    char socketPath[512];
    snprintf(socketPath, sizeof(socketPath), "/tmp/honggfuzz_socket.%i", getpid());

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return false;
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, socketPath);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(s, (struct sockaddr*)&local, len) == -1) {
        perror("bind");
        return false;
    }

    if (listen(s, 5) == -1) {
        perror("listen");
        return false;
    }

    printf("Waiting for SocketFuzzer connection on socket: %s\n", socketPath);
    t = sizeof(remote);
    if ((run->socketFuzzer.clientSocket =
                TEMP_FAILURE_RETRY(accept(s, (struct sockaddr*)&remote, &t))) == -1) {
        perror("accept");
        return false;
    }

    run->socketFuzzer.serverSocket = s;
    printf("A SocketFuzzer client connected. Continuing.\n");

    return true;
}

void cleanupSocketFuzzer() {
    char socketPath[512];
    snprintf(socketPath, sizeof(socketPath), "/tmp/honggfuzz_socket.%i", getpid());
    unlink(socketPath);
}
