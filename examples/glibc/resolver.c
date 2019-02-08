#define __USE_GNU
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libhfuzz/libhfuzz.h>

static void unsh(void) {
    if (linuxEnterNs(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS) == false) {
        exit(1);
    }
    if (linuxIfaceUp("lo") == false) {
        exit(1);
    }
}

static size_t rlen = 0;
static const char *rbuf = NULL;

static void *getdata(void *unused) {
    int myfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (myfd == -1) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(53);
    saddr.sin_addr.s_addr = inet_addr("127.0.0.53");
    if (bind(myfd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        perror("bind");
        exit(1);
    }
    if (listen(myfd, SOMAXCONN) == -1) {
        perror("listen");
        exit(1);
    }

    for (;;) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);

        int nfd = accept(myfd, (struct sockaddr *)&cli, &cli_len);
        if (nfd == -1) {
            perror("accept");
            exit(1);
        }

        char b[1024 * 1024];
        ssize_t sz = recv(nfd, b, sizeof(b), 0);
        if (sz <= 0) {
            perror("recv");
            exit(1);
        }
        if (sz < 4) {
            close(nfd);
            continue;
        }

        /* Copy the TCP len to the beginning of the reply packet */
        *((uint16_t *)rbuf) = htons(rlen - 2);
        /* Copy the DNS request ID back */
        memcpy((char *)&rbuf[2], &b[2], 2);

        if (send(nfd, rbuf, rlen, MSG_NOSIGNAL) == -1) {
            if (errno != ECONNRESET) {
                perror("send");
                exit(1);
            }
        }

        close(nfd);
    }

    return NULL;
}

static void launchthr(void) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024 * 4);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_t t;
    if (pthread_create(&t, &attr, getdata, NULL) < 0) {
        perror("pthread_create");
        exit(1);
    }
}

/* main entry point, possibly hooked */
int main(int argc, char *argv[]) {
    /* Use TCP connections for DNS */
    setenv("RES_OPTIONS", "use-vc", 1);
    res_init();

    if (getenv("NO_FUZZ") == NULL) {
        unsh();
        launchthr();
    }

    /* Wait for the DNS server to set up */
    usleep(100000);

    for (;;) {
        const char *buf;
        size_t len;
        HF_ITER((const uint8_t **)&buf, &len);
        rlen = 0;
        rbuf = NULL;

        if (len < 8) {
            continue;
        }

        uint32_t tmplen = *((const uint32_t *)buf);

        buf = &buf[sizeof(uint32_t)];
        len -= sizeof(uint32_t);

        tmplen %= len;

        rbuf = &buf[tmplen];
        rlen = len - tmplen;
        len = tmplen;

        char b[1024 * 1024];
        strncpy(b, buf, len);
        b[len] = '\0';

        gethostbyname(b);

        struct hostent he;
        struct hostent *result;
        char sbuf[1024 * 32];

        extern int h_errno;
        gethostbyname2_r(b, AF_INET, &he, sbuf, sizeof(sbuf), &result, &h_errno);
        gethostbyname2_r(b, AF_INET6, &he, sbuf, sizeof(sbuf), &result, &h_errno);

        struct addrinfo *res = NULL;
        if (getaddrinfo(b, NULL, NULL, &res) == 0) {
            freeaddrinfo(res);
        }
    }
}
