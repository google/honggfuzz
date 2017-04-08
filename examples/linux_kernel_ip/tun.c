#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

void HF_ITER(uint8_t**, size_t*);

void fatal(const char* fmt, ...)
{
    fprintf(stdout, "[-] ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fprintf(stdout, "\n");

    exit(1);
}

void pfatal(const char* fmt, ...)
{
    fprintf(stdout, "[-] ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fprintf(stdout, ": %s\n", strerror(errno));

    exit(1);
}

void mlog(const char* fmt, ...)
{
    fprintf(stdout, "[+] ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fprintf(stdout, "\n");
}

int main(void)
{
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
        pfatal("unshare()");
    }

    struct ifreq ifr;
    memset(&ifr, '\0', sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_NOFILTER;
    strcpy(ifr.ifr_name, "FUZZ0");

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        pfatal("open('/dev/net/tun')");
    }
    if (ioctl(fd, TUNSETIFF, (void*)&ifr) != 0) {
        pfatal("ioctl(TUNSETIFF)");
    }
    if (ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO_ECN | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO) == -1) {
        pfatal("ioctl(fd, TUNSETOFFLOAD)");
    }

    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == -1) {
        pfatal("socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)");
    }
    int tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_sock == -1) {
        pfatal("socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
    }
    int sctp_sock = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (sctp_sock == -1) {
        pfatal("socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)");
    }
    int udp_lite_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE);
    if (udp_lite_sock == -1) {
        pfatal("socket(AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE)");
    }

    int disable = 1;
    if (setsockopt(udp_sock, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) == -1) {
        pfatal("setsockopt(udp_sock, SOL_SOCKET, SO_NO_CHECK)");
    }
    if (setsockopt(tcp_sock, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) == -1) {
        pfatal("setsockopt(tcp_sock, SOL_SOCKET, SO_NO_CHECK)");
    }
    const uint8_t md5s[TCP_MD5SIG_MAXKEYLEN] = { 0 };
    setsockopt(tcp_sock, SOL_TCP, TCP_MD5SIG, (void*)md5s, sizeof(md5s));
    if (setsockopt(sctp_sock, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) == -1) {
        pfatal("setsockopt(sctp_sock, SOL_SOCKET, SO_NO_CHECK)");
    }
    if (setsockopt(udp_lite_sock, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) == -1) {
        pfatal("setsockopt(udp_lite_sock, SOL_SOCKET, SO_NO_CHECK)");
    }

    struct sockaddr_in* sa = (struct sockaddr_in*)(&ifr.ifr_addr);
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr("192.168.255.1");
    if (ioctl(tcp_sock, SIOCSIFADDR, &ifr) == -1) {
        pfatal("ioctl(tcp_sock, SIOCSIFADDR, &ifr)");
    }
    sa->sin_addr.s_addr = inet_addr("192.168.255.2");
    if (ioctl(tcp_sock, SIOCSIFDSTADDR, &ifr) == -1) {
        pfatal("ioctl(tcp_sock, SIOCSIFDSTADDR, &ifr)");
    }

    if (ioctl(tcp_sock, SIOCGIFFLAGS, &ifr) == -1) {
        pfatal("ioctl(tcp_sock, SIOCGIFFLAGS, &ifr)");
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(tcp_sock, SIOCSIFFLAGS, &ifr) == -1) {
        pfatal("ioctl(tcp_sock, SIOCSIFFLAGS, &ifr)");
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(1337),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(tcp_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        pfatal("bind(tcp)");
    }
    if (bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        pfatal("bind(udp)");
    }
    if (bind(sctp_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        pfatal("bind(sctp)");
    }
    if (bind(udp_lite_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        pfatal("bind(udp_lite)");
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR) == -1) {
        pfatal("fcntl(fd, F_SETFL, O_NONBLOCK|O_RDWR)");
    }
    if (fcntl(tcp_sock, F_SETFL, O_NONBLOCK | O_RDWR) == -1) {
        pfatal("fcntl(tcp_sock, F_SETFL, O_NONBLOCK|O_RDWR)");
    }
    if (fcntl(udp_sock, F_SETFL, O_NONBLOCK | O_RDWR) == -1) {
        pfatal("fcntl(udp_sock, F_SETFL, O_NONBLOCK|O_RDWR)");
    }
    if (fcntl(sctp_sock, F_SETFL, O_NONBLOCK | O_RDWR) == -1) {
        pfatal("fcntl(sctp_sock, F_SETFL, O_NONBLOCK|O_RDWR)");
    }
    if (fcntl(udp_lite_sock, F_SETFL, O_NONBLOCK | O_RDWR) == -1) {
        pfatal("fcntl(udp_lite_sock, F_SETFL, O_NONBLOCK|O_RDWR)");
    }

    if (listen(tcp_sock, SOMAXCONN) == -1) {
        pfatal("listen(tcp_sock)");
    }
    if (listen(sctp_sock, SOMAXCONN) == -1) {
        pfatal("listen(sctp_sock)");
    }

    int tcp_acc_sock = -1;

    for (;;) {
        char b[1024 * 128];
        for (;;) {
            if (read(fd, b, sizeof(b)) <= 0) {
                break;
            }
        }

        uint8_t* buf;
        size_t len;

        HF_ITER(&buf, &len);

        const size_t pkt_size = 1400UL;
        size_t num_iov = 0;
        if (len > 0) {
            num_iov = ((len - 1) / pkt_size) + 1;
        }
        for (size_t i = 0; i < num_iov; i++) {
            size_t off = pkt_size * i;
            size_t sz = ((len - off) > pkt_size) ? pkt_size : (len - off);
            write(fd, &buf[off], sz);

            char b[1024 * 128];
            for (;;) {
                if (read(fd, b, sizeof(b)) <= 0) {
                    break;
                }
            }

            if (tcp_acc_sock == -1) {
                struct sockaddr_in nsock;
                socklen_t slen = sizeof(nsock);
                tcp_acc_sock = accept4(tcp_sock, (struct sockaddr*)&nsock, &slen, SOCK_NONBLOCK);
            }
            if (tcp_acc_sock != -1) {
                if (recv(tcp_acc_sock, b, sizeof(b), MSG_DONTWAIT) == 0) {
                    close(tcp_acc_sock);
                    tcp_acc_sock = -1;
                }
                send(tcp_acc_sock, b, 1, MSG_NOSIGNAL | MSG_DONTWAIT);
            }

            struct sockaddr_in addr;
            socklen_t slen = sizeof(addr);
            if (recvfrom(udp_sock, b, sizeof(b), MSG_DONTWAIT, (struct sockaddr*)&addr, &slen) > 0) {
                sendto(udp_sock, b, 1, MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr*)&addr, slen);
            }

            slen = sizeof(addr);
            if (recvfrom(sctp_sock, b, sizeof(b), MSG_DONTWAIT, (struct sockaddr*)&addr, &slen) > 0) {
                sendto(sctp_sock, b, 1, MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr*)&addr, slen);
            }

            slen = sizeof(addr);
            if (recvfrom(udp_lite_sock, b, sizeof(b), MSG_DONTWAIT, (struct sockaddr*)&addr, &slen) > 0) {
                sendto(udp_lite_sock, b, 1, MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr*)&addr, slen);
            }
        }
    }
}
