#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int close(int fd) {
    if (fd == 1022 || fd == 1023) {
        return 0;
    }
    return syscall(__NR_close, fd);
}

int fcntl(int __fd, int __cmd, ...) {
    va_list ap;
    va_start(ap, __cmd);
    int a1 = va_arg(ap, int);
    int a2 = va_arg(ap, int);
    int a3 = va_arg(ap, int);
    int a4 = va_arg(ap, int);
    va_end(ap);

    if (__fd == 1022 || __fd == 1023) {
        if (__cmd == F_SETFD) {
            a1 &= ~(FD_CLOEXEC);
        }
    }

    return syscall(__NR_fcntl, __fd, __cmd, a1, a2, a3, a4);
}
