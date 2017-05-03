#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int close(int fd)
{
    if (fd == 1022 || fd == 1023) {
        return 0;
    }
    return syscall(__NR_close, fd);
}

int fcntl(int fd, int cmd, uintptr_t a1, uintptr_t a2)
{
    if (fd == 1022 || fd == 1023) {
        errno = EBADF;
        return -1;
    }
    return syscall(__NR_fcntl, fd, cmd, a1, a2);
}
