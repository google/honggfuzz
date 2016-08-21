#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __clang__
#include <stdatomic.h>
#endif

#ifdef _HF_ARCH_DARWIN
#include <stdlib.h>
#define EXITALL(x)  exit(x)
#else
#define EXITALL(x)  syscall(__NR_exit_group, x)
#endif

#define ATOMIC_PRE_INC(x) __atomic_add_fetch(&(x), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_POST_OR(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_SEQ_CST)

static uint8_t *bbMap;
static uint64_t *bbCnt;
static size_t bbSz;
static pid_t mypid;

__attribute__ ((constructor))
static void mapBB(void)
{
    mypid = getpid();
    struct stat st;
    if (fstat(1022, &st) == -1) {
        perror("stat");
        EXITALL(1);
    }
    bbSz = st.st_size - (1024 * 1024);
    if ((bbMap = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, 1022, 0)) == MAP_FAILED) {
        perror("mmap");
        EXITALL(1);
    }
    bbCnt = (uint64_t *) & bbMap[bbSz];
    bbCnt[mypid] = 0;
}

void __cyg_profile_func_enter(void *func, void *caller)
{
    size_t pos = (((uintptr_t) func << 12) ^ ((uintptr_t) caller & 0xFFF)) % (bbSz * 8);
    size_t byteOff = pos / 8;
    uint8_t bitSet = (uint8_t) (1 << (pos % 8));

    register uint8_t prev = ATOMIC_POST_OR(bbMap[byteOff], bitSet);
    if (!(prev & bitSet)) {
        ATOMIC_PRE_INC(bbCnt[mypid]);
    }
}

void __cyg_profile_func_exit(void *func __attribute__ ((unused)), void *caller
                             __attribute__ ((unused)))
{
}
