#include <openssl/rand.h>

static int rnd(unsigned char* buf, int num)
{
    for (size_t v = 0; v < num; v++) {
        buf[v] = v + 1;
    }
    return 1;
}

static int stat(void)
{
    return 1;
}

static RAND_METHOD fuzz_rand_method = {
    NULL,
    rnd,
    NULL,
    NULL,
    rnd,
    stat
};

void ResetRand(void)
{
    RAND_set_rand_method(&fuzz_rand_method);
}
