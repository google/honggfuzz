#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

static int hf_rnd(unsigned char* buf, int num)
{
    for (size_t v = 0; v < num; v++) {
        buf[v] = v + 1;
    }
    return 1;
}

static int hf_stat(void)
{
    return 1;
}

static RAND_METHOD hf_method = {
    NULL,
    hf_rnd,
    NULL,
    NULL,
    hf_rnd,
    hf_stat,
};

void HFResetRand(void)
{
    RAND_set_rand_method(&hf_method);
}

#ifdef __cplusplus
} // extern "C"
#endif
