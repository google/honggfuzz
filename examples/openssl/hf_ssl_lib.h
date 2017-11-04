#include <openssl/opensslv.h>
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#define HF_SSL_IS_LIBRESSL 1
#endif
#if defined(BORINGSSL_API_VERSION)
#define HF_SSL_IS_BORINGSSL 1
#endif
#if !defined(LIBRESSL_VERSION_NUMBER) && !defined(BORINGSSL_API_VERSION)
#define HF_SSL_IS_OPENSSL 1
#endif

#if defined(HF_SSL_IS_BORINGSSL)
static int hf_rnd(unsigned char* buf, unsigned long num)
#else /* defined(HF_SSL_IS_OPENSSL) */
static int hf_rnd(unsigned char* buf, int num)
#endif /* defined(HF_SSL_IS_OPENSSL) */
{
    for (size_t v = 0; v < num; v++) {
        buf[v] = v + 1;
    }
    return 1;
}

static int hf_stat(void) { return 1; }

static RAND_METHOD hf_method = {
    NULL,
    hf_rnd,
    NULL,
    NULL,
    hf_rnd,
    hf_stat,
};

static void HFResetRand(void) { RAND_set_rand_method(&hf_method); }

#ifdef __cplusplus
} // extern "C"
#endif
