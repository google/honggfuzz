#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <libhfuzz/libhfuzz.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#define HF_SSL_IS_LIBRESSL 1
#endif
#if defined(BORINGSSL_API_VERSION)
#define HF_SSL_IS_BORINGSSL 1
#endif
#if !defined(LIBRESSL_VERSION_NUMBER) && !defined(BORINGSSL_API_VERSION) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000
#define HF_SSL_IS_OPENSSL_GE_1_1 1
#endif
#if !defined(LIBRESSL_VERSION_NUMBER) && !defined(BORINGSSL_API_VERSION) && \
    defined(OPENSSL_VERSION_NUMBER)
#define HF_SSL_IS_OPENSSL
#endif

#if defined(HF_SSL_IS_BORINGSSL)
static int hf_rnd(unsigned char* buf, size_t num)
#else  /* defined(HF_SSL_IS_BORINGSSL) */
static int hf_rnd(unsigned char* buf, int num)
#endif /* defined(HF_SSL_IS_BORINGSSL) */
{
    for (size_t v = 0; v < num; v++) {
        buf[v] = v + 1;
    }
    return 1;
}

static int hf_stat(void) {
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

static void HFResetRand(void) {
    RAND_set_rand_method(&hf_method);
}

#if defined(HF_SSL_FROM_STDIN)
int LLVMFuzzerInitialize(int* argc, char*** argv) __attribute__((weak));

int main(int argc, char** argv) {
    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }
    return LLVMFuzzerTestOneInput(NULL, 0U);
}
#endif /* defined(HF_SSL_FROM_STDIN) */
#ifdef __cplusplus
}  // extern "C"
#endif

static void HFInit(void) {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();
}
