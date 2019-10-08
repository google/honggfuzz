#ifdef __cplusplus
extern "C" {
#endif

#include <hf_ssl_lib.h>
#include <libhfuzz/libhfuzz.h>

#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    HFInit();
    HFResetRand();

    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    EVP_PKEY* key = d2i_AutoPrivateKey(NULL, &buf, len);
    if (key == NULL) {
        fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
    }
    EVP_PKEY_free(key);
    return 0;
}

#ifdef __cplusplus
}
#endif
