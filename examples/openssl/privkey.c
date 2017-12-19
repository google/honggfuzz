#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <hf_ssl_lib.h>
#include <libhfuzz/libhfuzz.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerInitialize(int* argc, char*** argv) {
    HFInit();
    HFResetRand();

    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
    EVP_PKEY_free(d2i_AutoPrivateKey(NULL, &buf, len));
    return 0;
}

#ifdef __cplusplus
}
#endif
