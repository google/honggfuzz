#include <openssl/err.h>
#include <openssl/evp.h>
#include <inttypes.h>

#include <libhfuzz.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len)
{
    EVP_PKEY_free(d2i_AutoPrivateKey(NULL, &buf, len));
    return 0;
}

#ifdef __cplusplus
}
#endif
