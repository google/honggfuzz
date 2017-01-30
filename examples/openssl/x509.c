/* Based on BoringSSL's cert.c fuzzer */

#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t * buf, size_t len)
{
    const uint8_t *b = buf;
    X509 *x = d2i_X509(NULL, &b, len);
    if (x) {
        BIO *o = BIO_new_fp(stdout, BIO_NOCLOSE);
        X509_print_ex(o, x, XN_FLAG_RFC2253, X509_FLAG_COMPAT);
        X509_free(x);
        BIO_free(o);
    }

    return 0;
}
