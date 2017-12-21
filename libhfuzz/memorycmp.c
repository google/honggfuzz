#include <ctype.h>
#include <inttypes.h>
#include <string.h>

#include "libhfuzz/instrument.h"

int hfuzz_module_memorycmp = 0;

#if !defined(_HF_USE_RET_ADDR)
/* Use just single ret-address */
#define RET_CALL_CHAIN (uintptr_t) __builtin_return_address(0)
#elif _HF_USE_RET_ADDR == 2
/* Use mix of two previous return addresses - unsafe */
#define RET_CALL_CHAIN \
    ((uintptr_t)__builtin_return_address(0)) ^ ((uintptr_t)__builtin_return_address(1) << 12)
#elif _HF_USE_RET_ADDR == 3
/* Use mix of three previous returen addresses - unsafe */
#define RET_CALL_CHAIN                                                                         \
    ((uintptr_t)__builtin_return_address(0)) ^ ((uintptr_t)__builtin_return_address(1) << 8) ^ \
        ((uintptr_t)__builtin_return_address(2) << 16)
#else
#error "Unknown value of _HF_USE_RET_ADDR"
#endif /* !defined(_HF_USE_RET_ADDR_1) */

static inline int _strcmp(const char* s1, const char* s2, uintptr_t addr) {
    unsigned int v = 0;

    size_t i;
    for (i = 0; s1[i] == s2[i]; i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
        v++;
    }
    instrumentUpdateCmpMap(addr, v);
    return (s1[i] - s2[i]);
}

static inline int _strcasecmp(const char* s1, const char* s2, uintptr_t addr) {
    unsigned int v = 0;

    size_t i;
    for (i = 0; tolower(s1[i]) == tolower(s2[i]); i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
        v++;
    }
    instrumentUpdateCmpMap(addr, v);
    return (tolower(s1[i]) - tolower(s2[i]));
}

static inline int _strncmp(const char* s1, const char* s2, size_t n, uintptr_t addr) {
    if (n == 0) {
        return 0;
    }

    unsigned int v = 0;
    int ret = 0;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            ret = ret ? ret : ((unsigned char)s1[i] - (unsigned char)s2[i]);
        } else {
            v++;
        }
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    instrumentUpdateCmpMap(addr, v);
    return ret;
}

static inline int _strncasecmp(const char* s1, const char* s2, size_t n, uintptr_t addr) {
    if (n == 0) {
        return 0;
    }

    unsigned int v = 0;
    int ret = 0;

    for (size_t i = 0; i < n; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            ret = ret ? ret : (tolower(s1[i]) - tolower(s2[i]));
        } else {
            v++;
        }
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    instrumentUpdateCmpMap(addr, v);
    return ret;
}

static inline char* _strstr(const char* haystack, const char* needle, uintptr_t addr) {
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (_strncmp(&haystack[i], needle, needle_len, addr) == 0) {
            return (char*)(&haystack[i]);
        }
    }
    return NULL;
}

static inline char* _strcasestr(const char* haystack, const char* needle, uintptr_t addr) {
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (_strncasecmp(&haystack[i], needle, needle_len, addr) == 0) {
            return (char*)(&haystack[i]);
        }
    }
    return NULL;
}

static inline int _memcmp(const void* m1, const void* m2, size_t n, uintptr_t addr) {
    if (n == 0) {
        return 0;
    }

    unsigned int v = 0;
    int ret = 0;

    const unsigned char* s1 = (const unsigned char*)m1;
    const unsigned char* s2 = (const unsigned char*)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            ret = ret ? ret : (s1[i] - s2[i]);
        } else {
            v++;
        }
    }

    instrumentUpdateCmpMap(addr, v);
    return ret;
}

static inline void* _memmem(const void* haystack, size_t haystacklen, const void* needle,
    size_t needlelen, uintptr_t addr) {
    if (needlelen > haystacklen) {
        return NULL;
    }
    if (needlelen == 0) {
        return (void*)haystack;
    }

    const char* h = haystack;
    for (size_t i = 0; i <= (haystacklen - needlelen); i++) {
        if (_memcmp(&h[i], needle, needlelen, addr) == 0) {
            return (void*)(&h[i]);
        }
    }
    return NULL;
}

/* Define a weak function x, as well as __wrap_x pointing to x */
#define XVAL(x) x
#define HF_WEAK_WRAP(ret, func, ...)                                          \
    __attribute__((alias(#func))) XVAL(ret) XVAL(__wrap_##func)(__VA_ARGS__); \
    __attribute__((weak)) XVAL(ret) XVAL(func)(__VA_ARGS__)

/* Typical libc wrappers */
HF_WEAK_WRAP(int, strcmp, const char* s1, const char* s2) {
    return _strcmp(s1, s2, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(int, strcasecmp, const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(int, strncmp, const char* s1, const char* s2, size_t n) {
    return _strncmp(s1, s2, n, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(int, strncasecmp, const char* s1, const char* s2, size_t n) {
    return _strncasecmp(s1, s2, n, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(char*, strstr, const char* haystack, const char* needle) {
    return _strstr(haystack, needle, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(char*, strcasestr, const char* haystack, const char* needle) {
    return _strcasestr(haystack, needle, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(int, memcmp, const void* m1, const void* m2, size_t n) {
    return _memcmp(m1, m2, n, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(int, bcmp, const void* m1, const void* m2, size_t n) {
    return _memcmp(m1, m2, n, RET_CALL_CHAIN);
}
HF_WEAK_WRAP(
    void*, memmem, const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    return _memmem(haystack, haystacklen, needle, needlelen, RET_CALL_CHAIN);
}

/*
 * Apache's httpd wrappers
 */
HF_WEAK_WRAP(int, ap_cstr_casecmp, const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, ap_cstr_casecmpn, const char* s1, const char* s2, size_t n) {
    return _strncasecmp(s1, s2, n, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(const char*, ap_strcasestr, const char* s1, const char* s2) {
    return _strcasestr(s1, s2, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, apr_cstr_casecmp, const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, apr_cstr_casecmpn, const char* s1, const char* s2, size_t n) {
    return _strncasecmp(s1, s2, n, RET_CALL_CHAIN);
}

/*
 * *SSL wrappers
 */
HF_WEAK_WRAP(int, CRYPTO_memcmp, const void* m1, const void* m2, size_t len) {
    return _memcmp(m1, m2, len, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, OPENSSL_memcmp, const void* m1, const void* m2, size_t len) {
    return _memcmp(m1, m2, len, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, OPENSSL_strcasecmp, const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, OPENSSL_strncasecmp, const char* s1, const char* s2, size_t len) {
    return _strncasecmp(s1, s2, len, RET_CALL_CHAIN);
}

/*
 * libXML wrappers
 */
HF_WEAK_WRAP(int, xmlStrncmp, const char* s1, const char* s2, int len) {
    if (len <= 0) {
        return 0;
    }
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return _strncmp(s1, s2, (size_t)len, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, xmlStrcmp, const char* s1, const char* s2) {
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return _strcmp(s1, s2, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, xmlStrEqual, const char* s1, const char* s2) {
    if (s1 == s2) {
        return 1;
    }
    if (s1 == NULL) {
        return 0;
    }
    if (s2 == NULL) {
        return 0;
    }
    if (_strcmp(s1, s2, RET_CALL_CHAIN) == 0) {
        return 1;
    }
    return 0;
}

HF_WEAK_WRAP(int, xmlStrcasecmp, const char* s1, const char* s2) {
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return _strcasecmp(s1, s2, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(int, xmlStrncasecmp, const char* s1, const char* s2, int len) {
    if (len <= 0) {
        return 0;
    }
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return _strncasecmp(s1, s2, (size_t)len, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(const char*, xmlStrstr, const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return _strstr(haystack, needle, RET_CALL_CHAIN);
}

HF_WEAK_WRAP(const char*, xmlStrcasestr, const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return _strcasestr(haystack, needle, RET_CALL_CHAIN);
}
