#include <ctype.h>
#include <string.h>

#include "instrument.h"

__attribute__ ((always_inline))
static inline int _strcmp(const char *s1, const char *s2, void *addr)
{
    unsigned int v = 0;

    size_t i;
    for (i = 0; s1[i] == s2[i]; i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
        v++;
    }
    libhfuzz_instrumentUpdateCmpMap(addr, v);
    return (s1[i] - s2[i]);
}

int __wrap_strcmp(const char *s1, const char *s2)
{
    return _strcmp(s1, s2, __builtin_return_address(0));
}

__attribute__ ((always_inline))
static inline int _strcasecmp(const char *s1, const char *s2, void *addr)
{
    unsigned int v = 0;

    size_t i;
    for (i = 0; tolower(s1[i]) == tolower(s2[i]); i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
        v++;
    }
    libhfuzz_instrumentUpdateCmpMap(addr, v);
    return (tolower(s1[i]) - tolower(s2[i]));
}

int __wrap_strcasecmp(const char *s1, const char *s2)
{
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

__attribute__ ((always_inline))
static inline int _strncmp(const char *s1, const char *s2, size_t n, void *addr)
{
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

    libhfuzz_instrumentUpdateCmpMap(addr, v);
    return ret;
}

int __wrap_strncmp(const char *s1, const char *s2, size_t n)
{
    return _strncmp(s1, s2, n, __builtin_return_address(0));
}

__attribute__ ((always_inline))
static inline int _strncasecmp(const char *s1, const char *s2, size_t n, void *addr)
{
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

    libhfuzz_instrumentUpdateCmpMap(addr, v);
    return ret;
}

int __wrap_strncasecmp(const char *s1, const char *s2, size_t n)
{
    return _strncasecmp(s1, s2, n, __builtin_return_address(0));
}

char *__wrap_strstr(const char *haystack, const char *needle)
{
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (_strncmp(&haystack[i], needle, needle_len, __builtin_return_address(0)) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

char *__wrap_strcasestr(const char *haystack, const char *needle)
{
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (_strncasecmp(&haystack[i], needle, needle_len, __builtin_return_address(0)) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

__attribute__ ((always_inline))
static inline int _memcmp(const void *m1, const void *m2, size_t n, void *addr)
{
    if (n == 0) {
        return 0;
    }

    unsigned int v = 0;
    int ret = 0;

    const unsigned char *s1 = (const unsigned char *)m1;
    const unsigned char *s2 = (const unsigned char *)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            ret = ret ? ret : (s1[i] - s2[i]);
        } else {
            v++;
        }
    }

    libhfuzz_instrumentUpdateCmpMap(addr, v);
    return ret;
}

int __wrap_memcmp(const void *m1, const void *m2, size_t n)
{
    return (_memcmp(m1, m2, n, __builtin_return_address(0)));
}

int __wrap_bcmp(const void *m1, const void *m2, size_t n)
{
    return (_memcmp(m1, m2, n, __builtin_return_address(0)));
}

void *__wrap_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
    if (needlelen > haystacklen) {
        return NULL;
    }
    if (needlelen == 0) {
        return (void *)haystack;
    }

    const char *h = haystack;
    for (size_t i = 0; i <= (haystacklen - needlelen); i++) {
        if (_memcmp(&h[i], needle, needlelen, __builtin_return_address(0)) == 0) {
            return (void *)(&h[i]);
        }
    }
    return NULL;
}

/*
 * Better instrumentation of *SSL libs
 */
int __wrap_CRYPTO_memcmp(const void *m1, const void *m2, size_t len)
{
    return _memcmp(m1, m2, len, __builtin_return_address(0));
}

int __wrap_OPENSSL_memcmp(const void *m1, const void *m2, size_t len)
{
    return _memcmp(m1, m2, len, __builtin_return_address(0));
}

int __wrap_OPENSSL_strcasecmp(const char *s1, const char *s2)
{
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int __wrap_OPENSSL_strncasecmp(const char *s1, const char *s2, size_t len)
{
    return _strncasecmp(s1, s2, len, __builtin_return_address(0));
}
