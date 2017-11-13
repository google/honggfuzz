#include <ctype.h>
#include <string.h>

#include "instrument.h"

static inline int _strcmp(const char* s1, const char* s2, void* addr) {
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

static inline int _strcasecmp(const char* s1, const char* s2, void* addr) {
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

static inline int _strncmp(const char* s1, const char* s2, size_t n, void* addr) {
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

static inline int _strncasecmp(const char* s1, const char* s2, size_t n, void* addr) {
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

static inline char* _strstr(const char* haystack, const char* needle, void* addr) {
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (_strncmp(&haystack[i], needle, needle_len, addr) == 0) {
            return (char*)(&haystack[i]);
        }
    }
    return NULL;
}

static inline char* _strcasestr(const char* haystack, const char* needle, void* addr) {
    size_t needle_len = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (_strncasecmp(&haystack[i], needle, needle_len, addr) == 0) {
            return (char*)(&haystack[i]);
        }
    }
    return NULL;
}

static inline int _memcmp(const void* m1, const void* m2, size_t n, void* addr) {
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

static inline void* _memmem(
    const void* haystack, size_t haystacklen, const void* needle, size_t needlelen, void* addr) {
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

/*
 *  Exported wrappers taking return address as an argument
 */
int hfuzz_strcmp(const char* s1, const char* s2, void* addr) { return _strcmp(s1, s2, addr); }

int hfuzz_strcasecmp(const char* s1, const char* s2, void* addr) {
    return _strcasecmp(s1, s2, addr);
}

int hfuzz_strncmp(const char* s1, const char* s2, size_t n, void* addr) {
    return _strncmp(s1, s2, n, addr);
}

int hfuzz_strncasecmp(const char* s1, const char* s2, size_t n, void* addr) {
    return _strncasecmp(s1, s2, n, addr);
}

char* hfuzz_strstr(const char* haystack, const char* needle, void* addr) {
    return _strstr(haystack, needle, addr);
}

char* hfuzz_strcasestr(const char* haystack, const char* needle, void* addr) {
    return _strcasestr(haystack, needle, addr);
}

int hfuzz_memcmp(const void* m1, const void* m2, size_t n, void* addr) {
    return _memcmp(m1, m2, n, addr);
}

void* hfuzz_memmem(
    const void* haystack, size_t haystacklen, const void* needle, size_t needlelen, void* addr) {
    return _memmem(haystack, haystacklen, needle, needlelen, addr);
}

/*
 * Typical libc wrappers
 */
int __wrap_strcmp(const char* s1, const char* s2) {
    return _strcmp(s1, s2, __builtin_return_address(0));
}

int __wrap_strcasecmp(const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int __wrap_strncmp(const char* s1, const char* s2, size_t n) {
    return _strncmp(s1, s2, n, __builtin_return_address(0));
}

int __wrap_strncasecmp(const char* s1, const char* s2, size_t n) {
    return _strncasecmp(s1, s2, n, __builtin_return_address(0));
}

char* __wrap_strstr(const char* haystack, const char* needle) {
    return _strstr(haystack, needle, __builtin_return_address(0));
}

char* __wrap_strcasestr(const char* haystack, const char* needle) {
    return _strcasestr(haystack, needle, __builtin_return_address(0));
}

int __wrap_memcmp(const void* m1, const void* m2, size_t n) {
    return _memcmp(m1, m2, n, __builtin_return_address(0));
}

int __wrap_bcmp(const void* m1, const void* m2, size_t n) {
    return _memcmp(m1, m2, n, __builtin_return_address(0));
}

void* __wrap_memmem(
    const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    return _memmem(haystack, haystacklen, needle, needlelen, __builtin_return_address(0));
}

/*
 * Apache's httpd wrappers
 */
int __wrap_ap_cstr_casecmp(const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int __wrap_ap_cstr_casecmpn(const char* s1, const char* s2, size_t n) {
    return _strncasecmp(s1, s2, n, __builtin_return_address(0));
}

const char* __wrap_ap_strcasestr(const char* s1, const char* s2) {
    return _strcasestr(s1, s2, __builtin_return_address(0));
}

int __wrap_apr_cstr_casecmp(const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int __wrap_apr_cstr_casecmpn(const char* s1, const char* s2, size_t n) {
    return _strncasecmp(s1, s2, n, __builtin_return_address(0));
}

/*
 * *SSL wrappers
 */
int __wrap_CRYPTO_memcmp(const void* m1, const void* m2, size_t len) {
    return _memcmp(m1, m2, len, __builtin_return_address(0));
}

int __wrap_OPENSSL_memcmp(const void* m1, const void* m2, size_t len) {
    return _memcmp(m1, m2, len, __builtin_return_address(0));
}

int __wrap_OPENSSL_strcasecmp(const char* s1, const char* s2) {
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int __wrap_OPENSSL_strncasecmp(const char* s1, const char* s2, size_t len) {
    return _strncasecmp(s1, s2, len, __builtin_return_address(0));
}

/*
 * libXML wrappers
 */
int __wrap_xmlStrncmp(const char* s1, const char* s2, int len) {
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
    return _strncmp(s1, s2, (size_t)len, __builtin_return_address(0));
}

int __wrap_xmlStrcmp(const char* s1, const char* s2) {
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return _strcmp(s1, s2, __builtin_return_address(0));
}

int __wrap_xmlStrEqual(const char* s1, const char* s2) {
    if (s1 == s2) {
        return 1;
    }
    if (s1 == NULL) {
        return 0;
    }
    if (s2 == NULL) {
        return 0;
    }
    if (_strcmp(s1, s2, __builtin_return_address(0)) == 0) {
        return 1;
    }
    return 0;
}

int __wrap_xmlStrcasecmp(const char* s1, const char* s2) {
    if (s1 == s2) {
        return 0;
    }
    if (s1 == NULL) {
        return -1;
    }
    if (s2 == NULL) {
        return 1;
    }
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int __wrap_xmlStrncasecmp(const char* s1, const char* s2, int len) {
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
    return _strncasecmp(s1, s2, (size_t)len, __builtin_return_address(0));
}

const char* __wrap_xmlStrstr(const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return _strstr(haystack, needle, __builtin_return_address(0));
}

const char* __wrap_xmlStrcasestr(const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return _strcasestr(haystack, needle, __builtin_return_address(0));
}
