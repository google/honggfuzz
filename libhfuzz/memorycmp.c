#define NULL ((void*)0)
typedef unsigned long size_t;

#include "instrument.h"

extern int tolower(int c);

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

int strcmp(const char *s1, const char *s2)
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

int strcasecmp(const char *s1, const char *s2)
{
    return _strcasecmp(s1, s2, __builtin_return_address(0));
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }

    unsigned int v = 0;

    size_t i = 0;
    for (i = 0; (s1[i] == s2[i]) && i < n; i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
        v++;
    }
    libhfuzz_instrumentUpdateCmpMap(__builtin_return_address(0), v);
    if (i == n) {
        return 0;
    }
    return (s1[i] - s2[i]);
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0) {
        return 0;
    }

    unsigned int v = 0;

    size_t i = 0;
    for (i = 0; (tolower(s1[i]) == tolower(s2[i])) && i < n; i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
        v++;
    }
    libhfuzz_instrumentUpdateCmpMap(__builtin_return_address(0), v);
    if (i == n) {
        return 0;
    }
    return (s1[i] - s2[i]);
}

char *strstr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (_strcmp(&haystack[i], needle, __builtin_return_address(0)) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

char *strcasestr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (_strcasecmp(&haystack[i], needle, __builtin_return_address(0)) == 0) {
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

    const char *s1 = (const char *)m1;
    const char *s2 = (const char *)m2;

    size_t i = 0;
    for (i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            break;
        }
        v++;
    }
    libhfuzz_instrumentUpdateCmpMap(addr, v);
    if (i == n) {
        return 0;
    }
    return (s1[i] - s2[i]);
}

int memcmp(const void *m1, const void *m2, size_t n)
{
    return (_memcmp(m1, m2, n, __builtin_return_address(0)));
}

int bcmp(const void *m1, const void *m2, size_t n)
{
    return (_memcmp(m1, m2, n, __builtin_return_address(0)));
}

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
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
