#include <string.h>
#include <ctype.h>

int strcmp(const char *s1, const char *s2)
{
    for (size_t i = 0; s1[i] || s2[i]; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

int strcasecmp(const char *s1, const char *s2)
{
    for (size_t i = 0; s1[i] || s2[i]; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return (tolower(s1[i]) - tolower(s2[i]));
        }
    }
    return 0;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; (s1[i] || s2[i]) && i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; (s1[i] || s2[i]) && i < n; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return (tolower(s1[i]) - tolower(s2[i]));
        }
    }
    return 0;
}

char *strstr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (strcmp(&haystack[i], needle) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

char *strcasestr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (strcasecmp(&haystack[i], needle) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

int memcmp(const void *m1, const void *m2, size_t n)
{
    const char *s1 = (const char *)m1;
    const char *s2 = (const char *)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

int bcmp(const void *m1, const void *m2, size_t n)
{
    const char *s1 = (const char *)m1;
    const char *s2 = (const char *)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
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
        if (memcmp(&h[i], needle, needlelen) == 0) {
            return (void *)(&h[i]);
        }
    }
    return NULL;
}
