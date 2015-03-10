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
