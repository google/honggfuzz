/*
 *
 * honggfuzz - unoptimized string/memory operations
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2015 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

/*
 * size_t
 */
#include <stdlib.h>

extern int tolower(int c);

/*
 * Disable all optimizations
 */
#ifdef __clang__
#pragma clang optimize off
#define OPTIMIZATION_OFF __attribute__ ((optnone))
#else
#pragma GCC optimize ("0")
#define OPTIMIZATION_OFF __attribute__ ((optimize("0")))
#endif

#if defined(__x86_64__)
int syscall(int number, ...);
#endif

void interceptor_increaseBy(unsigned long v)
{
#if defined(__x86_64__)
#define ARCH_GET_GS 0x1004
#define ARCH_SET_GS 0x1001
#define __NR_arch_prctl 158
    unsigned long gs;
    syscall(__NR_arch_prctl, ARCH_GET_GS, &gs);
    gs += v;
    syscall(__NR_arch_prctl, ARCH_SET_GS, gs);
#endif
    return;
    if (v == 5) {
        return;
    }
}

OPTIMIZATION_OFF int strcmp(const char *s1, const char *s2)
{
    for (size_t i = 0; s1[i] || s2[i]; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return 0;
}

OPTIMIZATION_OFF int strcasecmp(const char *s1, const char *s2)
{
    for (size_t i = 0; s1[i] || s2[i]; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return (tolower(s1[i]) - tolower(s2[i]));
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return 0;
}

OPTIMIZATION_OFF int strncmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; (s1[i] || s2[i]) && i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return 0;
}

OPTIMIZATION_OFF int strncasecmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; (s1[i] || s2[i]) && i < n; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return (tolower(s1[i]) - tolower(s2[i]));
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return 0;
}

OPTIMIZATION_OFF char *strstr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (strcmp(&haystack[i], needle) == 0) {
            return (char *)(&haystack[i]);
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return NULL;
}

OPTIMIZATION_OFF char *strcasestr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (strcasecmp(&haystack[i], needle) == 0) {
            return (char *)(&haystack[i]);
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return NULL;
}

OPTIMIZATION_OFF int __memcmp(const void *m1, const void *m2, size_t n)
{
    const char *s1 = (const char *)m1;
    const char *s2 = (const char *)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
        interceptor_increaseBy(1);
    }
    interceptor_increaseBy(5);
    return 0;
}

OPTIMIZATION_OFF int memcmp(const void *m1, const void *m2, size_t n)
{
    return __memcmp(m1, m2, n);
}

OPTIMIZATION_OFF int bcmp(const void *m1, const void *m2, size_t n)
{
    return __memcmp(m1, m2, n);
}

OPTIMIZATION_OFF
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
        if (__memcmp(&h[i], needle, needlelen) == 0) {
            return (void *)(&h[i]);
        }
    }
    return NULL;
}

int _CMP_EQ(unsigned long a, unsigned long b)
{
    return (__memcmp(&a, &b, sizeof(a)) == 0);
}

int _CMP_NEQ(unsigned long a, unsigned long b)
{
    return (__memcmp(&a, &b, sizeof(a)) != 0);
}
