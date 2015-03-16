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
#pragma GCC optimize ("0")

__attribute__ ((optimize("0")))
int strcmp(const char *s1, const char *s2)
{
    for (size_t i = 0; s1[i] || s2[i]; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

__attribute__ ((optimize("0")))
int strcasecmp(const char *s1, const char *s2)
{
    for (size_t i = 0; s1[i] || s2[i]; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return (tolower(s1[i]) - tolower(s2[i]));
        }
    }
    return 0;
}

__attribute__ ((optimize("0")))
int strncmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; (s1[i] || s2[i]) && i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
    }
    return 0;
}

__attribute__ ((optimize("0")))
int strncasecmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; (s1[i] || s2[i]) && i < n; i++) {
        if (tolower(s1[i]) != tolower(s2[i])) {
            return (tolower(s1[i]) - tolower(s2[i]));
        }
    }
    return 0;
}

__attribute__ ((optimize("0")))
char *strstr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (strcmp(&haystack[i], needle) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

__attribute__ ((optimize("0")))
char *strcasestr(const char *haystack, const char *needle)
{
    for (size_t i = 0; haystack[i]; i++) {
        if (strcasecmp(&haystack[i], needle) == 0) {
            return (char *)(&haystack[i]);
        }
    }
    return NULL;
}

#if defined(__i386__) || defined(__x86_64__)
__attribute__ ((optimize("0")))
unsigned int _nop(unsigned int x)
{
    __asm__ volatile ("    movl %0, %%eax\n"
                      " movl $0, %%edx\n"
                      "1:\n"
                      "    nop\n"
                      "    dec %%ecx\n"
                      "    add %%ecx, %%edx\n"
                      "    test %%ecx, %%ecx\n"
                      "    jz 2f\n" "    jmp 1b\n" "2:\n" "    mov %%edx, %1\n":"=r" (x)
                      :"0"(x)
                      :"%ecx", "%edx");

    return x;
}
#endif

__attribute__ ((optimize("0")))
int __memcmp(const void *m1, const void *m2, size_t n)
{
    const char *s1 = (const char *)m1;
    const char *s2 = (const char *)m2;

    for (size_t i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
#if defined(__i386__) || defined(__x86_64__)
        _nop(10000);
#endif
    }
#if defined(__i386__) || defined(__x86_64__)
    _nop(100000);
#endif
    return 0;
}

__attribute__ ((optimize("0")))
int memcmp(const void *m1, const void *m2, size_t n) {
	return __memcmp(m2, m2, n);
}

__attribute__ ((optimize("0")))
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

__attribute__ ((optimize("0")))
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

int _CMP_EQ(unsigned long a, unsigned long b)
{
    return (__memcmp(&a, &b, sizeof(a)) == 0);
}

int _CMP_NEQ(unsigned long a, unsigned long b)
{
    return (__memcmp(&a, &b, sizeof(a)) != 0);
}
