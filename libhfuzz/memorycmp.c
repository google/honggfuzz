#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libhfcommon/common.h"
#include "libhfcommon/util.h"
#include "libhfuzz/instrument.h"

#if !defined(__CYGWIN__)
__attribute__((visibility("hidden")))
#endif /* !defined(__CYGWIN__) */
__attribute__((used)) const char* const LIBHFUZZ_module_memorycmp = "LIBHFUZZ_module_memorycmp";

/*
 * util_getProgAddr() check is quite costly, and it lowers the fuzzing speed typically by a factor
 * of 2, but keep it true for now
 */
#define HF_TEST_ADDR_CMPHASH true

static inline uintptr_t HF_cmphash(uintptr_t addr, const void* s1, const void* s2) {
    if (HF_TEST_ADDR_CMPHASH && util_getProgAddr(s1) != LHFC_ADDR_NOTFOUND) {
        addr ^= ((uintptr_t)s1 << 1);
    }
    if (HF_TEST_ADDR_CMPHASH && util_getProgAddr(s2) != LHFC_ADDR_NOTFOUND) {
        addr ^= ((uintptr_t)s2 << 2);
    }
    return addr;
}

static inline int HF_strcmp(const char* s1, const char* s2, uintptr_t addr) {
    size_t i;
    for (i = 0; s1[i] == s2[i]; i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    instrumentUpdateCmpMap(HF_cmphash(addr, s1, s2), i);
    instrumentAddConstStr(s1);
    instrumentAddConstStr(s2);
    return (unsigned char)s1[i] - (unsigned char)s2[i];
}

static inline int HF_strcasecmp(
    const char* s1, const char* s2, int (*cmp_func)(int), uintptr_t addr) {
    size_t i;
    for (i = 0; cmp_func((int)(unsigned char)s1[i]) == cmp_func((int)(unsigned char)s2[i]); i++) {
        if (s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    instrumentUpdateCmpMap(HF_cmphash(addr, s1, s2), i);
    instrumentAddConstStr(s1);
    instrumentAddConstStr(s2);
    return (cmp_func((int)(unsigned char)s1[i]) - cmp_func((int)(unsigned char)s2[i]));
}

static inline int HF_strncmp(
    const char* s1, const char* s2, size_t n, bool constfb, uintptr_t addr) {
    size_t i;
    for (i = 0; i < n; i++) {
        if ((s1[i] != s2[i]) || s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    instrumentUpdateCmpMap(HF_cmphash(addr, s1, s2), i);
    if (constfb) {
        instrumentAddConstStrN(s1, n);
        instrumentAddConstStrN(s2, n);
    }

    if (i == n) {
        return 0;
    }

    return (unsigned char)s1[i] - (unsigned char)s2[i];
}

static inline int HF_strncasecmp(
    const char* s1, const char* s2, size_t n, int (*cmp_func)(int), bool constfb, uintptr_t addr) {
    size_t i;
    for (i = 0; i < n; i++) {
        if ((cmp_func((int)(unsigned char)s1[i]) != cmp_func((int)(unsigned char)s2[i])) ||
            s1[i] == '\0' || s2[i] == '\0') {
            break;
        }
    }

    instrumentUpdateCmpMap(HF_cmphash(addr, s1, s2), i);
    if (constfb) {
        instrumentAddConstStrN(s1, n);
        instrumentAddConstStrN(s2, n);
    }

    if (i == n) {
        return 0;
    }

    return cmp_func((int)(unsigned char)s1[i]) - cmp_func((int)(unsigned char)s2[i]);
}

static inline char* HF_strstr(const char* haystack, const char* needle, uintptr_t addr) {
    size_t needle_len = __builtin_strlen(needle);
    if (needle_len == 0) {
        return (char*)haystack;
    }

    instrumentAddConstStr(needle);

    const char* h = haystack;
    for (; (h = __builtin_strchr(h, needle[0])) != NULL; h++) {
        if (HF_strncmp(h, needle, needle_len, /* constfb= */ false, addr) == 0) {
            return (char*)h;
        }
    }

    return NULL;
}

static inline char* HF_strcasestr(
    const char* haystack, const char* needle, int (*cmp_func)(int), uintptr_t addr) {
    size_t needle_len = __builtin_strlen(needle);
    if (needle_len == 0) {
        return (char*)haystack;
    }

    instrumentAddConstStr(needle);

    for (size_t i = 0; haystack[i]; i++) {
        if (HF_strncasecmp(
                &haystack[i], needle, needle_len, cmp_func, /* constfb= */ false, addr) == 0) {
            return (char*)(&haystack[i]);
        }
    }

    return NULL;
}

static inline int HF_memcmp(
    const void* m1, const void* m2, size_t n, bool constfb, uintptr_t addr) {
    const unsigned char* s1 = (const unsigned char*)m1;
    const unsigned char* s2 = (const unsigned char*)m2;

    size_t i;
    for (i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            break;
        }
    }

    instrumentUpdateCmpMap(HF_cmphash(addr, m1, m2), i);
    if (constfb) {
        instrumentAddConstMem(m1, n, /* check_if_ro= */ true);
        instrumentAddConstMem(m2, n, /* check_if_ro= */ true);
    }

    if (i == n) {
        return 0;
    }

    return (unsigned char)s1[i] - (unsigned char)s2[i];
}

static inline void* HF_memmem(const void* haystack, size_t haystacklen, const void* needle,
    size_t needlelen, uintptr_t addr) {
    if (needlelen > haystacklen) {
        return NULL;
    }
    if (needlelen == 0) {
        return (void*)haystack;
    }

    instrumentAddConstMem(needle, needlelen, /* check_if_ro= */ true);

    const char* h = haystack;
    for (size_t i = 0; i <= (haystacklen - needlelen); i++) {
        if (HF_memcmp(&h[i], needle, needlelen, /* constfb= */ false, addr) == 0) {
            return (void*)(&h[i]);
        }
    }

    return NULL;
}

static inline char* HF_strcpy(char* dest, const char* src, uintptr_t addr) {
    size_t len = __builtin_strlen(src);
    if (len > 0) {
        instrumentUpdateCmpMap(addr, util_Log2(len));
    }
    return __builtin_memcpy(dest, src, len + 1);
}

static inline char* HF_strcat(char* dest, const char* src, uintptr_t addr) {
    size_t len = __builtin_strlen(dest);
    return HF_strcpy(dest + len, src, addr);
}

static inline size_t HF_strlcpy(char* dest, const char* src, size_t sz, uintptr_t addr) {
    size_t slen = __builtin_strlen(src);
    size_t len  = sz < slen ? sz : slen;

    if (sz == 0) {
        return 0;
    }
    /* Make space for NUL at the end of the string.
     * sz != 0 here
     */
    if (len == sz) {
        len--;
    }

    if (len > 0) {
        instrumentUpdateCmpMap(addr, util_Log2(len));
        (void)__builtin_memcpy(dest, src, len);
    }

    dest[len] = '\0';
    return slen;
}

static inline size_t HF_strlcat(char* dest, const char* src, size_t sz, uintptr_t addr) {
    size_t dstlen = __builtin_strlen(dest);

    if (dstlen >= sz) {
        return dstlen + __builtin_strlen(src);
    }

    size_t left = sz - dstlen;

    return dstlen + HF_strlcpy(dest + dstlen, src, left, addr);
}

/* Define a weak function x, as well as __wrap_x pointing to x */
#define XVAL(x) x
#define HF_WEAK_WRAP(ret, func, ...)                                                               \
    _Pragma(HF__XSTR(weak func = __wrap_##func)) XVAL(ret) XVAL(__wrap_##func)(__VA_ARGS__)

/* Typical libc wrappers */
HF_WEAK_WRAP(int, strcmp, const char* s1, const char* s2) {
    return HF_strcmp(s1, s2, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strcmp(
    uintptr_t pc, const char* s1, const char* s2, int result HF_ATTR_UNUSED) {
    HF_strcmp(s1, s2, pc);
}
HF_WEAK_WRAP(int, strcasecmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strcasecmp(
    uintptr_t pc, const char* s1, const char* s2, int result HF_ATTR_UNUSED) {
    HF_strcasecmp(s1, s2, tolower, pc);
}
HF_WEAK_WRAP(int, stricmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_stricmp(
    uintptr_t pc, const char* s1, const char* s2, int result HF_ATTR_UNUSED) {
    HF_strcasecmp(s1, s2, tolower, pc);
}
HF_WEAK_WRAP(int, strncmp, const char* s1, const char* s2, size_t n) {
    return HF_strncmp(s1, s2, n, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strncmp(
    uintptr_t pc, const char* s1, const char* s2, size_t n, int result HF_ATTR_UNUSED) {
    HF_strncmp(s1, s2, n, instrumentConstAvail(), pc);
}
HF_WEAK_WRAP(int, strncasecmp, const char* s1, const char* s2, size_t n) {
    return HF_strncasecmp(
        s1, s2, n, tolower, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strncasecmp(
    uintptr_t pc, const char* s1, const char* s2, size_t n, int result HF_ATTR_UNUSED) {
    HF_strncasecmp(s1, s2, n, tolower, instrumentConstAvail(), pc);
}
HF_WEAK_WRAP(int, strnicmp, const char* s1, const char* s2, size_t n) {
    return HF_strncasecmp(
        s1, s2, n, tolower, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strnicmp(
    uintptr_t pc, const char* s1, const char* s2, size_t n, int result HF_ATTR_UNUSED) {
    HF_strncasecmp(s1, s2, n, tolower, instrumentConstAvail(), pc);
}
HF_WEAK_WRAP(char*, strstr, const char* haystack, const char* needle) {
    return HF_strstr(haystack, needle, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strstr(
    uintptr_t pc, const char* haystack, const char* needle, char* result HF_ATTR_UNUSED) {
    HF_strstr(haystack, needle, pc);
}
HF_WEAK_WRAP(char*, strcasestr, const char* haystack, const char* needle) {
    return HF_strcasestr(haystack, needle, tolower, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strcasestr(
    uintptr_t pc, const char* haystack, const char* needle, char* result HF_ATTR_UNUSED) {
    HF_strcasestr(haystack, needle, tolower, pc);
}
HF_WEAK_WRAP(int, memcmp, const void* m1, const void* m2, size_t n) {
    return HF_memcmp(m1, m2, n, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_memcmp(
    uintptr_t pc, const void* m1, const void* m2, size_t n, int result HF_ATTR_UNUSED) {
    HF_memcmp(m1, m2, n, instrumentConstAvail(), pc);
}
HF_WEAK_WRAP(int, bcmp, const void* m1, const void* m2, size_t n) {
    return HF_memcmp(m1, m2, n, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_bcmp(
    uintptr_t pc, const void* m1, const void* m2, size_t n, int result HF_ATTR_UNUSED) {
    HF_memcmp(m1, m2, n, instrumentConstAvail(), pc);
}
HF_WEAK_WRAP(
    void*, memmem, const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    return HF_memmem(
        haystack, haystacklen, needle, needlelen, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_memmem(uintptr_t pc, const void* haystack, size_t haystacklen,
    const void* needle, size_t needlelen, void* result HF_ATTR_UNUSED) {
    HF_memmem(haystack, haystacklen, needle, needlelen, pc);
}
HF_WEAK_WRAP(char*, strcpy, char* dest, const char* src) {
    return HF_strcpy(dest, src, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strcpy(
    uintptr_t pc, char* dest, const char* src, char* result HF_ATTR_UNUSED) {
    HF_strcpy(dest, src, pc);
}
HF_WEAK_WRAP(char*, strcat, char* dest, const char* src) {
    return HF_strcat(dest, src, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strcat(
    uintptr_t pc, char* dest, const char* src, char* result HF_ATTR_UNUSED) {
    HF_strcat(dest, src, pc);
}
HF_WEAK_WRAP(size_t, strlcpy, char* dest, const char* src, size_t len) {
    return HF_strlcpy(dest, src, len, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strlcpy(
    uintptr_t pc, char* dest, const char* src, size_t sz, size_t result HF_ATTR_UNUSED) {
    HF_strlcpy(dest, src, sz, pc);
}
HF_WEAK_WRAP(size_t, strlcat, char* dest, const char* src, size_t len) {
    return HF_strlcat(dest, src, len, (uintptr_t)__builtin_return_address(0));
}
void __sanitizer_weak_hook_strlcat(
    uintptr_t pc, char* dest, const char* src, size_t sz, size_t result HF_ATTR_UNUSED) {
    HF_strlcat(dest, src, sz, pc);
}

/*
 * Apache's httpd wrappers
 */
HF_WEAK_WRAP(int, ap_cstr_casecmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, ap_cstr_casecmpn, const char* s1, const char* s2, size_t n) {
    return HF_strncasecmp(
        s1, s2, n, tolower, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(const char*, ap_strcasestr, const char* s1, const char* s2) {
    return HF_strcasestr(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, apr_cstr_casecmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, apr_cstr_casecmpn, const char* s1, const char* s2, size_t n) {
    return HF_strncasecmp(
        s1, s2, n, tolower, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

/*
 * *SSL wrappers
 */
HF_WEAK_WRAP(int, CRYPTO_memcmp, const void* m1, const void* m2, size_t len) {
    return HF_memcmp(m1, m2, len, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, OPENSSL_memcmp, const void* m1, const void* m2, size_t len) {
    return HF_memcmp(m1, m2, len, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, OPENSSL_strcasecmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, OPENSSL_strncasecmp, const char* s1, const char* s2, size_t len) {
    return HF_strncasecmp(
        s1, s2, len, tolower, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int32_t, memcmpct, const void* s1, const void* s2, size_t len) {
    return HF_memcmp(s1, s2, len, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

/*
 * libXML wrappers
 */
static int xml_to_upper(int c) {
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 'A';
    }
    return c;
}

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
    return HF_strncmp(
        s1, s2, (size_t)len, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
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
    return HF_strcmp(s1, s2, (uintptr_t)__builtin_return_address(0));
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
    if (HF_strcmp(s1, s2, (uintptr_t)__builtin_return_address(0)) == 0) {
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
    return HF_strcasecmp(s1, s2, xml_to_upper, (uintptr_t)__builtin_return_address(0));
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
    return HF_strncasecmp(s1, s2, (size_t)len, xml_to_upper, instrumentConstAvail(),
        (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(const char*, xmlStrstr, const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return HF_strstr(haystack, needle, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(const char*, xmlStrcasestr, const char* haystack, const char* needle) {
    if (haystack == NULL) {
        return NULL;
    }
    if (needle == NULL) {
        return NULL;
    }
    return HF_strcasestr(haystack, needle, xml_to_upper, (uintptr_t)__builtin_return_address(0));
}

/*
 * Samba wrappers
 */
HF_WEAK_WRAP(int, memcmp_const_time, const void* s1, const void* s2, size_t n) {
    return HF_memcmp(s1, s2, n, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(bool, strcsequal, const void* s1, const void* s2) {
    if (s1 == s2) {
        return true;
    }
    if (!s1 || !s2) {
        return false;
    }
    return (HF_strcmp(s1, s2, (uintptr_t)__builtin_return_address(0)) == 0);
}

/*
 * LittleCMS wrappers
 */
HF_WEAK_WRAP(int, cmsstrcasecmp, const void* s1, const void* s2) {
    return HF_strcasecmp(s1, s2, toupper, (uintptr_t)__builtin_return_address(0));
}

/*
 * GLib wrappers
 */
HF_WEAK_WRAP(int, g_strcmp0, const char* s1, const char* s2) {
    if (!s1) {
        return -(s1 != s2);
    }
    if (!s2) {
        return s1 != s2;
    }
    return HF_strcmp(s1, s2, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, g_strcasecmp, const char* s1, const char* s2) {
    if (!s1 || !s2) {
        return 0;
    }
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, g_strncasecmp, const char* s1, const char* s2, int n) {
    if (!s1 || !s2) {
        return 0;
    }
    return HF_strncasecmp(
        s1, s2, n, tolower, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(char*, g_strstr_len, const char* haystack, ssize_t haystack_len, const char* needle) {
    if (!haystack || !needle) {
        return NULL;
    }
    if (haystack_len < 0) {
        return HF_strstr(haystack, needle, (uintptr_t)__builtin_return_address(0));
    }
    return HF_memmem(haystack, (size_t)haystack_len, needle, __builtin_strlen(needle),
        (uintptr_t)__builtin_return_address(0));
}

static inline int hf_glib_ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 'a';
    }
    return c;
}

HF_WEAK_WRAP(int, g_ascii_strcasecmp, const char* s1, const char* s2) {
    if (!s1 || !s2) {
        return 0;
    }
    return HF_strcasecmp(s1, s2, hf_glib_ascii_tolower, (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(int, g_ascii_strncasecmp, const char* s1, const char* s2, size_t n) {
    if (!s1 || !s2) {
        return 0;
    }
    return HF_strncasecmp(s1, s2, n, hf_glib_ascii_tolower, instrumentConstAvail(),
        (uintptr_t)__builtin_return_address(0));
}

HF_WEAK_WRAP(bool, g_str_has_prefix, const char* str, const char* prefix) {
    if (!str || !prefix) {
        return false;
    }
    return (HF_strncmp(str, prefix, __builtin_strlen(prefix), instrumentConstAvail(),
                (uintptr_t)__builtin_return_address(0)) == 0);
}

HF_WEAK_WRAP(bool, g_str_has_suffix, const char* str, const char* suffix) {
    if (!str || !suffix) {
        return false;
    }
    size_t str_len    = __builtin_strlen(str);
    size_t suffix_len = __builtin_strlen(suffix);
    if (str_len < suffix_len) {
        return false;
    }

    return (
        HF_strcmp(str + str_len - suffix_len, suffix, (uintptr_t)__builtin_return_address(0)) == 0);
}

/* CUrl wrappers */
static int curl_toupper(int c) {
    if (c >= 'a' && c <= 'z') {
        return ('A' + c - 'a');
    }
    return c;
}

HF_WEAK_WRAP(int, Curl_strcasecompare, const char* first, const char* second) {
    if (HF_strcasecmp(first, second, curl_toupper, (uintptr_t)__builtin_return_address(0)) == 0) {
        return 1;
    }
    return 0;
}

HF_WEAK_WRAP(int, curl_strequal, const char* first, const char* second) {
    if (HF_strcasecmp(first, second, curl_toupper, (uintptr_t)__builtin_return_address(0)) == 0) {
        return 1;
    }
    return 0;
}

HF_WEAK_WRAP(int, Curl_safe_strcasecompare, const char* first, const char* second) {
    if (!first && !second) {
        return 1;
    }
    if (!first || !second) {
        return 0;
    }
    if (HF_strcasecmp(first, second, curl_toupper, (uintptr_t)__builtin_return_address(0)) == 0) {
        return 1;
    }
    return 0;
}

HF_WEAK_WRAP(int, Curl_strncasecompare, const char* first, const char* second, size_t max) {
    if (HF_strncasecmp(first, second, max, curl_toupper, instrumentConstAvail(),
            (uintptr_t)__builtin_return_address(0)) == 0) {
        return 1;
    }
    return 0;
}

HF_WEAK_WRAP(int, curl_strnequal, const char* first, const char* second, size_t max) {
    if (HF_strncasecmp(first, second, max, curl_toupper, instrumentConstAvail(),
            (uintptr_t)__builtin_return_address(0)) == 0) {
        return 1;
    }
    return 0;
}

/* SQLite3 wrappers */
HF_WEAK_WRAP(int, sqlite3_stricmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}
HF_WEAK_WRAP(int, sqlite3StrICmp, const char* s1, const char* s2) {
    return HF_strcasecmp(s1, s2, tolower, (uintptr_t)__builtin_return_address(0));
}
HF_WEAK_WRAP(int, sqlite3_strnicmp, const char* s1, const char* s2, size_t len) {
    return HF_strncasecmp(
        s1, s2, len, tolower, /* constfb= */ true, (uintptr_t)__builtin_return_address(0));
}

/* C++ wrappers */
int _ZNSt11char_traitsIcE7compareEPKcS2_m(const char* s1, const char* s2, size_t count) {
    return HF_memcmp(s1, s2, count, instrumentConstAvail(), (uintptr_t)__builtin_return_address(0));
}
