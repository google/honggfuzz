# honggfuzz #

**Description**

A security oriented, feedback-driven, evolutionary, easy-to-use fuzzer with interesting analysis options. See [USAGE](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md) for more data on the usage.

  * It's __multi-threaded__ and __multi-process__: no need to run multiple copies of your fuzzer, as honggfuzz can unlock potential of all your available CPU cores. The file corpus is shared between threads (and fuzzed instances)
  * It's blazingly fast (esp. in the [persistent fuzzing mode](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md)). A simple _LLVMFuzzerTestOneInput_ function can be tested with __up to 1mo iterations per second__ on a relatively modern CPU (e.g. i7-6700K)
  * Has a nice track record of uncovered security bugs: e.g. the __only__ (to the date) __vulnerability in OpenSSL with the [critical](https://www.openssl.org/news/secadv/20160926.txt) score mark__ was discovered by honggfuzz. See the Throphies paragraph for the summary of findings to the date
  * Uses low-level interfaces to monitor processes (e.g. _ptrace_ under Linux). As opposed to other fuzzers, it __will discover and report hidden signals__ (caught and potentially hidden by signal handlers)
  * Easy-to-use, feed it a simple input corpus (__can even consist of a single, 1-byte file__) and it will work its way up expanding it utilizing feedback-based coverage metrics
  * Supports several (more than any other coverage-based feedback-driven fuzzer) hardware-based (CPU: branch/instruction counting, __Intel BTS__, __Intel PT__) and software-based [feedback-driven fuzzing](https://github.com/google/honggfuzz/blob/master/docs/FeedbackDrivenFuzzing.md) methods known from other fuzzers (libfuzzer, afl)
  * Works (at least) under GNU/Linux, FreeBSD, Mac OS X, Windows/CygWin and [Android](https://github.com/google/honggfuzz/blob/master/docs/Android.md)
  * Supports __persistent fuzzing mode__ (long-lived process calling a fuzzed API repeatedly) with libhfuzz/libhfuzz.a. More on that can be found [here](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md)
  * [Can fuzz remote/standalone long-lasting processes](https://github.com/google/honggfuzz/blob/master/docs/AttachingToPid.md) (e.g. network servers like __Apache's httpd__ and __ISC's bind__), though the [persistent fuzzing mode](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md) is suggested instead: as it's faster and multiple instances of a service can be fuzzed at once in this mode
  * It comes with the __[examples](https://github.com/google/honggfuzz/tree/master/examples) directory__, consisting of real world fuzz setups for widely-used software (e.g. Apache and OpenSSL)

**Code**

  * Latest stable version: [1.2](https://github.com/google/honggfuzz/releases), but using the __master__ branch is highly encouraged
  * [Changelog](https://github.com/google/honggfuzz/blob/master/CHANGELOG)

**Requirements**

  * **Linux** - The BFD library (libbfd-dev) and libunwind (libunwind-dev/libunwind8-dev), clang-4.0 or higher for software-based coverage modes
  * **FreeBSD** - gmake, clang-3.6 or newer (clang-devel/4.0 suggested)
  * **Android** - Android SDK/NDK. Also see [this detailed doc](https://github.com/google/honggfuzz/blob/master/docs/Android.md) on how to build and run it
  * **Windows** - CygWin
  * **Darwin/OS X** - Xcode 10.8+
  * if **Clang/LLVM** is used to compile honggfuzz - link it with the BlocksRuntime Library (libblocksruntime-dev)

**Trophies**

Honggfuzz has been used to find a few interesting security problems in major software packages; An incomplete list:

  * [Pre-auth remote crash in __OpenSSH__](https://anongit.mindrot.org/openssh.git/commit/?id=28652bca29046f62c7045e933e6b931de1d16737)
  * __Apache__
    * [Remote crash in __mod\_http2__ • CVE-2017-7659](http://seclists.org/oss-sec/2017/q2/504)
    * [Use-after-free in __mod\_http2__ • CVE-2017-9789](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9789)
    * [Memory leak in __mod\_auth\_digest__ • CVE-2017-9788](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9788)
  * __SSL__
    * [Remote OOB read in __OpenSSL__ • CVE-2015-1789]( https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1789)
    * [Remote Use-after-Free (potential RCE, rated as __critical__) in __OpenSSL__ • CVE-2016-6309](https://www.openssl.org/news/secadv/20160926.txt)
    * [Remote OOB write in __OpenSSL__ • CVE-2016-7054](https://www.openssl.org/news/secadv/20161110.txt)
    * [Remote OOB read in __OpenSSL__ • CVE-2017-3731](https://www.openssl.org/news/secadv/20170126.txt)
    * [Uninitialized mem use in __OpenSSL__](https://github.com/openssl/openssl/commit/bd5d27c1c6d3f83464ddf5124f18a2cac2cbb37f)
    * [Crash in __LibreSSL__](https://github.com/openbsd/src/commit/c80d04452814d5b0e397817ce4ed34edb4eb520d)
    * [Invalid free in __LibreSSL__](https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.6.2-relnotes.txt)
    * [Uninitialized mem use in __BoringSSL__](https://github.com/boringssl/boringssl/commit/7dccc71e08105b100c3acd56fa5f6fc1ba9b71d3)
  * [Adobe __Flash__ memory corruption • CVE-2015-0316](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0316)
  * [Multiple bugs in the __libtiff__ library](http://bugzilla.maptools.org/buglist.cgi?query_format=advanced;emailreporter1=1;email1=robert@swiecki.net;product=libtiff;emailtype1=substring)
  * [Multiple bugs in the __librsvg__ library](https://bugzilla.gnome.org/buglist.cgi?query_format=advanced;emailreporter1=1;email1=robert%40swiecki.net;product=librsvg;emailtype1=substring)
  * [Multiple bugs in the __poppler__ library](http://lists.freedesktop.org/archives/poppler/2010-November/006726.html)
  * [Multiple exploitable bugs in __IDA-Pro__](https://www.hex-rays.com/bugbounty.shtml)
  * [Remote DoS in __Crypto++__ • CVE-2016-9939](http://www.openwall.com/lists/oss-security/2016/12/12/7)
  * Language interpreters
    * [__PHP/Python/Ruby__](https://github.com/dyjakan/interpreter-bugs)
    * [PHP WDDX](https://bugs.php.net/bug.php?id=74145)
    * [PHP](https://bugs.php.net/bug.php?id=74194)
  * [Double-free in __LibXMP__](https://github.com/cmatsuoka/libxmp/commit/bd1eb5cfcd802820073504c234c3f735e96c3355)
  * [Heap buffer overflow in SAPCAR • CVE-2017-8852](https://www.coresecurity.com/blog/sapcar-heap-buffer-overflow-crash-exploit)
  * [Crashes in __libbass__](http://seclists.org/oss-sec/2017/q4/185)
  * __FreeType 2__:
    * [CVE-2010-2497](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2497)
    * [CVE-2010-2498](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2498)
    * [CVE-2010-2499](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2499)
    * [CVE-2010-2500](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2500)
    * [CVE-2010-2519](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2519)
    * [CVE-2010-2520](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2520)
    * [CVE-2010-2527](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2527)
  * A couple of problems in the [__MATLAB MAT File I/O Library__](https://sourceforge.net/projects/matio): [1](https://github.com/tbeu/matio/commit/406438f497931f45fb3edf6de17d3a59a922c257), [2](https://github.com/tbeu/matio/commit/406438f497931f45fb3edf6de17d3a59a922c257), [3](https://github.com/tbeu/matio/commit/a55b9c2c01582b712d5a643699a13b5c41687db1), [4](https://github.com/tbeu/matio/commit/3e6283f37652e29e457ab9467f7738a562594b6b), [5](https://github.com/tbeu/matio/commit/783ee496a6914df68e77e6019054ad91e8ed6420)
  * ... and more

**Projects utilizing Honggfuzz**
  * [__QuickFuzz__ by CIFASIS](http://quickfuzz.org)
  * [__OSS-Fuzz__](https://github.com/google/oss-fuzz)
  * [__Frog And Fuzz__](https://github.com/warsang/FrogAndFuzz/tree/develop)
  * [dyjakan's __interpreters fuzzing__ project](https://github.com/dyjakan/interpreter-bugs)
  * [__riufuzz__: honggfuzz with AFL-like UI](https://github.com/riusksk/riufuzz)
  * [__h2fuzz__: fuzzing of Apache's HTTP/2 implementation](https://github.com/icing/h2fuzz)
  * [__honggfuzz-dharma__: honggfuzz with dharma grammar fuzzer](https://github.com/Sbouber/honggfuzz-dharma)
  * [__Owl__: a system for finding concurrency attacks](https://github.com/hku-systems/owl)
  * [__honggfuzz-docker-apps__](https://github.com/skysider/honggfuzz_docker_apps)
  * [__FFW - Fuzzing For Worms__](https://github.com/dobin/ffw)

**Examples**

The [examples](https://github.com/google/honggfuzz/tree/master/examples/)
directory contains code demonstrating (among others) how to use honggfuzz to find bugs in the
[OpenSSL](https://github.com/google/honggfuzz/tree/master/examples/openssl)
library and in the [Apache](https://github.com/google/honggfuzz/tree/master/examples/apache-httpd)
HTTPD web server.

**Other**

  * User mailing list: [honggfuzz@googlegroups.com](mailto:honggfuzz@googlegroups.com), sign up with [this link](https://groups.google.com/forum/#!forum/honggfuzz).

__This is NOT an official Google product__
