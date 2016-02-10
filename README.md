# honggfuzz #

**Description**

  * A general-purpose, easy-to-use fuzzer with interesting analysis options. See [USAGE](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md) for more details
  * Supports hardware-based [feedback-driven fuzzing](https://github.com/google/honggfuzz/blob/master/docs/FeedbackDrivenFuzzing.md) (requires Linux and a supported CPU model), also for closed-source binaries
  * It works, at least, under GNU/Linux, FreeBSD, Mac OSX and [Android](https://github.com/google/honggfuzz/blob/master/docs/Android.md)
  * [Can fuzz long-lasting processes](https://github.com/google/honggfuzz/blob/master/docs/AttachingToPid.md) (e.g. network servers like Apache's httpd and ISC's bind)
  * It's been used to find a few interesting security problems in major software; examples:
    * FreeType 2 project: [CVE-2010-2497](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2497), [CVE-2010-2498](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2498), [CVE-2010-2499](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2499), [CVE-2010-2500](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2500), [CVE-2010-2519](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2519), [CVE-2010-2520](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2520), [CVE-2010-2527](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2527)
    * [Multiple bugs in the libtiff library](http://bugzilla.maptools.org/buglist.cgi?query_format=advanced;emailreporter1=1;email1=robert@swiecki.net;product=libtiff;emailtype1=substring)
    * [Multiple bugs in the librsvg library](https://bugzilla.gnome.org/buglist.cgi?query_format=advanced;emailreporter1=1;email1=robert%40swiecki.net;product=librsvg;emailtype1=substring)
    * [Multiple bugs in the poppler library](http://lists.freedesktop.org/archives/poppler/2010-November/006726.html)
    * [Multiple exploitable bugs in IDA-Pro](https://www.hex-rays.com/bugbounty.shtml)
    * ... and more

**Code**
  * Latest version: [0.6](https://github.com/google/honggfuzz/releases/tag/0.6) [CHANGELOG](https://github.com/google/honggfuzz/blob/master/CHANGELOG)
  * Older versions and static builds: [Honggfuzz 0.5](https://docs.google.com/file/d/0B86hdL7CeBvAX1NzMkMtUzN4Rms/view), [Direct download link](https://docs.google.com/uc?id=0B86hdL7CeBvAX1NzMkMtUzN4Rms&export=download) and [earlier versions](https://drive.google.com/folderview?id=0B86hdL7CeBvAfmJXcTJCeTJSeFdHd3E5Q3VGZFdCY192aVBxcHJSbkIyUVZGMG9ualJ6aE0&usp=sharing)

**Requirements**
  * Linux - BFD library (libbfd-dev) and LibUnwind (libunwind-dev/libunwind8-dev)
  * FreeBSD - gmake
  * Android - Android SDK/NDK

**Other**

This is NOT an official Google product.
