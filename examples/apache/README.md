# Fuzzing Apache 2.4 #

**Requirements**

  * honggfuzz
  * clang-4.0, or newer (5.0 works as well)
  * apache-2.4.x (e.g.: 2.4.25)

**Preparation**

Note: The examples provided below use hardcoded paths (here to _/home/swiecki/_) and
version strings of the libraries (e.g. apr-_1.5.2_). These will have to be modified, so they reflect your actual build environment.

1. Compile honggfuzz
2. Prepare (configure and compile) the following packages: apr, apr-util and ngttp2
  * Apr
  ```
  $ CC=clang-4.0 CFLAGS="-ggdb -fno-builtin -fno-inline -funroll-loops -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp" LDFLAGS="$CFLAGS" ./configure
  $ make
  ```
  * Apr-Util
  ```
  $ CC=clang-4.0 CFLAGS="-ggdb -fno-builtin -fno-inline -funroll-loops -fsanitize-coverage=trace-cmp,trace-pc-guard,indirect-calls" LDFLAGS="$CFLAGS" ./configure -with-apr=/home/swiecki/fuzz/apache/apr-1.5.2/
  $ make
  ```
  * NgHttp2
  ```
  $ CXX=clang++-4.0 CC=clang-4.0 LDFLAGS="$LIBS" CFLAGS="-ggdb -fno-builtin -fno-inline -funroll-loops -fsanitize-coverage=trace-cmp,trace-pc-guard,indirect-calls" CXXFLAGS="$CFLAGS" ./configure
  $ make
  ```
3. Unpack apache-2.4.x.tar.bz2
4. Patch Apache

  ```
  $ cd httpd-2.4.25/
  $ patch -p1 < /tmp/httpd-2.4.25.honggfuzz.patch
  ```
5. Configure, compile and install Apache

  * edit the _compile.sh_ file first, providing correct paths to libraries, and
    to the the installation directory (--prefix)
  ```
  $ sh compile.sh
  $ make -j4
  $ make install
  ```
6. Copy the custom configuration files to /home/swiecki/fuzz/apache/apache2/conf/

   ```
   $ cp httpd.conf.h1 httpd.conf.h2 /home/swiecki/fuzz/apache/apache2/conf/
   ```

**Fuzzing**

  * HTTP/1

```
$ ~/honggfuzz/honggfuzz -z -P -f corpus_http1 -w ./httpd.wordlist -- ./apache2/bin/httpd -X -f /home/swiecki/fuzz/apache/apache2/conf/httpd.conf.h1
```

  * HTTP/1 + HTTP/2

```
$ ~/honggfuzz/honggfuzz -z -P -f corpus_http2 -w ./httpd.wordlist -- ./apache2/bin/httpd -X -f /home/swiecki/fuzz/apache/apache2/conf/httpd.conf.h2
```
