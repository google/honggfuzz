# Fuzzing Apache 2.4 #

**Requirements**

  * honggfuzz (1.0 or from the master branch)
  * clang-4.0, or newer (5.0 works as well)
  * apache (e.g.: 2.4.25 or the master branch from git)

**Preparation**

Note: The examples provided below use hardcoded paths (here to _/home/swiecki/_) and
version strings of the libraries (e.g. apr-_1.5.2_). These will have to be modified, so they reflect your actual build environment.

1. Compile honggfuzz
2. Prepare (configure and compile) the following packages: apr, apr-util and ngttp2
  * Apr
  ```
  $ CC=honggfuzz/hfuzz_cc/hfuzz-clang-cc CXX="$CC" CFLAGS="-fsanitize=address -ggdb -fno-builtin -fno-inline -funroll-loops" LDFLAGS="$CFLAGS" ./configure
  $ make
  ```
  * Apr-Util
  ```
  $ CC=honggfuzz/hfuzz_cc/hfuzz-clang-cc CXX="$CC" CFLAGS="-fsanitize=address -ggdb -fno-builtin -fno-inline -funroll-loops" LDFLAGS="$CFLAGS" ./configure
  $ make
  ```
  * NgHttp2
  ```
  CC=honggfuzz/hfuzz_cc/hfuzz-clang-cc CXX="$CC" CFLAGS="-fsanitize=address -ggdb -fno-builtin -fno-inline -funroll-loops" LDFLAGS="$CFLAGS" ./configure
  $ make
  ```
3. Unpack/Clone Apache
4. Patch Apache

  ```
  $ cd httpd-master
  $ patch -p1 < httpd-master.honggfuzz.patch
  ```
5. Configure, compile and install Apache
  ```
  $ <edit compile.sh to point it to your dist directory>
  $ ./compile.sh
  $ make install
  ```

6. Copy the custom configuration files to ```/home/swiecki/fuzz/apache/apache2/conf/``` (i.e. to your apache dist directory)

   ```
   $ cp httpd.conf.h1 httpd.conf.h2 /home/swiecki/fuzz/apache/apache2/conf/
   ```

**Fuzzing**

  * HTTP/1

```
$ honggfuzz/honggfuzz -z -P -f corpus_http1 -w ./httpd.wordlist -- ./apache2/bin/httpd -X -f /home/swiecki/fuzz/apache/apache2/conf/httpd.conf.h1
```

  * HTTP/1 + HTTP/2

```
$ honggfuzz/honggfuzz -z -P -f corpus_http2 -w ./httpd.wordlist -- ./apache2/bin/httpd -X -f /home/swiecki/fuzz/apache/apache2/conf/httpd.conf.h2
```
