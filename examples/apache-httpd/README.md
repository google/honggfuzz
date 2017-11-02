# Fuzzing Apache 2.4 #

**Requirements**

  * honggfuzz (1.0 or from the master branch)
  * clang-4.0, or newer (5.0 works as well)
  * apache (e.g.: 2.4.25 or the master branch from git)

**Preparation**

Note: The examples provided below use hardcoded paths (here to _/home/swiecki/_) and
version strings of the libraries (e.g. apr-_1.5.2_). These will have to be modified, so they reflect your actual build environment.

1. Compile honggfuzz
2. Download and unpack the following packages: apr, apr-util, ngttp2, and Apache's httpd
3. Patch Apache's httpd
 ```
$ cd httpd-master
$ patch -p1 < httpd-master.honggfuzz.patch
 ```
4. Configure, compile and install Apache
  * edit compile_and_install.sh to contain valid versions/paths
 ```
$ ./compile_and_install.sh
 ```

5. Copy the custom configuration files to ```/home/swiecki/fuzz/apache/apache2/conf/``` (i.e. to your apache dist directory)

 ```
$ cp httpd.conf.h1 httpd.conf.h2 /home/swiecki/fuzz/apache/apache2/conf/
 ```

**Fuzzing**

  * HTTP/1

 ```
$ honggfuzz/honggfuzz -P -f corpus_http1 -w ./httpd.wordlist -- ./apache2/bin/httpd -DFOREGROUND -f  /home/swiecki/fuzz/apache/apache2/conf/httpd.conf.h1
 ```

  * HTTP/2

```
$ honggfuzz/honggfuzz -P -f corpus_http2 -w ./httpd.wordlist -- ./apache2/bin/httpd -DFOREGROUND -f /home/swiecki/fuzz/apache/apache2/conf/httpd.conf.h2
```
