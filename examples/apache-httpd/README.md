# Fuzzing Apache 2.4 #

**Requirements**

  * honggfuzz
  * clang-4.0, or newer (5.0 works as well)
  * apache (e.g. 2.4.29 or from githubs' master branch)
  * apr, apr-utils, nghttp2

**Preparation**

Note: The examples provided below use hardcoded paths (here to _/home/$USER/_) and
version strings of the libraries (e.g. apr-_1.5.2_). These will have to be modified, so they reflect your actual build environment.

1. Compile honggfuzz
2. Download and unpack the following packages: apr, apr-util, ngttp2, and Apache's httpd
3. Patch Apache's httpd

```shell
$ cd httpd-master
$ patch -p1 < httpd-master.honggfuzz.patch
```
4. Configure, compile and install Apache
  * edit ```compile_and_install.asan.sh``` so it contains valid versions/paths

```shell
$ ./compile_and_install.asan.sh
```

5. Copy custom configuration files (```httpd.conf.h1``` and ```httpd.conf.h2```) to ```/home/$USER/fuzz/apache/apache2/conf/``` (i.e. to your apache dist directory)

 ```
$ cp httpd.conf.h1 httpd.conf.h2 /home/$USER/fuzz/apache/apache2/conf/
 ```

6. Edit ```httpd.conf.h1``` and ```httpd.conf.h2```, so they contain valid configuration paths

**Fuzzing**

  * HTTP/1

 ```
$ honggfuzz/honggfuzz -f corpus_http1 -w ./httpd.wordlist -- ./apache2/bin/httpd -DFOREGROUND -f  /home/$USER/fuzz/apache/apache2/conf/httpd.conf.h1
 ```

  * HTTP/2

```
$ honggfuzz/honggfuzz -f corpus_http2 -w ./httpd.wordlist -- ./apache2/bin/httpd -DFOREGROUND -f /home/$USER/fuzz/apache/apache2/conf/httpd.conf.h2
```
