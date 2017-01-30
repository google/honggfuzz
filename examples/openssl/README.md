# Fuzzing OpenSSL #

**Requirements**

  * honggfuzz
  * clang-4.0, or newer (5.0 works as well)
  * openssl-1.1.0[a-d].tgz, or newer

**Preparation**

1. Compile honggfuzz
2. Unpack openssl-1.1.0[a-d].tgz
3. Patch OpenSSL

  ```
  $ cd openssl-1.1.0d
  $ patch -p1 < /tmp/openssl-1.1.0d.honggfuzz.patch
  ```
4. Configure and compile OpenSSL

  ```
  $ make distclean
  $ CC=clang-4.0 ./config enable-fuzz-hfuzz
  $ make -j4
  ```
5. Prepare fuzzing binaries

  ```
  $ clang-4.0 -o persistent.server.openssl.1.1.0d -I./openssl-1.1.0d/include server.c ./openssl-1.1.0d/libssl.a ./openssl-1.1.0d/libcrypto.a ~/honggfuzz/libhfuzz/libhfuzz.a  -ldl -lpthread
  $ clang-4.0 -o persistent.client.openssl.1.1.0d -I./openssl-1.1.0d/include client.c ./openssl-1.1.0d/libssl.a ./openssl-1.1.0d/libcrypto.a ~/honggfuzz/libhfuzz/libhfuzz.a  -ldl -lpthread
  $ clang-4.0 -o persistent.x509.openssl.1.1.0d -I./openssl-1.1.0d/include x509.c ./openssl-1.1.0d/libssl.a ./openssl-1.1.0d/libcrypto.a ~/honggfuzz/libhfuzz/libhfuzz.a  -ldl -lpthread
  ```
5 Fuzz it

  ```
  $ ~/honggfuzz/honggfuzz -z -P -f corpus_server -t2 -q -- ./persistent.server.openssl.1.1.0d
  $ ~/honggfuzz/honggfuzz -z -P -f corpus_client -t2 -q -- ./persistent.client.openssl.1.1.0d
  $ ~/honggfuzz/honggfuzz -z -P -f corpus_x509 -t2 -q -- ./persistent.x509.openssl.1.1.0d
  ```

**Use of sanitizers**

  * ASAN
   * Configure OpenSSL
```
CC=clang-4.0 ./config enable-fuzz-hfuzz enable-asan
```
   * Compile binaries with (notice the additional _/instrument.o_ at the beginning
     of the commandline)
```
clang-4.0 ~/honggfuzz/libhfuzz/instrument.o -I./openssl-1.1.0d/include server.c ./openssl-1.1.0c/libssl.a ./openssl-1.1.0c/libcrypto.a -o persistent.server.openssl.1.1.0d.asan ~/honggfuzz/libhfuzz/libhfuzz.a -ldl -lpthread -fsanitize=address
```
  * MSAN/UBSAN
   * As for ASAN

**32-bit builds**
Because some bugs can only affect 32-builds (e.g.: the [CVE-2017-3731](https://www.openssl.org/news/cl102.txt)), you might want to test your target in 32-bit mode

  * Configure and compile OpenSSL
```
$ CC=clang-4.0 linux32 ./config enable-fuzz-hfuzz enable-32
$ make -j4
```
  * Prepare 32-bit version of libhfuzz.a
```
$ cd ~/honggfuzz
$ rm -f libhfuzz/*.o libhfuzz/libhfuzz.a
$ CFLAGS="-m32" make libhfuzz/libhfuzz.a
```
  * Link the final binaries
```
$ clang-4.0 -I./openssl-1.1.0d/include server.c ./openssl-1.1.0d/libssl.a ./openssl-1.1.0d/libcrypto.a -o persistent.server.openssl.1.1.0d.32 ~/honggfuzz/libhfuzz/libhfuzz.a  -ldl -lpthread -m32
```
  * Fuzz it
```
$ ~/honggfuzz/honggfuzz -n2 -z -P -f IN.server/ -n8 -t2 -q -- ./persistent.server.openssl.1.1.0d.32
```
