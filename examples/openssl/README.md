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

**Fuzzing**

  ```
  $ ~/honggfuzz/honggfuzz -z -P -f corpus_server -q -- ./persistent.server.openssl.1.1.0d
  $ ~/honggfuzz/honggfuzz -z -P -f corpus_client -q -- ./persistent.client.openssl.1.1.0d
  $ ~/honggfuzz/honggfuzz -z -P -f corpus_x509 -q -- ./persistent.x509.openssl.1.1.0d
  ```

**Use of sanitizers**

***ASAN***
   * Configure OpenSSL
```
$ CC=clang-4.0 ./config enable-fuzz-hfuzz enable-asan
```
   * Compile the binaries with

```
$ clang-4.0 ~/honggfuzz/libhfuzz/instrument.o -I./openssl-1.1.0d/include server.c ./openssl-1.1.0d/libssl.a ./openssl-1.1.0d/libcrypto.a -o persistent.server.openssl.1.1.0d.asan ~/honggfuzz/libhfuzz/libhfuzz.a -ldl -lpthread -fsanitize=address
```

PS. Note the additional _instrument.o_ object file at the beginning of the command-line shown above. It's
requires here, because when _-fsanitize=address_ (or: _memory/undefined_) is in use, clang will
unconditionally link the final binary with _libFuzzer.a_. This will
override some important symbols from libhfuzz.a used for coverage counting in honggfuzz.

   * Run honggfuzz with the *-S* flag to support the sanitizer exit codes and reporting

```
$ ~/honggfuzz/honggfuzz -z -P -f corpus_server -q -S -- ./persistent.server.openssl.1.1.0d.asan
```

***MSAN/UBSAN***

As with ASAN

**32-bit builds**

Because some bugs may affect 32-builds only (e.g.: the [CVE-2017-3731](https://www.openssl.org/news/cl102.txt)), you might want to test your target in 32-bit mode

1. Configure and compile OpenSSL

  ```
  $ CC=clang-4.0 linux32 ./config enable-fuzz-hfuzz enable-32
  $ make -j4
  ```
2. Prepare 32-bit version of libhfuzz.a

  ```
  $ cd ~/honggfuzz
  $ rm -f libhfuzz/*.o libhfuzz/libhfuzz.a
  $ CFLAGS="-m32" make libhfuzz/libhfuzz.a
  ```
3. Link the final binaries

  ```
  $ clang-4.0 -I./openssl-1.1.0d/include server.c ./openssl-1.1.0d/libssl.a ./openssl-1.1.0d/libcrypto.a -o persistent.server.openssl.1.1.0d.32 ~/honggfuzz/libhfuzz/libhfuzz.a  -ldl -lpthread -m32
  ```
4. Fuzz it!

  ```
  $ ~/honggfuzz/honggfuzz -z -P -f IN.server/ -q -- ./persistent.server.openssl.1.1.0d.32
  ```
