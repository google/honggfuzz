# Fuzzing OpenSSL #

**Requirements**

  * honggfuzz
  * clang-4.0, or newer (5.0 works as well)
  * openssl (1.1.0, or newer)

**Preparation**

1. Compile honggfuzz
2. Unpack OpenSSL
3. Configure and compile OpenSSL

  ```
  $ make distclean
  $ CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang ./config enable-aria enable-heartbeats enable-md2 enable-rc5 enable-ssl3 enable-ssl3-method enable-tls13downgrade enable-tls1_3 enable-weak-ssl-ciphers
  $ make -j4
  ```
4. Prepare fuzzing binaries

```
  $ /home/jagger/src/honggfuzz/examples/openssl/make.sh master
```

**Fuzzing**

  ```
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.server/ -z -P -q -- ./persistent.server.openssl.master
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.client/ -z -P -q -- ./persistent.client.openssl.master
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.cert/ -z -P -q -- ./persistent.x509.openssl.master
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.privkey/ -z -P -q -- ./persistent.privkey.openssl.master
  ```

**Use of sanitizers**

***ASAN***
   * Configure OpenSSL with ASAN
```
  $ make distclean
  $ CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang ./config enable-aria enable-heartbeats enable-md2 enable-rc5 enable-ssl3 enable-ssl3-method enable-tls13downgrade enable-tls1_3 enable-weak-ssl-ciphers enable-asan
```
   * Compile binaries with

```
  $ /home/jagger/src/honggfuzz/examples/openssl/make.sh master address
```

   * Run honggfuzz with the *-S* flag to support the sanitizer exit codes and reporting

```
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.server/ -z -P -q -S -- ./persistent.server.openssl.master.address
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.client/ -z -P -q -S -- ./persistent.client.openssl.master.address
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.cert/ -z -P -q -S -- ./persistent.x509.openssl.master.address
  $ /home/jagger/src/honggfuzz/honggfuzz -f IN.privkey/ -z -P -q -S -- ./persistent.privkey.openssl.master.address
```
***MSAN/UBSAN***

As with ASAN

**32-bit builds**

Because some bugs may affect 32-builds only (e.g.: the [CVE-2017-3731](https://www.openssl.org/news/cl102.txt)), you might want to test your target in 32-bit mode

1. Configure and compile OpenSSL

  ```
  $ CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang linux32 ./config <other_options>
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
  (patch the CFLAGS make.sh to include -m32), and

  $ /home/jagger/src/honggfuzz/examples/openssl/make.sh master address
  ```
