# Fuzzing OpenSSL #

**Requirements**

  * honggfuzz
  * clang-4.0, or newer (5.0/6.0 work as well)
  * openssl 1.1.0 (or, the master branch from git)
  * libressl/boringssl/openssl-1.0.2 work as well, though they might require specific building instructions

**Preparation (for OpenSSL 1.1.0/master)**

1. Compile honggfuzz
2. Unpack/Clone OpenSSL

```shell
$ git clone --depth=1 https://github.com/openssl/openssl.git
$ mv openssl openssl-master
```

3. Use ```compile_hfuzz_openssl_master.sh``` to configure OpenSSL

```shell
$ cd openssl-master
$ /home/jagger/src/honggfuzz/examples/openssl/compile_hfuzz_openssl_master.sh [enable-asan|enable-msan|enable-ubsan]
```

4. Compile OpenSSL

```shell
$ make
```

5. Prepare fuzzing binaries

The _make.sh_ script will compile honggfuzz and libFuzzer binaries. Syntax:

```shell
make.sh <directory-with-open/libre/boring-ssl> [address|memory|undefined]
```

```shell
$ cd ..
$ /home/jagger/src/honggfuzz/examples/openssl/make.sh openssl-master address
```

**Fuzzing**

```shell
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_server/ -P -- ./openssl-master.address.server
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_client/ -P -- ./openssl-master.address.client
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_x509/ -P -- ./openssl-master.address.x509
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_privkey/ -P -- ./openssl-master.address.privkey
```
