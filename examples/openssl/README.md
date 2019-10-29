# Fuzzing OpenSSL #

**Requirements**

  * honggfuzz
  * clang-5.0 or newer
  * openssl 1.1.0 (or the github's master branch)
  * libressl/boringssl should work as well, though they might require more specific building instructions

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
$ <honggfuzz_dir>/examples/openssl/compile_hfuzz_openssl_master.sh [enable-asan|enable-msan|enable-ubsan]
```

4. Compile OpenSSL

```shell
$ make -j$(nproc)
```

5. Prepare fuzzing binaries

The _make.sh_ script will compile honggfuzz and libFuzzer binaries. Syntax:

```shell
<honggfuzz_dir>/examples/openssl/make.sh <directory-with-open/libre/boring-ssl> [address|memory|undefined]
```

```shell
$ cd ..
$ <honggfuzz_dir>/examples/openssl/make.sh openssl-master address
```

**Fuzzing**

```shell
$ <honggfuzz_dir>/honggfuzz --input corpus_server/ -- ./openssl-master.address.server
$ <honggfuzz_dir>/honggfuzz --input corpus_client/ -- ./openssl-master.address.client
$ <honggfuzz_dir>/honggfuzz --input corpus_x509/ -- ./openssl-master.address.x509
$ <honggfuzz_dir>/honggfuzz --input corpus_privkey/ -- ./openssl-master.address.privkey
```
