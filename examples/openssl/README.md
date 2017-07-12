# Fuzzing OpenSSL #

**Requirements**

  * honggfuzz
  * clang-4.0, or newer (5.0 works as well)
  * openssl 1.1.0 (or, the master branch from git)

**Preparation**

1. Compile honggfuzz
2. Unpack/Clone OpenSSL

```
$ git clone --depth=1 https://github.com/openssl/openssl.git
$ mv openssl openssl-master
```

3. Edit ```compile_hfuzz_openssl_master.sh``` (e.g. add -fsanitize=address) and configure and compile OpenSSL

```
$ cd openssl-master
$ /home/jagger/src/honggfuzz/examples/openssl/compile_hfuzz_openssl_master.sh
```

4. Prepare fuzzing binaries

The _make.sh_ script will compile honggfuzz and libFuzzer binaries. Syntax:

__make.sh <directory-suffix> [address|memory|undefined]__

```
$ cd ..
$ /home/jagger/src/honggfuzz/examples/openssl/make.sh master address
```

**Fuzzing**

```
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_server/ -z -P -- ./persistent.server.openssl.master
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_client/ -z -P -- ./persistent.client.openssl.master
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_x509/ -z -P -- ./persistent.x509.openssl.master
$ /home/jagger/src/honggfuzz/honggfuzz -f corpus_privkey/ -z -P -- ./persistent.privkey.openssl.master
```
