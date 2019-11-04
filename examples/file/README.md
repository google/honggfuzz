1. Compile file/libmagic

```shell
$ cd file-5.37/
$ CC="honggfuzz/hfuzz_cc/hfuzz-clang" ./configure --enable-static --disable-shared
$ make -j$(nproc)
```

2. Compile/link the persistent-file

```shell
$ honggfuzz/hfuzz_cc/hfuzz-clang -I ./file-5.37/ honggfuzz/examples/file/persistent-file.c -o persistent-file ./file-5.37/src/.libs/libmagic.a -lz
```

3. Fuzz it!

```shell
$ honggfuzz/honggfuzz --input inputs/ -- ./persistent-file  ./file-5.37/magic/magic.mgc 
```
