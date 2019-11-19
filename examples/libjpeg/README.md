# Fuzzing libjpeg(-turbo) #

**Requirements**

  * honggfuzz
  * clang-5.0, or newer
  * libjpeg9, or libjpeg-turbo

**Preparation**

1. Compile honggfuzz
2. Unpack/Clone libjpeg(-turbo)

3. Configure+Compile libjpeg(-turbo)

```shell
CC=<your_hfuzz_dir>/hfuzz_cc/hfuzz-clang CXX=<your_hfuzz_dir>/hfuzz_cc/hfuzz-clang++ CFLAGS="-fsanitize=address" ./configure
make -j$(nproc)
```

4. Compile fuzzing targets

```shell
$ <your_hfuzz_dir>/hfuzz_cc/hfuzz-clang -I ./jpeg-9c/ <your_hfuzz_dir>/examples/libjpeg/persistent-jpeg.c -o persistent.jpeg9.address jpeg-9c/.libs/libjpeg.a  -fsanitize=address
```

or

```shell
$ <your_hfuzz_dir>/hfuzz_cc/hfuzz-clang -I ./libjpeg-turbo-2.0.3/ -I ./libjpeg-turbo-2.0.3/out/ <your_hfuzz_dir>/examples/libjpeg/persistent-jpeg.c -o persistent.jpeg-turbo.address libjpeg-turbo-2.0.3/out/libjpeg.a -fsanitize=address
```

**Fuzzing**

```shell
$ honggfuzz -i initial_corpus --rlimit_rss 2048 -- ./persistent.jpeg9.address 
```

or

```
$ honggfuzz -i initial_corpus --rlimit_rss 2048 -- ./persistent.jpeg-turbo.address
```
