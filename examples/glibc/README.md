# Fuzzing glibc based programs #

**Requirements**
 * gcc-6 or, for best results (cmp instrumentation), gcc-8 released after 2017-10
 * relatively modern glibc (e.g. 2.26)

**Prepare glibc**

```shell
$ gcc -c ~/src/honggfuzz/examples/glibc/wrappers.c -o /tmp/wrappers.o
$ cd ~/src/glibc-2.26
$ mkdir build && cd build
$ CC="gcc-8 -Wl,/tmp/wrappers.o" CFLAGS="-fsanitize-coverage=trace-pc,trace-cmp -O3 -fno-omit-frame-pointer -ggdb -Wno-error" ../configure --prefix=/usr --without-cvs --enable-add-ons=libidn --without-selinux --enable-stackguard-randomization --enable-obsolete-rpc --disable-sanity-checks
$ make -j$(nproc) lib
```

_For gcc < 8, use the following ```CFLAGS```, as gcc < 8 doesn't support -fsanitize-coverage=trace-cmp_

```shell
CFLAGS="-fsanitize-coverage=trace-pc -O3 -fno-omit-frame-pointer -ggdb -Wno-error"
```

**Compile code**

```shell
$ ~/src/honggfuzz/hfuzz-cc/hfuzz-gcc -Wl,-z,muldefs -nodefaultlibs -I ~/src/honggfuzz/ ~/src/honggfuzz/examples/glibc/resolver.c -o resolver -L ~/src/glibc-2.26/build -L ~/src/glibc-2.26/build/nptl -L ~/src/glibc-2.26/rt -L ~/src/glibc-2.26/build/resolv ~/src/honggfuzz/libhfuzz/libhfuzz.a -lc -static -lgcc -lpthread -lgcc_eh -lc
```

**Fuzz it**

```shell
$ ~/src/honggfuzz/honggfuzz -f IN/ -P -- ./resolver
```
