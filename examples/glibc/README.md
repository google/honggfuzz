# Fuzzing glibc based programs #

**Prepare glibc**

```shell
$ gcc ~/src/honggfuzz/examples/glibc/wrappers.c -o /tmp/wrappers.o
$ cd ~/src/glibc-2.26
$ mkdir build
$ cd build
$ CC="gcc-8 -Wl,/tmp/wrappers.o" CFLAGS="-fsanitize-coverage=trace-pc,trace-cmp -O3 -fno-omit-frame-pointer -ggdb -Wno-error" LIBS="/tmp/wrappers.o" LDFLAGS="/tmp/wrappers.o" ../configure --prefix=/usr --without-cvs --enable-add-ons=libidn --without-selinux --enable-stackguard-randomization --enable-obsolete-rpc --disable-sanity-checks
$ make -j$(nproc)
```

_For gcc < 8, use the following ```configure``` options_

```
$ CC="gcc -Wl,/tmp/wrappers.o" CFLAGS="-fsanitize-coverage=trace-pc -O3 -fno-omit-frame-pointer -ggdb -Wno-error" LIBS="/tmp/wrappers.o" LDFLAGS="/tmp/wrappers.o" ../configure --prefix=/usr --without-cvs --enable-add-ons=libidn --without-selinux --enable-stackguard-randomization --enable-obsolete-rpc --disable-sanity-checks
```

**Compile code**

```shell
$ gcc -Wl,-z,muldefs -nodefaultlibs -I ~/src/honggfuzz/ ~/src/honggfuzz/examples/glibc/resolver.c -o resolver -L ~/src/glibc-2.26/build ~/src/honggfuzz/libhfuzz/libhfuzz.a -lc -static -lgcc -lpthread -lgcc_eh -lc
```

**Fuzz it**

```shell
$ ~/src/honggfuzz/honggfuzz -f IN/ -P -- ./resolver
```
