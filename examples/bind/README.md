# Fuzzing ISC BIND (verified with 9.15.4) #

**Requirements**

  * honggfuzz (1.9 or from the master branch)
  * clang-5.0 or newer (the newer, the better)
  * ISC Bind (tested with 9.15.4)

**Preparation**

1. Compile honggfuzz
2. Download bind-9.15.4.tgz from https://downloads.isc.org/isc/bind9/
3. Decompress/unpack and patch it

```shell
$ cd <fuzzing_dir>
$ tar -xvzf bind-9.15.4.tar.gz
$ cd bind-9.15.4
$ patch -p1 < <honggfuzz_dir>/examples/bind/bind-9.15.4.patch
$ chmod 755 compile.sh
```

4. Configure, compile and install ISC Bind

* edit _compile.sh_, so it contains the correct dist (_--prefix_) path

 ```shell
$ vim compile.sh # [edit the --prefix]
$ ./compile.sh
$ make install
 ```

5. Copy the custom configuration files to ```<fuzzing_directory>/bind/dist/etc/named.conf``` (i.e. to your bind/named dist directory)

```shell
$ cp honggfuzz/examples/bind/named.conf <fuzzing_directory>/bind/dist/etc/
$ cp honggfuzz/examples/bind/test.zone <fuzzing_directory>/bind/dist/etc/
 ```
 
6. Fix the _directory_ configuration directive inside your <fuzzing_directory>/bind/dist/etc/named.conf

```shell
$ vim <fuzzing_directory>/bind/dist/etc/named.conf # [edit the *directory* directive] 
```

7. **Fuzz it!**

```shell
$ <honggfuzz_dir>/honggfuzz -i input_corpus -- ./dist/sbin/named -c <fuzzing_directory>/bind/dist/etc/named.conf -g
 ```
