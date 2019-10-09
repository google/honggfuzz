# Fuzzing ISC BIND (verified with 9.15.4) #

**Requirements**

  * honggfuzz (1.1 or from the master branch)
  * clang-4.0, or newer (5.0 works as well)
  * ISC Bind (verified with 9.15.4)

**Preparation**

Note: The examples provided below use hardcoded paths (here to: _/home/jagger/_). These will have to be modified, so they reflect your actual build environment.

1. Compile honggfuzz
2. Download and unpack bind-9.15.4.tgz
3. Unpack bind, and patch it

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
$ ./compile.sh
$ make install
 ```

5. Copy the custom configuration files to ```<fuzzing_directory>/bind/dist/etc/named.conf``` (i.e. to your bind/named dist directory)

```shell
$ cp honggfuzz/examples/bind/named.conf <fuzzing_directory>/bind/dist/etc/
$ cp honggfuzz/examples/bind/test.zone <fuzzing_directory>/bind/dist/etc/
 ```

6. **Fuzz it!**

```shell
$ <honggfuzz_dir>/honggfuzz -i input_corpus -- ./dist/sbin/named -c /home/jagger/fuzz/bind/dist/etc/named.conf -g
 ```
