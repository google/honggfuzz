# Fuzzing ISC BIND 9.11.1 #

**Requirements**

  * honggfuzz (1.1 or from the master branch)
  * clang-4.0, or newer (5.0 works as well)
  * ISC BIND (e.g.: 9.11.1 or newer)

**Preparation**

Note: The examples provided below use hardcoded paths (here to: _/home/jagger/_). These will have to be modified, so they reflect your actual build environment.

1. Compile honggfuzz
2. Download and unpack bind-9.11.\*.tgz
3. Patch ISC BIND
 ```
$ cd bind-9.11.1-P3
$ patch -p1 < honggfuzz/examples/bind/patch-bind-9.11.1-P3
 ```

4. Configure, compile and install ISC BIND

* edit _compile.sh_, so it contains correct dist path
 ```
$ ./compile.sh
$ make install
 ```

5. Copy the custom configuration files to ```/home/jagger/fuzz/bind/dist/etc/named.conf``` (i.e. to your bind/named dist directory)

```
$ cp honggfuzz/examples/bind/named.conf /home/jagger/fuzz/bind/dist/etc/
$ cp honggfuzz/examples/bind/test.zone /home/jagger/fuzz/bind/dist/etc/
 ```

6. **Go**

```
$ honggfuzz/honggfuzz -f IN.req-response/ -z -P -- ./dist/sbin/named -c /home/jagger/fuzz/bind/dist/etc/named.conf -g
 ```
