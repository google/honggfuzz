# Fuzzing terminal emulators #

## Step 1: Prepare libclose.so and terminal-test ##

```
$ cd /home/jagger/src/honggfuzz/examples/terminal-emulators/
$ make
../../hfuzz_cc/hfuzz-clang -std=c99  -o terminal-test terminal-test.c
cc -std=c99  -shared -o libclose.so libclose.c
```

*libclose.so* serves one purpose only: when preloaded (with _LD_PRELOAD=libclose.so_)
it will prevent file-descriptors *1022* and *1023* (used by honggfuzz for coverage
feedback accumulation) will not be closed by the fuzzed binary (terminal emulator)
before passing to the _terminal-test_ binary.

The *terminal-test* program will feed the terminal emulator with data from the
fuzzing engine, and will try to read back any data that the terminal can produce.
See the _Bonus: term.log_ secion on why it might matter.

## Step 2: Instrument your terminal emulator ##

Add compiler-time instrumentation to your fuzzed terminal emulator. Typically it
would consist of the following sequence of commands (for xterm):

```
$ cd xterm-327
$ CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang CXX=$CC ./configure
...
...
$ CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang CXX=$CC make -j4
```

Alternatively, you might want to compile it with ASAN enabled, for better
detection of memory corruption problems

```
$ cd xterm-327
$ HFUZZ_CC_ASAN=1 CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang CXX=$CC ./configure
...
...
$ HFUZZ_CC_ASAN=1 CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang CXX=$CC make -j4
```

## Step 3: Create initial input corpus ##

It can consist even of a single file.

```
$ mkdir IN
$ echo A >IN/1
```

## Step 4: Launch it! ##

```
$ /home/jagger/src/honggfuzz/honggfuzz -z -P -f IN/ -E LD_PRELOAD=/home/jagger/src/honggfuzz/examples/terminal-emulators/libclose.so -- xterm-327/xterm -e /home/jagger/src/honggfuzz/examples/terminal-emulators/terminal-test
```

Typical output:
```
----------------------------[ honggfuzz v1.0alpha ]---------------------------
  Iterations : 4,865,546 [4.87M]
       Phase : Dynamic Main (2/2)
    Run Time : 0 hrs 0 min 15 sec
   Input Dir : [865] 'IN/'
  Fuzzed Cmd : './xterm -e /home/jagger/src/honggfuzz/examples/terminal-em...'
     Threads : 4, CPUs: 8, CPU: 733% (91%/CPU)
       Speed : 320,951/sec (avg: 324,369)
     Crashes : 0 (unique: 0, blacklist: 0, verified: 0)
    Timeouts : 0 [10 sec.]
 Corpus Size : 265, max file size: 1,024
    Coverage : bb: 850 cmp: 35,516
-----------------------------------[ LOGS ]-----------------------------------
NEW, size:912 (i,b,sw,hw,cmp): 0/0/1/0/1, Tot:0/0/772/0/32216
NEW, size:940 (i,b,sw,hw,cmp): 0/0/1/0/32, Tot:0/0/773/0/32248
NEW, size:919 (i,b,sw,hw,cmp): 0/0/0/0/9, Tot:0/0/773/0/32257
NEW, size:1024 (i,b,sw,hw,cmp): 0/0/0/0/2, Tot:0/0/773/0/32259
NEW, size:1013 (i,b,sw,hw,cmp): 0/0/0/0/1, Tot:0/0/773/0/32260
...
...
```

## Bonus: term.log ##

The *term.log* file will contain interesting data which can be fetched from the
terminal emulator's input buffer. It will typically contains responses to ESC
sequences requesting info about terminal size, or about the current color map.
But, if you notice there arbitrary or binary data, basically something that
a typical terminal shouldn't responsd with, try to investigate it. You might
have just found and interesting case of RCE, where arbitrary data can
be pushed into terminal's input buffer, and then read back (and potentially
executed) with whatever runs under said emulator (e.g. _/bin/bash_)
