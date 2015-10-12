# Feedback-driven fuzzing #

Honggfuzz (since its version 0.5) is capable of performing feedback-driven fuzzing. It utilizes Linux perf subsystem and hardware CPU counters to achieve the best outcomes.

Developers can provide their own initial file (-f flag) which will be gradually improved upon. Alternatively, honggfuzz is capable of starting with just empty buffer, and work its way through, creating a valid fuzzing input in the process.

# Requirements #
  * GNU/Linux OS
  * Relatively modern Linux kernel (v 3.2 should suffice)
  * CPU which is supported by the [perf subsystem](https://perf.wiki.kernel.org/index.php/Main_Page) for hardware-assisted instruction and branch counting
  * CPU supporting [BTS (Branch Trace Store)](https://software.intel.com/en-us/forums/topic/277868?language=es) for hardware assisted unique edge (branch pairs) counting. Currently it's available only in some newer Intel CPUs (unfortunately no AMD support for now)

# Examples #
The main fuzzing strategy is quite simple. It tries to maximize the number of perf events while mangling the file which servers as an input for fuzzing.

## Instruction counting (--linux_perf_instr) ##

```
$ honggfuzz -F3000 -q --linux_perf_instr -f /usr/share/doc/texlive-doc/latex/ctable/penguin.jpg -- /usr/bin/djpeg ___FILE___
...
============================== STAT ==============================
Iterations: 639
Start time: 2015-10-11 17:15:52 (3 seconds elapsed)
Input file/dir: '/usr/share/doc/texlive-doc/latex/ctable/penguin.jpg'
Fuzzed cmd: '/usr/bin/djpeg'
Fuzzing threads: 2
Execs per second: 233 (avg: 213)
Crashes: 0 (unique: 0, blacklist: 0) 
Timeouts: 0
Dynamic file size: 6 (max: 3000)
Coverage (max):
  - cpu instructions:      6339988
============================== LOGS ==============================
[2015-10-11T17:15:55+0200][I][27885] fuzz_fuzzLoop():302 New: (Size New,Old): 6,6, Perf (Cur,New): 6339988/0/0/0/0,6339993/0/0/0/0
[2015-10-11T17:15:55+0200][I][27886] fuzz_fuzzLoop():302 New: (Size New,Old): 5,6, Perf (Cur,New): 6339993/0/0/0/0,6342013/0/0/0/0
[2015-10-11T17:15:55+0200][I][27885] fuzz_fuzzLoop():302 New: (Size New,Old): 5,5, Perf (Cur,New): 6342013/0/0/0/0,6342200/0/0/0/0
[2015-10-11T17:15:55+0200][I][27885] fuzz_fuzzLoop():302 New: (Size New,Old): 5,5, Perf (Cur,New): 6342200/0/0/0/0,6342206/0/0/0/0
[2015-10-11T17:15:56+0200][I][27885] fuzz_fuzzLoop():302 New: (Size New,Old): 5,5, Perf (Cur,New): 6342206/0/0/0/0,6342208/0/0/0/0
```


It will start with some initial file (or with no file at all), and subsequent fuzzing iterations will try to maximize the number of instructions spent on parsing it.

## Branch counting (--linux_perf_branch) ##

As above, it will try to maximize the number of branches taken by CPU on behalf of the fuzzed process (here: djpeg.static) while performing the fuzzing process.

```
$ honggfuzz -F3000 -q --linux_perf_branch -f /usr/share/doc/texlive-doc/latex/ctable/penguin.jpg -- /usr/bin/djpeg ___FILE___
============================== STAT ==============================
Iterations: 1617
Start time: 2015-10-11 17:16:31 (3 seconds elapsed)
Input file/dir: '/usr/share/doc/texlive-doc/latex/ctable/penguin.jpg'
Fuzzed cmd: '/usr/bin/djpeg'
Fuzzing threads: 2
Execs per second: 455 (avg: 539)
Crashes: 0 (unique: 0, blacklist: 0) 
Timeouts: 0
Dynamic file size: 2997 (max: 3000)
Coverage (max):
  - cpu branches:          434886
============================== LOGS ==============================
[2015-10-11T17:16:34+0200][I][28961] fuzz_fuzzLoop():302 New: (Size New,Old): 2997,2997, Perf (Cur,New): 0/434886/0/0/0,0/434898/0/0/0
[2015-10-11T17:16:34+0200][I][28961] fuzz_fuzzLoop():302 New: (Size New,Old): 2997,2997, Perf (Cur,New): 0/434898/0/0/0,0/434901/0/0/0
[2015-10-11T17:16:35+0200][I][28961] fuzz_fuzzLoop():302 New: (Size New,Old): 2997,2997, Perf (Cur,New): 0/434901/0/0/0,0/434906/0/0/0
[2015-10-11T17:16:35+0200][I][28960] fuzz_fuzzLoop():302 New: (Size New,Old): 2997,2997, Perf (Cur,New): 0/434906/0/0/0,0/434906/0/0/0
[2015-10-11T17:16:35+0200][I][28961] fuzz_fuzzLoop():302 New: (Size New,Old): 2997,2997, Perf (Cur,New): 0/434906/0/0/0,0/434909/0/0/0
```

## Unique branch points counting (--linux_perf_ip) / Unique branch pair (edges) counting (--linux_perf_ip_addr) ##
This is the most powerfull mode of feedback-driven counting that honggfuzz supports. It utilizes Intel's BTS (Branch Trace Store) feature to record all branch events (edges) inside the fuzzed process. Later, honggfuzz will de-duplicate those entries. The resulting number of branch pairs (edges) is good approximation of how much code of a given tool have been actively executed/used (code coverage).

```
$ honggfuzz -F3000000 -q --linux_perf_ip -f /usr/share/lxde/wallpapers/lxde_red.jpg -- /usr/bin/djpeg ___FILE___
============================== STAT ==============================
Iterations: 10
Start time: 2015-10-11 17:15:58 (10 seconds elapsed)
Input file/dir: '/usr/share/lxde/wallpapers/lxde_red.jpg'
Fuzzed cmd: '/usr/bin/djpeg'
Fuzzing threads: 2
Execs per second: 2 (avg: 2)
Crashes: 0 (unique: 0, blacklist: 0) 
Timeouts: 0
Dynamic file size: 275664 (max: 3000000)
Coverage (max):
  - unique branch targets: 2301
============================== LOGS ==============================
[2015-10-11T17:15:59+0200][I][28880] fuzz_fuzzLoop():302 New: (Size New,Old): 275664,275664, Perf (Cur,New): 0/0/0/0/0,0/0/2301/0/0
[2015-10-11T17:15:59+0200][I][28881] fuzz_fuzzLoop():302 New: (Size New,Old): 275664,275664, Perf (Cur,New): 0/0/2301/0/0,0/0/2301/0/0

```
