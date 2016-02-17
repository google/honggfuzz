# Feedback-driven fuzzing #

Honggfuzz (since its version 0.5) is capable of performing feedback-driven fuzzing. It utilizes Linux perf subsystem and hardware CPU counters to achieve the best outcomes.

Developers can provide their own initial file (-f flag) which will be gradually improved upon. Alternatively, honggfuzz is capable of starting with just empty buffer, and work its way through, creating a valid fuzzing input in the process.

# Requirements #
  * GNU/Linux OS
  * Relatively modern Linux kernel (v 3.2 should suffice)
  * CPU which is supported by the [perf subsystem](https://perf.wiki.kernel.org/index.php/Main_Page) for hardware-assisted instruction and branch counting
  * CPU supporting [BTS (Branch Trace Store)](https://software.intel.com/en-us/forums/topic/277868?language=en) for hardware assisted unique edge (branch pairs) counting. Currently it's available only in some newer Intel CPUs (unfortunately no AMD support for now)
  * CPU supporting [Intel PT (Processor Tracing)](https://software.intel.com/en-us/blogs/2013/09/18/processor-tracing) for hardware assisted unique edge (branch pairs) counting. Currently it's available only in some newer Intel CPUs (unfortunately no AMD support for now)

# Examples #
The main fuzzing strategy is quite simple. It tries to maximize the number of perf events while mangling the file which servers as an input for fuzzing.

## Instruction counting (--linux_perf_instr) ##

```
============================== STAT ==============================
Iterations: 2776
Start time: 2016-02-16 18:40:51 (3 seconds elapsed)
Input file/dir: 'CURRENT_BEST'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 1
Execs per second: 922 (avg: 925)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0) 
Timeouts: 0
Dynamic file size: 2496 (max: 2500)
Dynamic file max iterations keep for chosen seed (136/8192)
Coverage (max):
  - cpu instructions:      1369752
============================== LOGS ==============================
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2496, Perf (Cur,New): 1369752/0/0/0/0/0,1371747/0/0/0/0/0
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2497, Perf (Cur,New): 1371747/0/0/0/0/0,1372273/0/0/0/0/0
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2497, Perf (Cur,New): 1372273/0/0/0/0/0,1372390/0/0/0/0/0
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2497, Perf (Cur,New): 1372390/0/0/0/0/0,1372793/0/0/0/0/0
```

It will start with some initial file (or with no file at all), and subsequent fuzzing iterations will try to maximize the number of instructions spent on parsing it.

## Branch counting (--linux_perf_branch) ##

As above, it will try to maximize the number of branches taken by CPU on behalf of the fuzzed process (here: djpeg.static) while performing the fuzzing process.

```
$ honggfuzz --linux_perf_branch -f CURRENT_BEST -F 2500 -q -n1 -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 0
Start time: 2016-02-16 18:39:41 (0 seconds elapsed)
Input file/dir: 'CURRENT_BEST'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 1
Execs per second: 0 (avg: 0)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0) 
Timeouts: 0
Dynamic file size: 1 (max: 2500)
Dynamic file max iterations keep for chosen seed (8193/8192)
Coverage (max):
  - cpu branches:          0
============================== LOGS ==============================
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/0/0/0/0/0,0/258259/0/0/0/0
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/258259/0/0/0/0,0/258260/0/0/0/0
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/258260/0/0/0/0,0/258261/0/0/0/0
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/258261/0/0/0/0,0/258263/0/0/0/0
```

## Unique branch points counting (--linux_perf_bts_block) / Unique branch pair (edges) counting (--linux_perf_bts_edge) with Intel BTS, and unique branch points counting ((--linux_perf_ipt_block) with Intel PT ##
This is the most powerfull mode of feedback-driven counting that honggfuzz supports. It utilizes Intel's BTS (Branch Trace Store) feature to record all branch events (edges) inside the fuzzed process. Later, honggfuzz will de-duplicate those entries. The resulting number of branch pairs (edges) is good approximation of how much code of a given tool have been actively executed/used (code coverage).

```
$ honggfuzz --linux_perf_bts_block -f CURRENT_BEST -F 2500 -q -n1 -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 0
Start time: 2016-02-16 18:35:32 (0 seconds elapsed)
Input file/dir: 'CURRENT_BEST'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 1
Execs per second: 0 (avg: 0)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0)
Timeouts: 0
Dynamic file size: 1 (max: 2500)
Dynamic file max iterations keep for chosen seed (8193/8192)
Coverage (max):
  - BTS unique blocks: 0
============================== LOGS ==============================
[2016-02-16T18:35:32+0100][I][14846] fuzz_perfFeedback():420 New: (Size New,Old): 257,257, Perf (Cur,New): 0/0/0/0/0/0,0/0/2030/0/0/0
[2016-02-16T18:35:32+0100][I][14846] fuzz_perfFeedback():420 New: (Size New,Old): 257,257, Perf (Cur,New): 0/0/2030/0/0/0,0/0/2031/0/0/0

$ honggfuzz --linux_perf_bts_edge -f CURRENT_BEST -F 2500 -q -n1 -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 1
Start time: 2016-02-16 18:37:08 (1 seconds elapsed)
Input file/dir: 'CURRENT_BEST'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 1
Execs per second: 1 (avg: 1)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0)
Timeouts: 0
Dynamic file size: 257 (max: 2500)
Dynamic file max iterations keep for chosen seed (0/8192)
Coverage (max):
  - BTS unique edges:   0
============================== LOGS ==============================
[2016-02-16T18:37:09+0100][I][14944] fuzz_perfFeedback():420 New: (Size New,Old): 257,257, Perf (Cur,New): 0/0/0/0/0/0,0/0/0/2341/0/0

$ honggfuzz --linux_perf_ipt_block -f CURRENT_BEST -F 2500 -q -n1 -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 0
Start time: 2016-02-16 18:38:45 (0 seconds elapsed)
Input file/dir: 'CURRENT_BEST'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 1
Execs per second: 0 (avg: 0)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0) 
Timeouts: 0
Dynamic file size: 1 (max: 2500)
Dynamic file max iterations keep for chosen seed (8193/8192)
Coverage (max):
  - PT unique blocks: 243
============================== LOGS ==============================
```
