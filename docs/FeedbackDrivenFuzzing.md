# Feedback-driven fuzzing #

Honggfuzz is capable of performing feedback-guided (code coverage driven) fuzzing. It can utilize the following sources of data:
  * (Linux) Hardware-based counters (instructions, branches)
  * (Linux) Intel BTS code coverage (kernel >= 4.2)
  * (Linux) Intel PT code coverage (kernel >= 4.2)
  * Sanitzer-coverage instrumentation (`-fsanitize-coverage=bb`)
  * Compile-time instrumentation (`-finstrument-functions` or `-fsanitize-coverage=trace-pc[-guard],indirect-calls,trace-cmp` or both)

Developers should provide the initial file corpus which will be gradually improved upon. It can even comprise of a single 1-byte initial file, and honggfuzz will try to generate better inputs starting from there.

---
# Requirements for software-based coverage-guided fuzzing #
  * `-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp` - Clang >= 4.0
  * `-fsanitize-coverage=bb` - Clang >= 3.7
  * `-finstrument-functions` - GCC or Clang
  * [older, slower variant] `-fsanitize-coverage=trace-pc,indirect-calls` - Clang >= 3.9 

_Note_: The _-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp_ set of flags will be automatically added to clang's command-line switches when using [hfuzz-clang](https://github.com/google/honggfuzz/tree/master/hfuzz_cc) binary.

```
$ [honggfuzz_dir]/honggfuzz/hfuzz_cc/hfuzz-clang terminal-test.c -o terminal-test
```

---
# Requirements for hardware-based counter-based fuzzing #
  * GNU/Linux OS
  * Relatively modern Linux kernel (4.2 should suffice)
  * CPU which is supported by the [perf subsystem](https://perf.wiki.kernel.org/index.php/Main_Page) for hardware-assisted instruction and branch counting

---
# Requirements for hardware-based coverage-feedback fuzzing (Intel) #
  * CPU supporting [BTS (Branch Trace Store)](https://software.intel.com/en-us/forums/topic/277868?language=en) for hardware assisted unique pc and edges (branch pairs) counting. Currently it's available only in some newer Intel CPUs (unfortunately no AMD support for now)
  * CPU supporting [Intel PT (Processor Tracing)](https://software.intel.com/en-us/blogs/2013/09/18/processor-tracing) for hardware assisted unique edge (branch pairs) counting. Currently it's available only in some newer Intel CPUs (since Broadwell architecture)
  * GNU/Linux OS with a supported CPU; Intel Core 2 for BTS, Intel Broadwell for Intel PT
  * Intel's [ibipt library](http://packages.ubuntu.com/yakkety/libipt1) for Intel PT
  * Linux kernel >= v4.2 for perf AUXTRACE

---
# Fuzzing strategy #
The implemented strategy is trying to identify files which add new code coverage (or increased instruction/branch counters). Then those inputs are added (dynamically stored in memory) corpus, and reused during following fuzzing rounds

There are 2 phases of feedback-driven the fuzzing:
  * Honggfuzz goes through each file in the initial corpus directory (-f). It adds files which hit new code coverage to the dynamic input corpus (as well as saving them on the disk, using *COVERAGE_DATA.PID.pid.RND.time.rnd* pattern
  * Honggfuzz choses randomly files from the dynamic input corpus (in-memory), mutates them, and runs a new fuzzing round (round in persistent mode, exec in non-persistent mode). If the newly created file induces new code path (extends code coverage), it gets added to the dynamic input corpus

# Compile-time instrumentation with clang/gcc (default mode) #

Here you can use the following:
  * gcc/clang `-finstrument-functions` (less-precise)
  * clang's (>= 4.0) `-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp`
    (trace-cmp adds additional comparison map to the instrumentation)

_Note_: The _-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp_ set of flags will be automatically added to clang's command-line switches when using [hfuzz-clang](https://github.com/google/honggfuzz/tree/master/hfuzz_cc) binary. The [hfuzz-clang](https://github.com/google/honggfuzz/tree/master/hfuzz_cc) binary will also link your code with _libhfuzz.a_

Two persistent modes can be used here:

### LLVM-style LLVMFuzzerTestOneInput ###

```c
$ cat test.c
#include <inttypes.h>
#include <testlib.h>  // Our API to test

extern int LLVMFuzzerTestOneInput(uint8_t **buf, size_t *len);

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  _FuncFromFuzzedLib_(buf, len);
  return 0;
}
```

```
$ [honggfuzz_dir]/honggfuzz/hfuzz_cc/hfuzz-clang -c fuzzedlib.c -o fuzzedlib.o
$ [honggfuzz_dir]/honggfuzz/hfuzz_cc/hfuzz-clang test.c fuzzedlib.o -o test
$ [honggfuzz_dir]/honggfuzz -P -f INPUT.corpus -- ./test
```

`LLVMFuzzerInitialize(int *argc, char **argv)` is supported as well

### Fetching input with HF_ITER() ###

```c
$ cat test.c
#include <inttypes.h>
#include <testlib.h>  // Our API to test

// Get input from the fuzzer
extern void HF_ITER(uint8_t **buf, size_t *len);

int main(void) {
  for (;;) {
    uint8_t *buf;
    size_t len;
    HF_ITER(&buf, &len);
    _FuncFromFuzzedLib_(buf, len);
  }
  return 0;
}
```
```
$ [honggfuzz_dir]/honggfuzz/hfuzz_cc/hfuzz-clang -c fuzzedlib.c -o fuzzedlib.o
$ [honggfuzz_dir]/honggfuzz/hfuzz_cc/hfuzz-clang test.c fuzzedlib.o -o test
$ [honggfuzz_dir]/honggfuzz -P -f INPUT.corpus -- ./test
```

Example:
```
$ [honggfuzz_dir]/honggfuzz -P -f IN.server/ -- ./persistent.server.openssl.1.0.2i.asan
------------------------------[ honggfuzz v0.8 ]------------------------------
      Iterations : 3,275,169 [3.28M]
        Run Time : 2 hrs 17 min 16 sec (since: 2016-09-27 07:30:04)
       Input Dir : 'IN.server/'
      Fuzzed Cmd : './persistent.server.openssl.1.0.2i.asan'
 Fuzzing Threads : 2, CPUs: 8, CPU: 759.0% (94.9%/CPU)
   Speed (Round) : 86/sec (avg: 397)
         Crashes : 0 (unique: 0, blacklist: 0, verified: 0)
        Timeouts : 0 [10 sec.]
     Corpus size : 393 (max file size: 40,000 bytes)
        Coverage :
       *** blocks seen:    3,545, comparison map: 204,542
-----------------------------------[ LOGS ]-----------------------------------
```

PS. You can also use a non-persistent mode here (without the __-P__ flag), in which case you need to read data either from a file passed at command-line (`___FILE___`), or from the standard input (e.g. with `read(0, buf, sizeof(buf))`. The compile-time instrumentation will still work in such case.

# Hardware-based coverage #
## Unique branch pair (edges) counting (--linux_perf_bts_edge) ##

This mode will take into consideration pairs (tuples) of jumps, recording unique from-to jump pairs. The data is taken from the Intel BTS CPU registers.

```
$ [honggfuzz_dir]/honggfuzz --linux_perf_bts_edge -f IN.corpus/ -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 1
Start time: 2016-02-16 18:37:08 (1 seconds elapsed)
Input file/dir: 'IN/'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 2
Execs per second: 1 (avg: 1)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0)
Timeouts: 0
Number of dynamic files: 251
Coverage (max):
  - BTS unique edges:   2341
============================== LOGS ==============================
[2016-02-16T18:37:09+0100][I][14944] fuzz_perfFeedback():420 New: (Size New,Old): 257,257, Perf (Cur,New): 0/0/0/0/0/0,0/0/0/2341/0/0
```

## Unique branch points counting (--linux_perf_ipt_block) ##

This mode will utilize Interl's PT (Process Trace) subsystem, which should be way faster than BTS (Branch Trace Store), but will currently produce less precise results.

```
$ [honggfuzz_dir]/honggfuzz --linux_perf_ipt_block -f IN.corpus/ -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 0
Start time: 2016-02-16 18:38:45 (0 seconds elapsed)
Input file/dir: 'IN/'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 2
Execs per second: 0 (avg: 0)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0)
Timeouts: 0
Number of dynamic files: 251
Coverage (max):
  - PT unique blocks: 243
============================== LOGS ==============================
```

## Instruction counting (--linux_perf_instr) ##

This mode tries to maximize the number of instructions taken during each process iteration. The counters will be taken from the Linux perf subsystems. Intel, AMD and even other CPU architectures are supported for this mode.

```
$ [honggfuzz_dir]/honggfuzz --linux_perf_instr -f IN.corpus -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 2776
Start time: 2016-02-16 18:40:51 (3 seconds elapsed)
Input file/dir: 'CURRENT_BEST'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 2
Execs per second: 922 (avg: 925)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0)
Timeouts: 0
Number of dynamic files: 251
Coverage (max):
  - cpu instructions:      1369752
============================== LOGS ==============================
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2496, Perf (Cur,New): 1369752/0/0/0/0/0,1371747/0/0/0/0/0
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2497, Perf (Cur,New): 1371747/0/0/0/0/0,1372273/0/0/0/0/0
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2497, Perf (Cur,New): 1372273/0/0/0/0/0,1372390/0/0/0/0/0
[2016-02-16T18:40:54+0100][I][17406] fuzz_perfFeedback():420 New: (Size New,Old): 2497,2497, Perf (Cur,New): 1372390/0/0/0/0/0,1372793/0/0/0/0/0
```

## Branch counting (--linux_perf_branch) ##

As above, it will try to maximize the number of branches taken by CPU on behalf of the fuzzed process (here: djpeg.static) while performing each fuzzing iteration. Intel, AMD and even other CPU architectures are supported for this mode.

```
$ [honggfuzz_dir]/honggfuzz --linux_perf_branch -f IN/ -F 2500 -- /usr/bin/xmllint -format ___FILE___
============================== STAT ==============================
Iterations: 0
Start time: 2016-02-16 18:39:41 (0 seconds elapsed)
Input file/dir: 'IN/'
Fuzzed cmd: '/usr/bin/xmllint -format ___FILE___'
Fuzzing threads: 2
Execs per second: 0 (avg: 0)
Crashes: 0 (unique: 0, blacklist: 0, verified: 0)
Timeouts: 0
Number of dynamic files: 251
Coverage (max):
  - cpu branches:          0
============================== LOGS ==============================
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/0/0/0/0/0,0/258259/0/0/0/0
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/258259/0/0/0/0,0/258260/0/0/0/0
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/258260/0/0/0/0,0/258261/0/0/0/0
[2016-02-16T18:39:41+0100][I][16738] fuzz_perfFeedback():420 New: (Size New,Old): 2500,2500, Perf (Cur,New): 0/258261/0/0/0/0,0/258263/0/0/0/0
```
