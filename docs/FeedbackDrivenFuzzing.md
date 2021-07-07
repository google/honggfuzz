# Feedback-driven fuzzing #

Honggfuzz is capable of performing feedback-guided (code coverage driven) fuzzing. It can utilize the following sources of data:
  * (Linux) Hardware-based counters (instructions, branches)
  * (Linux) Intel BTS code coverage (kernel >= 4.2)
  * (Linux) Intel PT code coverage (kernel >= 4.2)
  * Sanitizer-coverage instrumentation (`-fsanitize-coverage=bb`)
  * Compile-time instrumentation (`-finstrument-functions` or `-fsanitize-coverage=trace-pc[-guard],indirect-calls,trace-cmp` or both)

Developers may provide the initial file corpus which will be gradually improved upon, but it's not necessary with feedback-driven modes.

---
# Requirements for software-based coverage-guided fuzzing #
  * `-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp` - Clang >= 5.0
  * `-fsanitize-coverage=trace-pc` - GCC >= 9.0
  * `-fsanitize-coverage=bb` - Clang >= 3.7
  * `-finstrument-functions` - GCC or Clang
  * [older, slower variant] `-fsanitize-coverage=trace-pc,indirect-calls` - Clang >= 3.9 

_Note_: The _-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp_ set of flags will be automatically added to clang's command-line switches when using [hfuzz-clang](https://github.com/google/honggfuzz/tree/master/hfuzz_cc) binary.

```shell
$ <honggfuzz_dir>/honggfuzz/hfuzz_cc/hfuzz-clang terminal-test.c -o terminal-test
```

---
# Requirements for hardware-based counter-based fuzzing #
  * GNU/Linux OS
  * A relatively modern Linux kernel (4.2 should be ok)
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
The implemented strategy identifies files which add new code coverage (or increased instruction/branch counters). Those inputs are then added to a dynamically stored in memory corpus, and reused during following fuzzing rounds

There are 2 phases of feedback-driven the fuzzing:
  * Honggfuzz goes through each file in the initial corpus directory (_-i_). It adds files which hit new code coverage to the dynamic input corpus.
  * Honggfuzz choses randomly files from the dynamic input corpus (in-memory), mutates them, and runs a new fuzzing round. If the newly created file induces new code path (extends code coverage), it gets added to the dynamic input corpus as well.

# Compile-time instrumentation with clang/gcc (default mode) #

Here you can use the following:
  * gcc/clang `-finstrument-functions` (less-precise)
  * clang's (>= 4.0) `-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp`
    (trace-cmp adds additional comparison map to the instrumentation)

_Note_: The _-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp_ set of flags will be automatically added to clang's command-line switches when using [hfuzz-clang](https://github.com/google/honggfuzz/tree/master/hfuzz_cc) binary. The [hfuzz-clang](https://github.com/google/honggfuzz/tree/master/hfuzz_cc) binary will also link your code with _libhfuzz.a_

# Hardware-based coverage #
## Unique branch pair (edges) counting (--linux_perf_bts_edge) ##

This mode will take into consideration pairs (tuples) of jumps, recording unique from-to jump pairs. The data is taken from the Intel BTS CPU registers.

```shell
$ <honggfuzz_dir>/honggfuzz --linux_perf_bts_edge -i input_corpus -- /usr/bin/xmllint -format ___FILE___
```

## Unique branch points counting (--linux_perf_ipt_block) ##

This mode will utilize Interl's PT (Process Trace) subsystem, which should be way faster than BTS (Branch Trace Store), but will currently produce less precise results.

```shell
$ <honggfuzz_dir>/honggfuzz --linux_perf_ipt_block -i input_corpus -- /usr/bin/xmllint -format ___FILE___
```

## Instruction counting (--linux_perf_instr) ##

This mode tries to maximize the number of instructions taken during each process iteration. The counters will be taken from the Linux perf subsystems. Intel, AMD and even other CPU architectures are supported for this mode.

```shell
$ <honggfuzz_dir>/honggfuzz --linux_perf_instr -i input_corpus -- /usr/bin/xmllint -format ___FILE___
```

## Branch counting (--linux_perf_branch) ##

As above, it will try to maximize the number of branches taken by CPU on behalf of the fuzzed process (here: djpeg.static) while performing each fuzzing iteration. Intel, AMD and even other CPU architectures are supported for this mode.

```shell
$ <honggfuzz_dir>/honggfuzz --linux_perf_branch -i input_corpus -F 2500 -- /usr/bin/xmllint -format ___FILE___
```
