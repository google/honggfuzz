# REQUIREMENTS #

  * A POSIX compliant operating system, MacOSX, [Android](https://github.com/google/honggfuzz/blob/master/docs/Android.md) or Windows (CygWin)
  * GNU/Linux with modern kernel (>= v4.2) for hardware-based code coverage guided fuzzing (intel PT, Intel BTS, instruction/branch counting)
  * An input corpus: You might be interested in the following for some common file formats:
    * Image formats: Tavis Ormandy's [Image Testsuite](http://code.google.com/p/imagetestsuite/) has been effective at finding vulnerabilities in various graphics libraries.
    * PDF: Adobe provides some [test PDF files](http://acroeng.adobe.com/).
    * _**Note**: With the feedback-driven coverage-based modes, you can start your fuzzing without the input corpus._

## Compatibility list ##

It should work under the following operating systems:

| **OS** | **Status** | **Notes** |
|:-------|:-----------|:----------|
| **GNU/Linux** | Works | ptrace() API (x86, x86-64 disassembly support)|
| **FreeBSD** | Works | POSIX signal interface |
| **OpenBSD** | Works | POSIX signal interface |
| **NetBSD** | Works | ptrace() API (x86, x86-64 disassembly support)|
| **Mac OS X** | Works | POSIX signal interface/Mac OS X crash reports (x86-64/x86 disassembly support) |
| **Android** | Works | ptrace() API (x86, x86-64 disassembly support) |
| **MS Windows** | Works | POSIX signal interface via CygWin |
| **Other Unices** | Maybe | POSIX signal interface |

# USAGE #

## Non-persistent fuzzing w/o instrumentation (```-x```) ##

### Input as a file (```___FILE___```) ###
```shell
honggfuzz -i input_dir -x -- /usr/bin/djpeg ___FILE___
```

### Input on FD=0/STDIN (```-s```/```--stdin_input```) ####
```shell
honggfuzz -i input_dir -x -s -- /usr/bin/djpeg
```

## Non-persistent fuzzing with instrumentation ##

### Compile-time instrumentation (```-z```/```--instrument```). _Note: it is enabled by default_ ###
```shell
  honggfuzz -i input_dir -z -- instrumented.djpeg ___FILE___
```

### QEMU-mode (black-box instrumentation) ###
```shell
honggfuzz -i input_dir -- <honggfuzz_dir>/qemu_mode/honggfuzz-qemu/x86_64-linux-user/qemu-x86_64 /usr/bin/djpeg ___FILE___
```

### Various hardware-based mechanisms/counters ###
```shell
  honggfuzz -i input_dir --linux_perf_bts_edge -- /usr/bin/djpeg ___FILE___
  honggfuzz -i input_dir --linux_perf_ipt_block -- /usr/bin/djpeg ___FILE___
  honggfuzz -i input_dir --linux_perf_instr -- /usr/bin/djpeg ___FILE___
  honggfuzz -i input_dir --linux_perf_branch -- /usr/bin/djpeg ___FILE___
```

## Persistent-mode (```-P```). _Note: it will be auto-detected_ ##

```shell
  honggfuzz -i input_dir -z -P -- jpeg_persistent_mode
  honggfuzz -i input_dir --linux_perf_bts_edge -P -- jpeg_persistent_mode
  honggfuzz -i input_dir --linux_perf_ipt_block -P -- jpeg_persistent_mode
  honggfuzz -i input_dir --linux_perf_branch -P -- jpeg_persistent_mode
  honggfuzz -i input_dir --linux_perf_instr -P -- jpeg_persistent_mode
```

but also a couple of instrumentation mechanisms used together

```shell
honggfuzz -i input_dir --linux_perf_bts_edge --linux_perf_instr -P -- jpeg_persistent_mode
```

## Corpus Minimization (```-M```) ##

### Minimize corpus directly inside the input (```-i```/```--input```) directory ###

```shell
honggfuzz -i input_dir -P -M -- jpeg_persistent_mode
```

or

```shell
honggfuzz -i input_dir -M -- instrumented.djpeg ___FILE___
```

### Save minimized corpus to the output (```--output```) directory  ###

```shell
honggfuzz -i input_dir --output output_dir -P -M -- jpeg_persistent_mode
```

or

```shell
honggfuzz -i input_dir --output output_dir -M -- instrumented.djpeg ___FILE___
```

# CMDLINE ```--help``` #

```shell
Usage: ./honggfuzz [options] -- path_to_command [args]
Options:
 --help|-h 
	Help plz..
 --input|-i VALUE
	Path to a directory containing initial file corpus
 --output VALUE
	Output data (new dynamic coverage corpus, or the minimized coverage corpus) is written to this directory (default: input directory is used)
 --persistent|-P 
	Enable persistent fuzzing (use hfuzz_cc/hfuzz-clang to compile code). This will be auto-detected!!!
 --instrument|-z 
	*DEFAULT-MODE-BY-DEFAULT* Enable compile-time instrumentation (use hfuzz_cc/hfuzz-clang to compile code)
 --minimize|-M 
	Minimize the input corpus. It will most likely delete some corpus files (from the --input directory) if no --output is used!
 --noinst|-x 
	Static mode only, disable any instrumentation (hw/sw) feedback
 --keep_output|-Q 
	Don't close children's stdin, stdout, stderr; can be noisy
 --timeout|-t VALUE
	Timeout in seconds (default: 10)
 --threads|-n VALUE
	Number of concurrent fuzzing threads (default: number of CPUs / 2)
 --stdin_input|-s 
	Provide fuzzing input on STDIN, instead of ___FILE___
 --mutations_per_run|-r VALUE
	Maximal number of mutations per one run (default: 6)
 --logfile|-l VALUE
	Log file
 --verbose|-v 
	Disable ANSI console; use simple log output
 --verifier|-V 
	Enable crashes verifier
 --debug|-d 
	Show debug messages (level >= 4)
 --quiet|-q 
	Show only warnings and more serious messages (level <= 1)
 --extension|-e VALUE
	Input file extension (e.g. 'swf'), (default: 'fuzz')
 --workspace|-W VALUE
	Workspace directory to save crashes & runtime files (default: '.')
 --crashdir VALUE
	Directory where crashes are saved to (default: workspace directory)
 --covdir_all VALUE
	** DEPRECATED ** use --output
 --covdir_new VALUE
	New coverage (beyond the dry-run fuzzing phase) is written to this separate directory
 --dict|-w VALUE
	Dictionary file. Format:http://llvm.org/docs/LibFuzzer.html#dictionaries
 --stackhash_bl|-B VALUE
	Stackhashes blacklist file (one entry per line)
 --mutate_cmd|-c VALUE
	External command producing fuzz files (instead of internal mutators)
 --pprocess_cmd VALUE
	External command postprocessing files produced by internal mutators
 --ffmutate_cmd VALUE
	External command mutating files which have effective coverage feedback
 --run_time VALUE
	Number of seconds this fuzzing session will last (default: 0 [no limit])
 --iterations|-N VALUE
	Number of fuzzing iterations (default: 0 [no limit])
 --rlimit_as VALUE
	Per process RLIMIT_AS in MiB (default: 0 [no limit])
 --rlimit_rss VALUE
	Per process RLIMIT_RSS in MiB (default: 0 [no limit]). It will also set *SAN's soft_rss_limit_mb if used
 --rlimit_data VALUE
	Per process RLIMIT_DATA in MiB (default: 0 [no limit])
 --rlimit_core VALUE
	Per process RLIMIT_CORE in MiB (default: 0 [no cores are produced])
 --report|-R VALUE
	Write report to this file (default: '<workdir>/HONGGFUZZ.REPORT.TXT')
 --max_file_size|-F VALUE
	Maximal size of files processed by the fuzzer in bytes (default: 1048576 = 1MB)
 --clear_env 
	Clear all environment variables before executing the binary
 --env|-E VALUE
	Pass this environment variable, can be used multiple times
 --save_all|-u 
	Save all test-cases (not only the unique ones) by appending the current time-stamp to the filenames
 --save_smaller|-U
    Save smaller test-cases, renaming first found with .orig suffix
 --tmout_sigvtalrm|-T 
	Use SIGVTALRM to kill timeouting processes (default: use SIGKILL)
 --sanitizers|-S 
	Enable sanitizers settings (default: false)
 --monitor_sigabrt VALUE
	Monitor SIGABRT (default: false for Android, true for other platforms)
 --no_fb_timeout VALUE
	Skip feedback if the process has timeouted (default: false)
 --exit_upon_crash 
	Exit upon seeing the first crash (default: false)
 --socket_fuzzer 
	Instrument external fuzzer via socket
 --netdriver 
	Use netdriver (libhfnetdriver/). In most cases it will be autodetected through a binary signature
 --only_printable 
	Only generate printable inputs
 --linux_symbols_bl VALUE
	Symbols blacklist filter file (one entry per line)
 --linux_symbols_wl VALUE
	Symbols whitelist filter file (one entry per line)
 --linux_addr_low_limit VALUE
	Address limit (from si.si_addr) below which crashes are not reported, (default: 0)
 --linux_keep_aslr 
	Don't disable ASLR randomization, might be useful with MSAN
 --linux_perf_ignore_above VALUE
	Ignore perf events which report IPs above this address
 --linux_perf_instr 
	Use PERF_COUNT_HW_INSTRUCTIONS perf
 --linux_perf_branch 
	Use PERF_COUNT_HW_BRANCH_INSTRUCTIONS perf
 --linux_perf_bts_edge 
	Use Intel BTS to count unique edges
 --linux_perf_ipt_block 
	Use Intel Processor Trace to count unique blocks (requires libipt.so)
 --linux_perf_kernel_only 
	Gather kernel-only coverage with Intel PT and with Intel BTS
 --linux_ns_net 
	Use Linux NET namespace isolation
 --linux_ns_pid 
	Use Linux PID namespace isolation
 --linux_ns_ipc 
	Use Linux IPC namespace isolation

Examples:
 Run the binary over a mutated file chosen from the directory. Disable fuzzing feedback (static mode):
  honggfuzz -i input_dir -x -- /usr/bin/djpeg ___FILE___
 As above, provide input over STDIN:
  honggfuzz -i input_dir -x -s -- /usr/bin/djpeg
 Use compile-time instrumentation (-fsanitize-coverage=trace-pc-guard,...):
  honggfuzz -i input_dir -- /usr/bin/djpeg ___FILE___
 Use persistent mode w/o instrumentation:
  honggfuzz -i input_dir -P -x -- /usr/bin/djpeg_persistent_mode
 Use persistent mode and compile-time (-fsanitize-coverage=trace-pc-guard,...) instrumentation:
  honggfuzz -i input_dir -P -- /usr/bin/djpeg_persistent_mode
 Run the binary with dynamically generate inputs, maximize total no. of instructions:
  honggfuzz --linux_perf_instr -- /usr/bin/djpeg ___FILE___
 As above, maximize total no. of branches:
  honggfuzz --linux_perf_branch -- /usr/bin/djpeg ___FILE___
 As above, maximize unique branches (edges) via Intel BTS:
  honggfuzz --linux_perf_bts_edge -- /usr/bin/djpeg ___FILE___
 As above, maximize unique code blocks via Intel Processor Trace (requires libipt.so):
  honggfuzz --linux_perf_ipt_block -- /usr/bin/djpeg ___FILE___
```

# OUTPUT FILES #

| **Mode** | **Output file** |
|:---------|:----------------|
| Linux,NetBSD | **SIGSEGV.PC.4ba1ae.STACK.13599d485.CODE.1.ADDR.0x10.INSTR.mov____0x10(%rbx),%rax.fuzz** |
| POSIX signal interface | **SIGSEGV.22758.2010-07-01.17.24.41.tif** |

## Description ##

  * **SIGSEGV**,**SIGILL**,**SIGBUS**,**SIGABRT**,**SIGFPE** - Description of the signal which terminated the process (when using ptrace() API, it's a signal which was delivered to the process, even if silently discarded)
  * **PC.0x8056ad7** - Program Counter (PC) value (ptrace() API only), for x86 it's a value of the EIP register (RIP for x86-64)
  * **STACK.13599d485** - Stack signature (based on stack-tracing)
  * **ADDR.0x30333037** - Value of the ```_siginfo_t.si_addr_``` (see _man 2 signaction_ for more details) (most likely meaningless for SIGABRT)
  * **INSTR.mov____0x10(%rbx),%rax** - Disassembled instruction which was found under the last known PC (Program Counter) (x86, x86-64 architectures only, meaningless for SIGABRT)

# FAQ #

  * Q: **Why the name _honggfuzz_**?
  * A: The term honggfuzz was coined during a major and memorable event in the city of [Zurich](http://en.wikipedia.org/wiki/H%C3%B6ngg), where a Welsh security celebrity tried to reach Höngg in a cab while singing _[Another one bites the dust](https://en.wikipedia.org/wiki/Another_One_Bites_the_Dust)_.

  * Q: **Why do you prefer the ptrace() API to the POSIX signal interface**?
  * A: The ptrace() API is more flexible when it comes to analyzing a process' crash. wait3/4() syscalls are only able to determine the type of signal which crashed an application and limited resource usage information (see _man wait4_).

  * Q: **Why isn't there any support for the ptrace() API when compiling under FreeBSD or Mac OS X operating systems**?
  * A: These operating systems lack some specific ptrace() operations, including ```PT_GETREGS``` (Mac OS X) and ```PT_GETSIGINFO```, both of which honggfuzz depends on. If you have any ideas on how to get around this limitation, send us an email or patch.

# LICENSE #

 This project is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

# CREDITS #

  * Thanks to **[taviso@google.com Tavis Ormandy]** for many valuable ideas used in the course of this project's design and implementation phases
  * Thanks to my 1337 friends for all sorts of support and distraction :) - **LiquidK, lcamtuf, novocainated, asiraP, ScaryBeasts, redpig, jln**
