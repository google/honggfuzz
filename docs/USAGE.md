
---



---

# INTRODUCTION #

This document describes the **honggfuzz** project.


---

# OBJECTIVE #

Honggfuzz is a general-purpose fuzzing tool. Given a starting corpus of test files, Hongfuzz supplies and modifies input to a test program and utilize the **ptrace() API**/**POSIX signal interface** to detect and log crashes.


---

# FEATURES #

  * **Easy setup**: No complicated configuration files or setup necessary -- Hongfuzz can be run directly from the command line.
  * **Fast**: Multiple Hongfuzz instances can be run simultaneously for more efficient fuzzing.
  * **Powerful analysis capabilities**: Hongfuzz will use the most powerful process state analysis (e.g. ptrace) interface under a given OS.


---

# REQUIREMENTS #

  * A POSIX compilant operating system (See the compatibility list for more)
  * The **[capstone](capstone.md)** library (wth x86/amd64 Linux boxes)
  * A corpus of input files. Honggfuzz expects a set of files to use and modify as input to the application you're fuzzing. How you get or create these files is up to you, but you might be interested in the following sources:
    * Image formats: Tavis Ormandy's [Image Testuite](http://code.google.com/p/imagetestsuite/) has been effective at finding vulnerabilities in various graphics libraries.
    * PDF: Adobe provides some [test PDF files](http://acroeng.adobe.com/).

## Compatibility list ##

It should work under the following operating systems:

| **OS** | **Status** | **Notes** |
|:-------|:-----------|:----------|
| **GNU/Linux** | Works | ptrace() API (x86, x86-64 disassembly support)|
| **FreeBSD** | Works | POSIX signal interface |
| **Mac OS X** | Works | POSIX signal interface/Mac OS X crash reports (x86-64/x86 disassembly support) |
| **MS Windows** | Doesn't work | The POSIX signal implementation provided by the Cygwin project is not sufficient |
| **Other Unices** | Depends`*` | POSIX signal interface |

_`*`) It might work provided that a given operating system implements **wait3()** call_

---

# USAGE #

```
$ ./honggfuzz 
honggfuzz version 0.3 Robert Swiecki <swiecki@google.com>, Copyright 2010 by Google Inc. All Rights Reserved.
 <-f val>: input file (or input dir)
 [-h]: this help
 [-q]: null-ify children's stdin, stdout, stderr; make them quiet
 [-s]: standard input fuzz, instead of providing a file argument
 [-u]: save unique test-cases only, otherwise (if not used) append
       current timestamp to the output filenames
 [-d val]: debug level (0 - FATAL ... 4 - DEBUG), default: '3' (INFO)
 [-e val]: file extension (e.g swf), default: 'fuzz'
 [-r val]: flip rate, default: '0.001'
 [-m val]: flip mode (-mB - byte, -mb - bit), default: '-mB'
 [-c val]: command modifying input files externally (instead of -r/-m)
 [-t val]: timeout (in secs), default: '3' (0 - no timeout)
 [-a val]: address limit (from si.si_addr) below which crashes
           are not reported, default: '0' (suggested: 65535)
 [-n val]: number of concurrent fuzzing processes, default: '5'
 [-l val]: per process memory limit in MiB, default: '0' (no limit)
 [-p val]: attach to a pid (a group thread), instead of monitoring
           previously created process, default: '0' (none) (ptrace only)
usage: honggfuzz -f input_dir -- /usr/bin/tiffinfo -D ___FILE___
```

Honggfuzz offers simple file mutation algorithm only (bits/bytes). This [document](ExternalFuzzerUsage.md) explains how to use an external command to create fuzzing input.


---

# OUTPUT FILES #

| **Mode** | **Output file** |
|:---------|:----------------|
| Unique mode (**-u**) | **SIGSEGV.PC.0x7ffff78c8f70.CODE.1.ADDR.0x6c9000.INSTR.mov`_``[`rdi+0x10`]`,`_`[r9](https://code.google.com/p/honggfuzz/source/detail?r=9).ttf** |
| Non-unique mode | **SIGSEGV.PC.0x8056ad7.CODE.1.ADDR.0x30333037.INSTR.movsx\_eax,`_``[`eax`]`.TIME.2010-06-07.02.25.04.PID.10097.ttf** |
| POSIX signal interface | **SIGSEGV.22758.2010-07-01.17.24.41.tif** |

## Description ##

  * **SIGSEGV**,**SIGILL**,**SIGBUS**,**SIGABRT**,**SIGFPE** - Description of the signal which terminated the process (when using ptrace() API, it's a signal which was delivered to the process, even if silently discarded)
  * **PC.0x8056ad7** - Program Counter (PC) value (ptrace() API only), for x86 it's a value of the EIP register (RIP for x86-64)
  * **CODE.1** - Value of the _siginfo`_`t.si`_`code_ field (see _man 2 signaction_ for more details), valid for some signals (e.g. SIGSEGV) only
  * **ADDR.0x30333037** - Value of the _siginfo`_`t.si`_`addr_ (see _man 2 signaction_ for more details) (most likely meaningless for SIGABRT)
  * **INSTR.movsx\_eax,`_``[`eax`]`** - Disassembled instruction which was found under the last known PC (Program Counter) (x86, x86-64 architectures only, meaningless for SIGABRT)
  * **TIME.2010-06-07.02.25.04** - Local time when the signal was delivered
  * **PID.10097** - Fuzzing process' id (PID) (See [AttachingToPid](AttachingToPid.md) for more)


---

# FAQ #

  * Q: **Why the name _honggfuzz_**?
  * A: The term honggfuzz was coined during a major and memorable event in the city of [Zurich](http://en.wikipedia.org/wiki/H%C3%B6ngg), where a Welsh security celebrity tried to reach Höngg in a cab while singing _Another one bites the dust_.

  * Q: **Why do you prefer the ptrace() API to the POSIX signal interface**?
  * A: The ptrace() API is more flexible when it comes to analyzing a process' crash. wait3/4() syscalls are only able to determine the type of signal which crashed an application and limited resource usage information (see _man wait4_).

  * Q: **Why isn't there any support for the ptrace() API when compiling under FreeBSD or Mac OS X operating systems**?
  * A: These operating systems lack some specific ptrace() operations, including **PT`_`GETREGS** (Mac OS X) and **PT`_`GETSIGINFO**, both of which Hongfuzz depends on. If you have any ideas on how to get around this limitation, send us an email or patch.


---

# LICENSE #

This project is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

---

# CREDITS #

  * Thanks to **[taviso@google.com Tavis Ormandy]** for many valuable ideas used in the course of this project's design and implementation phases
  * Thanks to my 1337 friends for all sorts of support and distraction :) - **LiquidK, lcamtuf, novocainated, asiraP, ScaryBeasts, redpig, jln**