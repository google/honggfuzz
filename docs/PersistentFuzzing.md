# Persistent fuzzing #

Honggfuzz is capable of fuzzing APIs, which is to say; to test new data within the same process. This speeds-up the process of fuzzing APIs greatly

# Requirements for hardware-based counter-based fuzzing #
  * GNU/Linux or POSIX interface (e.g. FreeBSD, Windows/CygWin)

# HowTo #

One can prepare a binary in the two following ways:

## ASAN-style ##

Two functions must be prepared

```int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len)```

and (optional)

```int LLVMFuzzerInitialize(int *argc, char ***argv)```

Example (test.c):
```
int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
	TestAPI(buf, len);
	return 0;
}
```

Compilation:
```
$ hfuzz_cc/hfuzz_clang test.c -o test
```

Execution:
```
$ honggfuzz -P -- ./test
```

## HF_ITER style ##

A complete program needs to be prepared, using ```HF_ITER``` symbol to obtain new inputs

Example (test.c):
```c
#include <inttypes.h>

extern HF_ITER(uint8_t** buf, size_t* len);

int main(void) {
	for (;;) {
		size_t len;
		uint8_t *buf;

		HF_ITER(&buf, &len);

		TestAPI(buf, len);
	}
}
```

Compilation:
```
$ hfuzz_cc/hfuzz_clang test.c -o test ~/honggfuzz/libfuzz/libfuzz.a
```

Execution:
```
$ honggfuzz -P -- ./test
```

# Feedback-driven modes #

The persistent fuzzing can be easily used together with feedback-driven fuzzing. In order to achieve that, one needs to compile binary with compile-time instrumentation, or use hardware-based instrumentation (BTS, Intel PT). More can be found in this [document](FeedbackDrivenFuzzing.md)

Example (compile-time)
```
$ honggfuzz -P -z -- ./test
```

Example (hardware-based)
```
$ honggfuzz -P --linux_perf_bts_edge -- ./test
$ honggfuzz -P --linux_perf_ipt_block -- ./test
```
