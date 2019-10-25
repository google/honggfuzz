# Persistent fuzzing #

Honggfuzz is capable of fuzzing APIs, which is to say; to test new data within the same process. This speeds-up the process of fuzzing APIs greatly

# Requirements for hardware-based counter-based fuzzing #
  * GNU/Linux

# HowTo #

Prepare a binary in the two following ways:

## ASAN-style (_LLVMFuzzerTestOneInput_) ##

Two functions must be provided

```c
int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len)
````

and optionally

```c
int LLVMFuzzerInitialize(int *argc, char ***argv)
```

### Example (test.c):
```c
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
	TestAPI(buf, len);
	return 0;
}
```

### Compilation
```shell
$ hfuzz_cc/hfuzz-clang test.c -o test
```

### Fuzzing
```shell
$ honggfuzz -P -- ./test
```

## HF_ITER style ##

A complete program needs to be prepared, using ```HF_ITER``` symbol to fetch new inputs from honggfuzz

### Example (test.c):

```c
#include <inttypes.h>

extern HF_ITER(uint8_t** buf, size_t* len);

int main(void) {
	for (;;) {
		size_t len;
		uint8_t *buf;

		HF_ITER(&buf, &len);

		ApiToBeFuzzed(buf, len);
	}
}
```

### Compilation

```shell
$ hfuzz_cc/hfuzz-clang test.c -o test
```

## Fuzzing

```
$ honggfuzz -P -- ./test
```
