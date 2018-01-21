all: vulnserver_cov

vulnserver_cov:
	unset HFUZZ_CC_ASAN
	../hfuzz_cc/hfuzz-gcc vulnserver_cov.c -o vulnserver_cov
