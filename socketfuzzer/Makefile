all: vulnserver_cov

vulnserver_cov: vulnserver_cov.c
	unset HFUZZ_CC_ASAN
	../hfuzz_cc/hfuzz-cc vulnserver_cov.c -o vulnserver_cov
