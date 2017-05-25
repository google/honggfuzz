:

# Use enable-msan for MSAN and enable-ubsan for UBSAN
# You can also remove enable-asan for pure code coverage growth mode,
# as it will be a bit faster

set -x
set -e

make clean

export CC=/home/jagger/src/honggfuzz/hfuzz_cc/hfuzz-clang
./config \
	-DPEDANTIC no-shared \
	-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
	-DCRYPTO_memcmp=memcmp -DOPENSSL_memcmp=memcmp -O3 \
	enable-ec_nistp_64_gcc_128 -fno-sanitize=alignment enable-tls1_3 \
	enable-weak-ssl-ciphers enable-rc5 enable-md2 \
	enable-ssl3 enable-ssl3-method enable-nextprotoneg \
	enable-asan enable-tls13downgrade \
	--debug

make -j4
