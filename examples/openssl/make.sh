#!/bin/sh

set -x
set -e

TYPE="$1"
SAN="$2"
COMMON_FLAGS="-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE -DBORINGSSL_UNSAFE_FUZZER_MODE -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DBN_DEBUG -O3 -g -DFuzzerInitialize=LLVMFuzzerInitialize -DFuzzerTestOneInput=LLVMFuzzerTestOneInput -lpthread -lz -Wl,-z,now"
OS=`uname -s`
HFUZZ_SRC=~/src/honggfuzz/
CC="$HFUZZ_SRC/hfuzz_cc/hfuzz-clang"
CXX="clang++"

if [ "$OS" = "Linux" ]; then
		COMMON_FLAGS="$COMMON_FLAGS -ldl"
fi

if [ -z "$TYPE" ]; then
		echo "$0" DIR SANITIZE
		exit 1
fi

if [ -n "$SAN" ]; then
		SAN_COMPILE="-fsanitize=$SAN"
		SAN=".$SAN"
fi

$CC $COMMON_FLAGS -g "$HFUZZ_SRC/examples/openssl/server.c" "-I./openssl-$TYPE/include" -o "persistent.server.openssl.$TYPE$SAN" "./openssl-$TYPE/libssl.a" "./openssl-$TYPE/libcrypto.a" $SAN_COMPILE
$CC $COMMON_FLAGS -g "$HFUZZ_SRC/examples/openssl/client.c" "-I./openssl-$TYPE/include" -o "persistent.client.openssl.$TYPE$SAN" "./openssl-$TYPE/libssl.a" "./openssl-$TYPE/libcrypto.a" $SAN_COMPILE
$CC $COMMON_FLAGS -g "$HFUZZ_SRC/examples/openssl/x509.c" "-I./openssl-$TYPE/include" -o "persistent.x509.openssl.$TYPE$SAN" "./openssl-$TYPE/libssl.a" "./openssl-$TYPE/libcrypto.a" $SAN_COMPILE
$CC $COMMON_FLAGS -g "$HFUZZ_SRC/examples/openssl/privkey.c" "-I./openssl-$TYPE/include" -o "persistent.privkey.openssl.$TYPE$SAN" "./openssl-$TYPE/libssl.a" "./openssl-$TYPE/libcrypto.a" $SAN_COMPILE
