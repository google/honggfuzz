#!/bin/sh

set -x
set -e

DIR="$1"
SAN="$2"
TYPE=`basename "$DIR"`
HFUZZ_SRC=~/src/honggfuzz/
OS=`uname -s`
CC="$HFUZZ_SRC/hfuzz_cc/hfuzz-clang"
CXX="$HFUZZ_SRC/hfuzz_cc/hfuzz-clang++"
COMMON_FLAGS="-DBORINGSSL_UNSAFE_DETERMINISTIC_MODE -DBORINGSSL_UNSAFE_FUZZER_MODE -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DBN_DEBUG -DLIBRESSL_HAS_TLS1_3 \
	-O3 -g -DFuzzerInitialize=LLVMFuzzerInitialize -DFuzzerTestOneInput=LLVMFuzzerTestOneInput \
	-I./$DIR/include -I$HFUZZ_SRC/examples/openssl -I$HFUZZ_SRC"
COMMON_LDFLAGS="-lpthread -lz -Wl,-z,now"

if [ -z "$DIR" ]; then
	echo "$0" DIR SANITIZE
	exit 1
fi

LIBSSL="`find "$DIR" -type f -name 'libssl.a' | head -n1`"
if [ -z "$LIBSSL" ]; then
	echo "Couldn't find libssl.a inside $DIR"
	exit 1
fi

LIBCRYPTO="`find "$DIR" -type f -name 'libcrypto.a' | head -n1`"
if [ -z "$LIBCRYPTO" ]; then
	echo "Couldn't find libcrypto.a inside $DIR"
	exit 1
fi


if [ "$OS" = "Linux" ]; then
	COMMON_LDFLAGS="$COMMON_LDFLAGS -ldl"
fi

if [ -n "$SAN" ]; then
	SAN_COMPILE="-fsanitize=$SAN"
	SAN=".$SAN"
fi

for x in x509 privkey client server; do
	$CC $COMMON_FLAGS -g "$HFUZZ_SRC/examples/openssl/$x.c" -o "$TYPE$SAN.$x$SUFFIX" "$LIBSSL" "$LIBCRYPTO" $COMMON_LDFLAGS $SAN_COMPILE
done

for x in x509 privkey client server; do
	$CC $COMMON_FLAGS -DHF_SSL_FROM_STDIN -g "$HFUZZ_SRC/examples/openssl/$x.c" -o "stdin.$TYPE$SAN.$x" "$LIBSSL" "$LIBCRYPTO" $COMMON_LDFLAGS $SAN_COMPILE
done

for x in x509 privkey client server; do
	clang++ $COMMON_FLAGS -g "$HFUZZ_SRC/examples/openssl/$x.c" -o "libfuzzer.$TYPE$SAN.$x$SUFFIX" "$LIBSSL" "$LIBCRYPTO" $COMMON_LDFLAGS $SAN_COMPILE -lFuzzer
done

