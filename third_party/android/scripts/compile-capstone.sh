#!/bin/bash
#
#   honggfuzz capstone build help script
#   -----------------------------------------
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

if [ -z "$NDK" ]; then
  # Search in $PATH
  if [[ $(which ndk-build) != "" ]]; then
    NDK=$(dirname $(which ndk-build))
  else
    echo "[-] Could not detect Android NDK dir"
    exit 1
  fi
fi

if [ $# -ne 2 ]; then
  echo "[-] Invalid arguments"
  echo "[!] $0 <CAPSTONE_DIR> <ARCH>"
  echo "    ARCH: arm arm64 x86 x86_64"
  exit 1
fi

readonly CAPSTONE_DIR=$1

# Fetch if not already there
if [ ! -d $CAPSTONE_DIR ]; then
    echo "[!] capstone not found. Fetching a fresh copy"
    git clone https://github.com/aquynh/capstone $CAPSTONE_DIR
fi

case "$2" in
  arm|arm64|x86|x86_64)
    readonly ARCH=$2
    if [ ! -d $CAPSTONE_DIR/$ARCH ] ; then mkdir -p $CAPSTONE_DIR/$ARCH; fi
    ;;
  *)
    echo "[-] Invalid CPU architecture"
    exit 1
    ;;
esac

case "$ARCH" in
  arm)
    CS_ARCH="arm"
    CS_BUILD_BIN="./make.sh cross-android $ARCH"
    ;;
  arm64)
    CS_ARCH="arm aarch64"
    CS_BUILD_BIN="./make.sh cross-android $ARCH"
    ;;
  x86)
    CS_ARCH="x86"
    CS_BUILD_BIN="make"
    TOOLCHAIN=i686-linux-android
    TOOLCHAIN_S=x86-4.9
    ;;
  x86_64)
    CS_ARCH="x86"
    CS_BUILD_BIN="make"
    TOOLCHAIN=x86_64-linux-android
    TOOLCHAIN_S=x86_64-4.9
    ;;
esac

# Capstone handles internally only Android ARM cross builds not Intel x86/x86_x64
# We need to prepare the Android NDK toolchains manually for these builds
if [[ "$ARCH" == "x86" || "$ARCH" == "x86_64" ]]; then
  if [ -z "$NDK" ]; then
    # Search in $PATH
    if [[ $(which ndk-build) != "" ]]; then
      $NDK=$(dirname $(which ndk-build))
    else
      echo "[-] Could not detect Android NDK dir"
      exit 1
    fi
  fi

  # Support both Linux & Darwin
  HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  HOST_ARCH=$(uname -m)

  SYSROOT="$NDK/platforms/android-21/arch-$ARCH"
  export CC="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-gcc --sysroot=$SYSROOT"
  export CXX="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-g++ --sysroot=$SYSROOT"
  export PATH="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin":$PATH
  # We need to construct a cross variable that capstone Makefile can pick ar, strip & ranlib from
  export CROSS="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-" CFLAGS="--sysroot=$SYSROOT" LDFLAGS="--sysroot=$SYSROOT"
fi

# Change workdir to simplify args
cd $CAPSTONE_DIR

# Build it
make clean

NDK=$NDK CAPSTONE_BUILD_CORE_ONLY=yes CAPSTONE_ARCHS=$CS_ARCH \
CAPSTONE_SHARED=no CAPSTONE_STATIC=yes \
eval $CS_BUILD_BIN
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    exit 1
else
    echo "[*] '$ARCH' libcapstone  vailable at '$CAPSTONE_DIR/$ARCH'"
fi

cp libcapstone.a $ARCH/

# Revert workdir to caller
cd - &>/dev/null
