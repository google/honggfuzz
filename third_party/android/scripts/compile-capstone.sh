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

#set -x # debug

abort() {
  cd - &>/dev/null
  exit "$1"
}

trap "abort 1" SIGINT SIGTERM

if [ $# -ne 2 ]; then
  echo "[-] Invalid arguments"
  echo "[!] $0 <CAPSTONE_DIR> <ARCH>"
  echo "    ARCH: arm arm64 x86 x86_64"
  exit 1
fi

readonly CAPSTONE_DIR="$1"

if [ ! -d "$CAPSTONE_DIR/.git" ]; then
  git submodule update --init third_party/android/capstone || {
    echo "[-] git submodules init failed"
    exit 1
  }
fi

# register client hooks
hooksDir="$(git -C "$CAPSTONE_DIR" rev-parse --git-dir)/hooks"
mkdir -p "$hooksDir"

if [ ! -f "$hooksDir/post-checkout" ]; then
  cat > "$hooksDir/post-checkout" <<'endmsg'
#!/usr/bin/env bash

rm -f arm/*.a
rm -f arm64/*.a
rm -f x86/*.a
rm -f x86_64/*.a
endmsg
  chmod +x "$hooksDir/post-checkout"
fi

# Change workspace
cd "$CAPSTONE_DIR" &>/dev/null

if [ -z "$NDK" ]; then
  # Search in $PATH
  if [[ $(which ndk-build) != "" ]]; then
    NDK=$(dirname $(which ndk-build))
  else
    echo "[-] Could not detect Android NDK dir"
    abort 1
  fi
fi

case "$2" in
  arm|arm64|x86|x86_64)
    readonly ARCH=$2
    if [ ! -d $ARCH ] ; then mkdir -p $ARCH; fi
    ;;
  *)
    echo "[-] Invalid CPU architecture"
    abort 1
    ;;
esac

# Check if previous build exists and matches selected ANDROID_API level
# If API cache file not there always rebuild
if [ -f "$ARCH/libcapstone.a" ]; then
  if [ -f "$ARCH/android_api.txt" ]; then
    old_api=$(cat "$ARCH/android_api.txt")
    if [[ "$old_api" == "$ANDROID_API" ]]; then
      # No need to recompile
      abort 0
    fi
  fi
fi

case "$ARCH" in
  arm)
    CS_ARCH="arm"
    CS_BUILD_BIN="make"
    TOOLCHAIN=arm-linux-androideabi
    TOOLCHAIN_S=arm-linux-androideabi-4.9
    ;;
  arm64)
    CS_ARCH="arm aarch64"
    CS_BUILD_BIN="make"
    TOOLCHAIN=aarch64-linux-android
    TOOLCHAIN_S=aarch64-linux-android-4.9
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

# Capstone ARM/ARM64 cross-compile automation is broken,
# we need to prepare the Android NDK toolchains manually
if [ -z "$NDK" ]; then
  # Search in $PATH
  if [[ $(which ndk-build) != "" ]]; then
    $NDK=$(dirname $(which ndk-build))
  else
    echo "[-] Could not detect Android NDK dir"
    abort 1
  fi
fi

if [ -z "$ANDROID_API" ]; then
  ANDROID_API="android-26"
fi
if ! echo "$ANDROID_API" | grep -qoE 'android-[0-9]{1,2}'; then
  echo "[-] Invalid ANDROID_API '$ANDROID_API'"
  abort 1
fi
ANDROID_API_V=$(echo "$ANDROID_API" | grep -oE '[0-9]{1,2}$')

# Support both Linux & Darwin
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -m)

SYSROOT="$NDK/platforms/$ANDROID_API/arch-$ARCH"
export CC="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-gcc --sysroot=$SYSROOT -isystem $NDK/sysroot/usr/include/$TOOLCHAIN -isystem $NDK/sysroot/usr/include/ -D__ANDROID_API__=$ANDROID_API_V"
export CXX="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-g++ --sysroot=$SYSROOT -isystem $NDK/sysroot/usr/include/$TOOLCHAIN -isystem $NDK/sysroot/usr/include/ -D__ANDROID_API__=$ANDROID_API_V"
export PATH="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin":$PATH

# We need to construct a cross variable that capstone Makefile can pick ar, strip & ranlib from
export CROSS="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-" CFLAGS="--sysroot=$SYSROOT -isystem $NDK/sysroot/usr/include/$TOOLCHAIN -isystem $NDK/sysroot/usr/include/" LDFLAGS="--sysroot=$SYSROOT -isystem $NDK/sysroot/usr/include/$TOOLCHAIN -isystem $NDK/sysroot/usr/include/"

# Build it
make clean

NDK=$NDK CAPSTONE_BUILD_CORE_ONLY=yes CAPSTONE_ARCHS=$CS_ARCH \
CAPSTONE_SHARED=no CAPSTONE_STATIC=yes \
eval $CS_BUILD_BIN
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    abort 1
else
    echo "[*] '$ARCH' libcapstone available at '$CAPSTONE_DIR/$ARCH'"
fi

cp libcapstone.a "$ARCH/"
echo "$ANDROID_API" > "$ARCH/android_api.txt"

abort 0
