#!/bin/bash
#
#   honggfuzz libunwind build help script
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

set -x # debug

readonly JOBS=$(getconf _NPROCESSORS_ONLN)

abort() {
  cd - &>/dev/null
  exit "$1"
}

trap "abort 1" SIGINT SIGTERM

if [ $# -ne 2 ]; then
  echo "[-] Invalid arguments"
  echo "[!] $0 <LIBUNWIND_DIR> <ARCH>"
  echo "    ARCH: arm arm64 x86 x86_64"
  exit 1
fi

readonly LIBUNWIND_DIR="$1"

if [ ! -d "$LIBUNWIND_DIR/.git" ]; then
  git submodule update --init third_party/android/libunwind || {
    echo "[-] git submodules init failed"
    exit 1
  }
fi

# register client hooks
hooksDir="$(git -C "$LIBUNWIND_DIR" rev-parse --git-dir)/hooks"
mkdir -p "$hooksDir"

if [ ! -f "$hooksDir/post-checkout" ]; then
  cat > "$hooksDir/post-checkout" <<'endmsg'
#!/usr/bin/env bash

endmsg
  chmod +x "$hooksDir/post-checkout"
fi

# Change workspace
cd "$LIBUNWIND_DIR" &>/dev/null

if [ -z "$NDK" ]; then
  # Search in $PATH
  if [[ $(which ndk-build) != "" ]]; then
    NDK=$(dirname $(which ndk-build))
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

LC_LDFLAGS="-static"

ARCH="$2"

# Prepare toolchain
case "$ARCH" in
  arm)
    TOOLCHAIN=arm-linux-androideabi
    ;;
  arm64)
    TOOLCHAIN=aarch64-linux-android
    ;;
  x86)
    TOOLCHAIN=i686-linux-android
    ;;
  x86_64)
    TOOLCHAIN=x86_64-linux-android
    ;;
esac

# Apply patches required for Android
# TODO: Automate global patching when all archs have been tested

# Ptrace patches due to Android incompatibilities
git reset --hard

git apply --check ../patches/libunwind.patch
if [ $? -eq 0 ]; then
  git apply ../patches/libunwind.patch
  if [ $? -ne 0 ]; then
    echo "[-] Failed to apply libunwind patches"
    abort 1
  fi
else
  echo "[-] Cannot apply libunwind patches"
  abort 1
fi

# Support both Linux & Darwin
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -m)


export CC="$NDK"/toolchains/llvm/prebuilt/linux-x86_64/bin/"$ANDROID_NDK_COMPILER_PREFIX""$ANDROID_API_V"-clang
export CXX="$NDK"/toolchains/llvm/prebuilt/linux-x86_64/bin/"$ANDROID_NDK_COMPILER_PREFIX""$ANDROID_API_V"-clang++

if [ ! -x "$CC" ]; then
  echo "[-] clang doesn't exist: $CC"
  abort 1
elif [ ! -x "$CXX" ]; then
  echo "[-] clang++ doesn't exist: $CXX"
  abort 1
fi

if [ ! -f configure ]; then
  NOCONFIGURE=true ./autogen.sh
  if [ $? -ne 0 ]; then
    echo "[-] autogen failed"
    abort 1
  fi
  # Patch configure
  sed -i -e 's/-lgcc_s/-lgcc/g' configure
else
  make clean
fi

./configure --host=$TOOLCHAIN --disable-coredump
if [ $? -ne 0 ]; then
  echo "[-] configure failed"
  abort 1
fi

make -j"$JOBS" CFLAGS="$LC_CFLAGS" LDFLAGS="$LC_LDFLAGS"
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    cd - &>/dev/null
    abort 1
fi

# Naming conventions for arm64
if [[ "$ARCH" == "arm64" ]]; then
  cd "$ARCH"
  find . -type f -name "*aarch64*.a" | while read -r libFile
  do
    fName=$(basename "$libFile")
    newFName=$(echo "$fName" | sed "s#aarch64#arm64#")
    ln -sf "$fName" "$newFName"
  done
  cd -
fi

abort 0
