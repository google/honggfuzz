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

#set -x # debug

readonly JOBS=$(getconf _NPROCESSORS_ONLN)

abort() {
  # Revert patches if not debugging
  if [[ "$-" == *x* ]]; then
    echo "[!] git patches are not reverted since running under debug mode"
  else
    # Extra care to ensure we're under expected project
    if [[ $# -eq 1 && "$(basename $(git rev-parse --show-toplevel))" == "libunwind" ]]; then
      echo "[*] Resetting locally applied patches"
      git reset --hard &>/dev/null || {
        echo "[-] git reset failed"
      }
    fi
  fi

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

rm -f arm/*.a
rm -f arm64/*.a
rm -f x86/*.a
rm -f x86_64/*.a
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

case "$2" in
  arm|arm64|x86|x86_64)
    readonly ARCH="$2"
    if [ ! -d "$ARCH" ] ; then mkdir -p "$ARCH"; fi
    ;;
  *)
    echo "[-] Invalid architecture"
    abort 1
    ;;
esac

# Check if previous build exists and matches selected ANDROID_API level
# If API cache file not there always rebuild
if [ -f "$ARCH/libunwind-$ARCH.a" ]; then
  if [ -f "$ARCH/android_api.txt" ]; then
    old_api=$(cat "$ARCH/android_api.txt")
    if [[ "$old_api" == "$ANDROID_API" ]]; then
      # No need to recompile
      abort 0 true
    fi
  fi
fi

LC_LDFLAGS="-static"

# For debugging
# Remember to export UNW_DEBUG_LEVEL=<level>
# where 1 < level < 16 (usually values up to 5 are enough)
#LC_CFLAGS="$LC_FLAGS -DDEBUG"

# Prepare toolchain
case "$ARCH" in
  arm)
    TOOLCHAIN=arm-linux-androideabi
    TOOLCHAIN_S=arm-linux-androideabi-4.9
    ;;
  arm64)
    TOOLCHAIN=aarch64-linux-android
    TOOLCHAIN_S=aarch64-linux-android-4.9
    ;;
  x86)
    TOOLCHAIN=i686-linux-android
    TOOLCHAIN_S=x86-4.9
    ;;
  x86_64)
    TOOLCHAIN=x86_64-linux-android
    TOOLCHAIN_S=x86_64-4.9
    ;;
esac

# Apply patches required for Android
# TODO: Automate global patching when all archs have been tested

# Ptrace patches due to Android incompatibilities
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


SYSROOT="$NDK/platforms/$ANDROID_API/arch-$ARCH"
export CC="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-gcc"
export CXX="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-g++"
export PATH="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin":$PATH

if [ ! -x "$CC" ]; then
  echo "[-] gcc doesn't exist: $CC"
  abort 1
elif [ ! -x "$CXX" ]; then
  echo "[-] g++ doesn't exist: $CXX"
  abort 1
fi

export CC="$CC --sysroot=$SYSROOT -isystem $NDK/sysroot/usr/include/$TOOLCHAIN -isystem $NDK/sysroot/usr/include/ -D__ANDROID_API__=$ANDROID_API_V"
export CXX="$CXX --sysroot=$SYSROOT -isystem $NDK/sysroot/usr/include/$TOOLCHAIN -isystem $NDK/sysroot/usr/include/ -D__ANDROID_API__=$ANDROID_API_V"

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

# Fix stuff that configure failed to detect
# TODO: Investigate for more elegant patches
if [ "$ARCH" == "arm64" ]; then
  sed -i -e 's/#define HAVE_DECL_PTRACE_POKEUSER 1/#define HAVE_DECL_PTRACE_POKEUSER 0/g' include/config.h
  echo "#define HAVE_DECL_PT_GETREGSET 1" >> include/config.h
fi

make -j"$JOBS" CFLAGS="$LC_CFLAGS" LDFLAGS="$LC_LDFLAGS"
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    cd - &>/dev/null
    abort 1
fi

echo "[*] '$ARCH' libunwind available at '$LIBUNWIND_DIR/$ARCH'"
cp src/.libs/*.a "$ARCH"
echo "$ANDROID_API" > "$ARCH/android_api.txt"

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
