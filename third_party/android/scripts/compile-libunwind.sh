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
  echo "[!] $0 <LIBUNWIND_DIR> <ARCH>"
  echo "    ARCH: arm arm64 x86 x86_64"
  exit 1
fi

readonly LIBUNWIND_DIR=$1

# Fetch if not already there
if [ ! -d $LIBUNWIND_DIR ]; then
    echo "[!] libunwind not found. Fetching a fresh copy"
    git clone git://git.sv.gnu.org/libunwind.git $LIBUNWIND_DIR
fi

case "$2" in
  arm|arm64|x86|x86_64)
    readonly ARCH=$2
    if [ ! -d $LIBUNWIND_DIR/$ARCH ] ; then mkdir -p $LIBUNWIND_DIR/$ARCH; fi
    ;;
  *)
    echo "[-] Invalid architecture"
    exit 1
    ;;
esac

LC_LDFLAGS="-static"

# For debugging
# Remember to export UNW_DEBUG_LEVEL=<level>
# where 1 < level < 16 (usually values up to 5 are enough)
#LC_CFLAGS="$LC_FLAGS -DDEBUG"

# Change workdir to simplify args
cd $LIBUNWIND_DIR

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
patch -N --dry-run --silent src/ptrace/_UPT_access_reg.c < ../patches/ptrace-libunwind_1.patch &>/dev/null
if [ $? -eq 0 ]; then
  patch src/ptrace/_UPT_access_reg.c < ../patches/ptrace-libunwind_1.patch
  if [ $? -ne 0 ]; then
    echo "[-] ptrace-libunwind_1 patch failed"
    exit 1
  fi
fi

patch -N --dry-run --silent src/ptrace/_UPT_access_fpreg.c < ../patches/ptrace-libunwind_2.patch &>/dev/null
if [ $? -eq 0 ]; then
  patch src/ptrace/_UPT_access_fpreg.c < ../patches/ptrace-libunwind_2.patch
  if [ $? -ne 0 ]; then
    echo "[-] ptrace-libunwind_2 patch failed"
    exit 1
  fi
fi

if [ "$ARCH" == "arm64" ]; then
  # Missing libc functionality
  patch -N --dry-run --silent include/libunwind-aarch64.h < ../patches/aarch64-libunwind_1.patch &>/dev/null
  if [ $? -eq 0 ]; then
    patch include/libunwind-aarch64.h < ../patches/aarch64-libunwind_1.patch
    if [ $? -ne 0 ]; then
      echo "[-] aarch64-libunwind_1 patch failed"
      exit 1
    fi
  fi
  # Frames ip bugs
  patch -N --dry-run --silent src/aarch64/Gstep.c < ../patches/aarch64-libunwind_2.patch &>/dev/null
  if [ $? -eq 0 ]; then
    patch src/aarch64/Gstep.c < ../patches/aarch64-libunwind_2.patch
    if [ $? -ne 0 ]; then
      echo "[-] aarch64-libunwind_2 patch failed"
      exit 1
    fi
  fi
fi

if [ "$ARCH" == "x86" ]; then
  # Missing syscalls
  patch -N --dry-run --silent src/x86/Gos-linux.c < ../patches/x86-libunwind.patch &>/dev/null
  if [ $? -eq 0 ]; then
    patch src/x86/Gos-linux.c < ../patches/x86-libunwind.patch
    if [ $? -ne 0 ]; then
      echo "[-] x86-libunwind patch failed"
      exit 1
    fi
  fi
fi

# Support both Linux & Darwin
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -m)

SYSROOT="$NDK/platforms/android-21/arch-$ARCH"
export CC="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-gcc --sysroot=$SYSROOT"
export CXX="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin/$TOOLCHAIN-g++ --sysroot=$SYSROOT"
export PATH="$NDK/toolchains/$TOOLCHAIN_S/prebuilt/$HOST_OS-$HOST_ARCH/bin":$PATH

if [ ! -f configure ]; then
  autoreconf -i
  if [ $? -ne 0 ]; then
    echo "[-] autoreconf failed"
    exit 1
  fi
  # Patch configure
  sed -i -e 's/-lgcc_s/-lgcc/g' configure
else
  make clean
fi

./configure --host=$TOOLCHAIN --disable-coredump
if [ $? -ne 0 ]; then
  echo "[-] configure failed"
  exit 1
fi

# Fix stuff that configure failed to detect
# TODO: Investigate for more elegant patches
if [ "$ARCH" == "arm64" ]; then
  sed -i -e 's/#define HAVE_DECL_PTRACE_POKEUSER 1/#define HAVE_DECL_PTRACE_POKEUSER 0/g' include/config.h
  echo "#define HAVE_DECL_PT_GETREGSET 1" >> include/config.h
fi

make CFLAGS="$LC_CFLAGS" LDFLAGS="$LC_LDFLAGS"
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    cd - &>/dev/null
    exit 1
else
    echo "[*] '$ARCH' libunwind  available at '$LIBUNWIND_DIR/$ARCH'"
    cp src/.libs/*.a $ARCH
    cd - &>/dev/null
fi
