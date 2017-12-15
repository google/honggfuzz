#!/bin/bash
#
#   honggfuzz libBlocksRuntime build help script
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

if [ -z "$ANDROID_API" ]; then
  ANDROID_API="android-26"
fi
if ! echo "$ANDROID_API" | grep -qoE 'android-[0-9]{1,2}'; then
  echo "[-] Invalid ANDROID_API '$ANDROID_API'"
  exit 1
fi

if [ $# -ne 2 ]; then
  echo "[-] Invalid arguments"
  echo "[!] $0 <libBlocksRuntime_DIR> <ARCH>"
  echo "    ARCH: arm arm64 x86 x86_64"
  exit 1
fi

readonly BRT_DIR="$1"

case "$2" in
  arm|arm64|x86|x86_64)
    readonly ARCH=$2
    if [ ! -d $BRT_DIR/$ARCH ] ; then mkdir -p $BRT_DIR/$ARCH; fi
    ;;
  *)
    echo "[-] Invalid CPU architecture"
    exit 1
    ;;
esac

# Check if previous build exists and matches selected ANDROID_API level
# If API cache file not there always rebuild
if [ -f "$BRT_DIR/$ARCH/libblocksruntime.a" ]; then
  if [ -f "$BRT_DIR/$ARCH/android_api.txt" ]; then
    old_api=$(cat "$BRT_DIR/$ARCH/android_api.txt")
    if [[ "$old_api" == "$ANDROID_API" ]]; then
      # No need to recompile
      exit 0
    fi
  fi
fi

case "$ARCH" in
  arm)
    BRT_ARCH="armeabi-v7a"
    BRT_TOOLCHAIN="arm-linux-androideabi-clang"
    ;;
  arm64)
    BRT_ARCH="arm64-v8a"
    BRT_TOOLCHAIN="aarch64-linux-android-clang"
    ;;
  x86)
    BRT_ARCH="x86"
    BRT_TOOLCHAIN="x86-clang"
    ;;
  x86_64)
    BRT_ARCH="x86_64"
    BRT_TOOLCHAIN="x86_64-clang"
    ;;
esac

# Clean first
$NDK/ndk-build NDK_PROJECT_PATH=$BRT_DIR APP_BUILD_SCRIPT=$BRT_DIR/Android.mk \
  APP_PLATFORM=$ANDROID_API APP_ABI=$BRT_ARCH \
  NDK_TOOLCHAIN=$BRT_TOOLCHAIN clean

# Build
$NDK/ndk-build NDK_PROJECT_PATH=$BRT_DIR APP_BUILD_SCRIPT=$BRT_DIR/Android.mk \
  APP_PLATFORM=$ANDROID_API APP_ABI=$BRT_ARCH \
  NDK_TOOLCHAIN=$BRT_TOOLCHAIN
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed"
    exit 1
else
    echo "[*] '$ARCH' libBlocksRuntime available at '$BRT_DIR/$ARCH'"
fi

# Change workdir to simplify args
cd $BRT_DIR

cp obj/local/$BRT_ARCH/libblocksruntime.a "$ARCH/"
echo "$ANDROID_API" > "$ARCH/android_api.txt"

# Revert workdir to caller
cd - &>/dev/null
