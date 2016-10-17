# Android Platform #

Honggfuzz (as of version 0.6) supports Android OS (NDK cross-compilation) using both ptrace() API and POSIX signals interface. When ptrace() API is enabled, honggfuzz's engine prevents monitored signals from reaching the debugger (no logcat backtraces & tombstones), since the fuzzer's runtime analysis was affected.

## Requirements ##

  * [Android NDK](https://developer.android.com/ndk/index.html): User has to manually install NDK and set environment PATH
  * [libunwind](http://www.nongnu.org/libunwind/download.html): In case of first build an upstream git fork is executed followed by required patches
  * [capstone](http://www.capstone-engine.org/download.html): In case of first build an upstream git fork is executed

| **Dependency** | **Last Tested Version** |
|:-------|:-----------|
| **Android NDK** | r13 with Android API 24 (Nougat 7.0) |
| **libunwind** | upstream master commit [bc8698f] |
| **capstone** | 3.0.4 stable version |

## Compatibility list ##

It has been tested under the following CPU architectures:

| **ABI** | **Status** |
|:-------|:-----------|
| **armeabi** | ptrace() API & POSIX signal interface |
| **armeabi-v7a** | ptrace() API & POSIX signal interface |
| **arm64-v8a** | ptrace() API & POSIX signal interface `*`|
| **x86** | ptrace() API & POSIX signal interface |
| **x86_64** | ptrace() API & POSIX signal interface |

_`*`) libunwind fails to extract frames if fuzzing target is 32bit. Prefer a 32bit build for such targets._

## Cross-Compiling ##
## Dependencies ##

Helper bash scripts are present to automate capstone & libunwind builds for target CPU in case of ptrace() API interface being used. From project root directory execute the following to compile the two libraries for the matching architecture:

  * `third_party/android/scripts/compile-libunwind.sh third_party/android/libunwind <arch>`
  * `third_party/android/scripts/compile-capstone.sh third_party/android/capstone <arch>`

Were `<arch>`:

  * "arm": For armeabi & armeabi-v7a
  * "arm64": For arm64-v8a*
  * "x86"
  * "x86_64"

For example in case of arm:

```
$ third_party/android/scripts/compile-libunwind.sh third_party/android/libunwind arm
Submodule path 'third_party/android/libunwind': checked out 'bc8698fd7ed13a629a8ec3cb2a89bd74f9d8b5c0'
patching file src/ptrace/_UPT_access_reg.c
patching file src/ptrace/_UPT_access_fpreg.c
glibtoolize: putting auxiliary files in AC_CONFIG_AUX_DIR, 'config'.
glibtoolize: copying file 'config/ltmain.sh'
...
[*] 'arm' libunwind available at 'third_party/android/libunwind/arm'
[*] Resetting locally applied patches
```
```
$ third_party/android/scripts/compile-capstone.sh third_party/android/capstone arm
Submodule path 'third_party/android/capstone': checked out 'e710e4fcf40302c25d7bdc28da93571a61f21f5d'
rm -f  ./cs.o ./utils.o ./SStream.o ./MCInstrDesc.o
...
  GEN     capstone.pc
[*] 'arm' libcapstone available at 'third_party/android/capstone/arm'
```

## Honggfuzz ##

| **Flag** | **Options** | **Description** |
|:----------|:------------|:----------------|
| **ANDROID_DEBUG_ENABLED** | true, false (default: false) | Enable Android debug builds |
| **ANDROID_APP_ABI** | armeabi, armeabi-v7a, arm64-v8a, x86, x86_64 (default: armeabi-v7a) | Target CPU |
| **ANDROID_WITH_PTRACE** | true, false (default: true) `1`| Fuzzing engine backend architecture |
| **ANDROID_API** | android-21, android-22, ... (default: android-24) `2` | Target Android API |
| **ANDROID_CLANG** | true, false (default: false) | Android NDK compiler toolchain to use |

_`1`) in case of false, POSIX signals interface is used instead of PTRACE API_

_`2`) Due to bionic incompatibilities, only APIs >= 21 are supported_

After compiling the dependencies (ptrace() API only), from project's root directory execute make with android PHONY to cross-compile.

For example in case of ptrace() API for armeabi-v7a:

```
$ make -B android ANDROID_APP_ABI=armeabi-v7a
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android/Android.mk \
                  APP_PLATFORM=android-24 APP_ABI=armeabi-v7a \
                  NDK_TOOLCHAIN=arm-linux-androideabi-4.9
********************************************************************
Android PTRACE build: Will prevent debuggerd from processing crashes
********************************************************************
[armeabi-v7a] Compile thumb  : honggfuzz <= honggfuzz.c
[armeabi-v7a] Compile thumb  : honggfuzz <= cmdline.c
[armeabi-v7a] Compile thumb  : honggfuzz <= display.c
[armeabi-v7a] Compile thumb  : honggfuzz <= log.c
[armeabi-v7a] Compile thumb  : honggfuzz <= files.c
[armeabi-v7a] Compile thumb  : honggfuzz <= fuzz.c
[armeabi-v7a] Compile thumb  : honggfuzz <= report.c
[armeabi-v7a] Compile thumb  : honggfuzz <= mangle.c
[armeabi-v7a] Compile thumb  : honggfuzz <= util.c
[armeabi-v7a] Compile thumb  : honggfuzz <= sancov.c
[armeabi-v7a] Compile thumb  : honggfuzz <= subproc.c
[armeabi-v7a] Compile thumb  : honggfuzz <= arch.c
[armeabi-v7a] Compile thumb  : honggfuzz <= ptrace_utils.c
[armeabi-v7a] Compile thumb  : honggfuzz <= perf.c
[armeabi-v7a] Compile thumb  : honggfuzz <= unwind.c
[armeabi-v7a] Compile thumb  : honggfuzz <= pt.c
[armeabi-v7a] Executable     : honggfuzz
[armeabi-v7a] Install        : honggfuzz => libs/armeabi-v7a/honggfuzz
```
