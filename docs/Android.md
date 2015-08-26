# Android Platform #

Honggfuzz (as of version 0.6) supports Android OS (NDK cross-compilation) using both ptrace() API and POSIX signals interface. When ptrace() API is enabled, honggfuzz's engine prevents monitored signals from reaching the debugger (no logcat backtraces & tombstones), since the fuzzer's runtime analysis was affected.

## Requirements ##

  * [Android NDK](https://developer.android.com/ndk/index.html): User has to manually install NDK and set environment PATH
  * [libunwind](http://www.nongnu.org/libunwind/download.html): In case of first build an upstream git fork is executed followed by required patches
  * [capstone](http://www.capstone-engine.org/download.html): In case of first build an upstream git fork is executed
  
| **Dependency** | **Last Tested Version** |
|:-------|:-----------|
| **Android NDK** | r10e with Android API 21 (Lollipop) |
| **libunwind** | upstream master commit [396b6c7] |
| **capstone** | upstream master commit[0793345] | 

## Compatibility list ##

It has been tested under the following CPU architectures:

| **ABI** | **Status** |
|:-------|:-----------|
| **armeabi** | ptrace() API & POSIX signal interface |
| **armeabi-v7a** | ptrace() API & POSIX signal interface |
| **arm64-v8a** | ptrace() API & POSIX signal interface `*`|
| **x86** | ptrace() API & POSIX signal interface |
| **x86_64** | POSIX signal interface (ptrace API & capstone work, although libunwind does not) |

_`*`) libunwind fails to extract frames if fuzzing target is 32bit. Prefer a 32bit build for such targets._

## Cross-Compiling ##
## Dependencies ##

Helper bash scripts are present to automate capstone & libunwind builds for target CPU in case of ptrace() API interface being used. From project root directory execute the following to compile the two libraries for the matching architecture:

  * third_party/android/scripts/compile-libunwind.sh third_party/android/libunwind \<arch\>
  * third_party/android/scripts/compile-capstone.sh third_party/android/capstone \<arch\>
  
Were \<arch\>:

  * "arm": For armeabi & armeabi-v7a
  * "arm64": For arm64-v8a*
  * "x86"
  * "x86_64"

For example in case of arm:

```
$ third_party/android/scripts/compile-libunwind.sh third_party/android/libunwind arm
[!] libunwind not found. Fetching a fresh copy
Cloning into 'third_party/android/libunwind'...
remote: Counting objects: 14860, done.
remote: Compressing objects: 100% (3855/3855), done.
remote: Total 14860 (delta 10932), reused 14860 (delta 10932)
Receiving objects: 100% (14860/14860), 3.46 MiB | 856.00 KiB/s, done.
Resolving deltas: 100% (10932/10932), done.
Checking connectivity... done.
patching file src/ptrace/_UPT_access_reg.c
patching file src/ptrace/_UPT_access_fpreg.c
...
[*] 'arm' libunwind  available at 'third_party/android/libunwind/arm'
```
```
$ [!] capstone not found. Fetching a fresh copy
Cloning into 'third_party/android/capstone'...
remote: Counting objects: 16981, done.
remote: Compressing objects: 100% (39/39), done.
remote: Total 16981 (delta 18), reused 0 (delta 0), pack-reused 16942
Receiving objects: 100% (16981/16981), 26.18 MiB | 1.24 MiB/s, done.
Resolving deltas: 100% (12223/12223), done.
Checking connectivity... done.
...
  GEN     capstone.pc
[*] 'arm' libcapstone  available at 'third_party/android/capstone/arm'
```

## Honggfuzz ##

| **Flags** | **Allowed Values** | 
|:-------|:-----------|
| **ANDROID_DEBUG_ENABLED** | true, false (default: false) |
| **ANDROID_APP_ABI** | armeabi, armeabi-v7a, arm64-v8a, x86, x86_64 (default: armeabi-v7a) |
| **ANDROID_WITH_PTRACE** | true, false (default: true) `1`|
| **ANDROID_API** | android-21, android-22, ... (default: android-21) `2` |

_`1`) in case of false, POSIX signals interface is used instead of PTRACE API_

_`2`) Due to getdelim() only APIs >= 21 are supported_

After compiling the dependencies (ptrace() API only), from project's root directory execute make with android PHONY to cross-compile.

For example in case of ptrace() API for armeabi-v7a:

```
$ make -B android ANDROID_APP_ABI=armeabi-v7a
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android/Android.mk \
			APP_PLATFORM=android-21 APP_ABI=armeabi-v7a 
********************************************************************
Android PTRACE build: Will prevent debuggerd from processing crashes
********************************************************************
make[1]: Entering directory `/Users/anestisb/Tools/Fuzzers/honggfuzz'
[armeabi-v7a] Compile thumb  : honggfuzz <= honggfuzz.c
[armeabi-v7a] Compile thumb  : honggfuzz <= log.c
[armeabi-v7a] Compile thumb  : honggfuzz <= files.c
[armeabi-v7a] Compile thumb  : honggfuzz <= fuzz.c
[armeabi-v7a] Compile thumb  : honggfuzz <= report.c
[armeabi-v7a] Compile thumb  : honggfuzz <= mangle.c
[armeabi-v7a] Compile thumb  : honggfuzz <= util.c
[armeabi-v7a] Compile thumb  : honggfuzz <= arch.c
[armeabi-v7a] Compile thumb  : honggfuzz <= ptrace_utils.c
[armeabi-v7a] Compile thumb  : honggfuzz <= perf.c
[armeabi-v7a] Compile thumb  : honggfuzz <= unwind.c
[armeabi-v7a] Executable     : honggfuzz
[armeabi-v7a] Install        : honggfuzz => libs/armeabi-v7a/honggfuzz
make[1]: Leaving directory `/Users/anestisb/Tools/Fuzzers/honggfuzz'
```
