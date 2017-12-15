# Android Platform #

Honggfuzz (as of version 0.6) supports Android OS (NDK cross-compilation) using
both ptrace() API and POSIX signals interface. When ptrace() API is enabled,
honggfuzz's engine prevents monitored signals from reaching the debugger (no
logcat backtraces & tombstones), since the fuzzer's runtime analysis is
affected.

## Requirements ##

* [Android NDK](https://developer.android.com/ndk/index.html): User has to
manually install NDK and set environment PATH
* [libunwind](http://www.nongnu.org/libunwind/download.html): In case of first
build an upstream git fork is executed followed by required patches
* [capstone](http://www.capstone-engine.org/download.html): In case of first
build an upstream git fork is executed

| **Dependency** | **Last Tested Version** |
|:-------|:-----------|
| **Android NDK** | r16 with Android API 24 (Nougat 7.0) |
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

_`*`) libunwind fails to extract frames if fuzzing target is 32bit. Prefer a32bit build for such targets._


## Cross-Compiling ##
## Dependencies ##

A series of helper bash scripts have been created under the
`third_party/android/scripts` directory to automate the dependencies
configuration & build process. The scripts are automatically invoked from the
makefile, based on the selected target CPU. Normally you'll not need to manually
execute or modify them.

## Building
### All CPUs ###
For convenience the master makefile defines an `android-all` target that
automatically builds honggfuzz (and its dependencies) for all the supported
Android CPUs.

From the root directory execute the following. Build output is available under
the `libs` directory.

```
$ make android-all
...
$ tree libs/
libs/
├── arm64-v8a
│   ├── android_api.txt
│   ├── honggfuzz
│   ├── libhfuzz.a
│   └── ndk_toolchain.txt
├── armeabi
│   ├── android_api.txt
│   ├── honggfuzz
│   ├── libhfuzz.a
│   └── ndk_toolchain.txt
├── armeabi-v7a
│   ├── android_api.txt
│   ├── honggfuzz
│   ├── libhfuzz.a
│   └── ndk_toolchain.txt
├── x86
│   ├── android_api.txt
│   ├── honggfuzz
│   ├── libhfuzz.a
│   └── ndk_toolchain.txt
└── x86_64
    ├── android_api.txt
    ├── honggfuzz
    ├── libhfuzz.a
    └── ndk_toolchain.txt

5 directories, 20 files
```


### Specific CPU ###
To build for a specific CPU use the `android` target with one of the supported
ABI descriptions. Again the dependencies are automatically build.

```
$ make android ANDROID_APP_ABI=<arch>
...
```

Were `<arch>` can be:

* armeabi
* armeabi-v7a (**default**)
* arm64-v8a
* x86
* x86_64


## Android specific flags ##

| **Flag** | **Options** | **Description** |
|:----------|:------------|:----------------|
| **ANDROID_DEBUG_ENABLED** | true, false (default: false) | Enable Android debug builds |
| **ANDROID_APP_ABI** | armeabi, armeabi-v7a, arm64-v8a, x86, x86_64 (default: armeabi-v7a) | Target CPU |
| **ANDROID_WITH_PTRACE** | true, false (default: true) `1`| Fuzzing engine backend architecture |
| **ANDROID_API** | android-21, android-22, ... (default: android-26) `2` | Target Android API |
| **ANDROID_CLANG** | true, false (default: true) | Android NDK compiler toolchain to use |

_`1`) If false, POSIX signals interface is used instead of PTRACE API_

_`2`) Due to bionic incompatibilities, only APIs >= 21 are supported_
