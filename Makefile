#   honggfuzz - Makefile
#   -----------------------------------------
#
#   Author: Robert Swiecki <swiecki@google.com>
#
#   Copyright 2010-2015 by Google Inc. All Rights Reserved.
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
#
#   NOTE: xcrun is within xcode...xcode is required on OSX.
#

# Common for all architectures
CC ?= gcc
LD = $(CC)
BIN := honggfuzz
HFUZZ_CC_BIN := hfuzz_cc/hfuzz-cc
HFUZZ_CC_SRCS := hfuzz_cc/hfuzz-cc.c
COMMON_CFLAGS := -D_GNU_SOURCE -Wall -Werror -Wno-format-truncation -I.
COMMON_LDFLAGS := -lm libhfcommon/libhfcommon.a
COMMON_SRCS := $(sort $(wildcard *.c))
CFLAGS ?= -O3 -mtune=native
LDFLAGS ?=
LIBS_CFLAGS ?= -fPIC -fno-stack-protector
GREP_COLOR ?=

OS ?= $(shell uname -s)
MARCH ?= $(shell uname -m)
KERNEL ?= $(shell uname -r)

ifeq ($(OS)$(findstring Microsoft,$(KERNEL)),Linux) # matches Linux but excludes WSL (Windows Subsystem for Linux)
    ARCH := LINUX

    ARCH_CFLAGS := -std=c11 -I/usr/local/include \
                   -Wextra -Wno-override-init \
                   -funroll-loops \
                   -D_FILE_OFFSET_BITS=64
    ARCH_LDFLAGS := -L/usr/local/include \
                    -pthread -lunwind-ptrace -lunwind-generic -lbfd -lopcodes -lrt -ldl
    ARCH_SRCS := $(sort $(wildcard linux/*.c))
    LIBS_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0

    ifeq ("$(wildcard /usr/include/bfd.h)","")
        WARN_LIBRARY += binutils-devel
    endif
    ifeq ("$(wildcard /usr/include/libunwind-ptrace.h)","")
        WARN_LIBRARY += libunwind-devel/libunwind8-devel
    endif
    ifeq ("$(wildcard /usr/local/include/intel-pt.h)","/usr/local/include/intel-pt.h")
        ARCH_CFLAGS += -D_HF_LINUX_INTEL_PT_LIB
        ARCH_CFLAGS += -I/usr/local/include
        ARCH_LDFLAGS += -L/usr/local/lib -lipt -Wl,--rpath=/usr/local/lib
    endif
    ifeq ("$(wildcard /usr/include/intel-pt.h)","/usr/include/intel-pt.h")
        ARCH_CFLAGS += -D_HF_LINUX_INTEL_PT_LIB
        ARCH_LDFLAGS += -lipt
    endif
    ifdef WARN_LIBRARY
        $(info --------------------------------------------------------)
        $(info Libraries which are most likely missing on your OS.     )
        $(info This can result in linking/compilation errors.          )
        $(info > $(WARN_LIBRARY))
        $(info --------------------------------------------------------)
    endif
    # OS Linux
else ifeq ($(OS),Darwin)
    ARCH := DARWIN

    # MacOS-X grep seem to use colors unconditionally
    GREP_COLOR = --color=never

    # Figure out which crash reporter to use.
    CRASHWRANGLER := third_party/mac
    OS_VERSION := $(shell sw_vers -productVersion)
    ifneq (,$(findstring 10.14,$(OS_VERSION)))
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
    else ifneq (,$(findstring 10.13,$(OS_VERSION)))
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
    else ifneq (,$(findstring 10.12,$(OS_VERSION)))
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
    else ifneq (,$(findstring 10.11,$(OS_VERSION)))
        # El Capitan didn't break compatibility
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Yosemite.o
    else ifneq (,$(findstring 10.10,$(OS_VERSION)))
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Yosemite.o
    else ifneq (,$(findstring 10.9,$(OS_VERSION)))
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Mavericks.o
    else ifneq (,$(findstring 10.8,$(OS_VERSION)))
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Mountain_Lion.o
    else
        $(error Unsupported MAC OS X version)
    endif

    # Figure out which XCode SDK to use.
    OSX_SDK_VERSION := $(shell xcrun --show-sdk-version)
    SDK_NAME_V := macosx$(OSX_SDK_VERSION)
    SDK_V := $(shell xcrun --sdk $(SDK_NAME) --show-sdk-path 2>/dev/null)
    SDK_NAME := macosx
    SDK := $(shell xcrun --sdk $(SDK_NAME) --show-sdk-path 2>/dev/null)

    CC := $(shell xcrun --sdk $(SDK_NAME) --find cc)
    LD := $(shell xcrun --sdk $(SDK_NAME) --find cc)
    ARCH_CFLAGS := -arch x86_64 -std=c99 -isysroot $(SDK) \
                   -x objective-c -pedantic -fblocks \
                   -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
                   -Wreturn-type -Wpointer-arith -Wno-gnu-case-range -Wno-gnu-designator \
                   -Wno-deprecated-declarations -Wno-unknown-pragmas -Wno-attributes \
                   -Wno-embedded-directive
    ARCH_LDFLAGS := -F/System/Library/PrivateFrameworks -framework CoreSymbolication -framework IOKit \
                    -F$(SDK_V)/System/Library/Frameworks -F$(SDK_V)/System/Library/PrivateFrameworks \
                    -F$(SDK)/System/Library/Frameworks \
                    -framework Foundation -framework ApplicationServices -framework Symbolication \
                    -framework CoreServices -framework CrashReporterSupport -framework CoreFoundation \
                    -framework CommerceKit $(CRASH_REPORT)

    XCODE_VER := $(shell xcodebuild -version | grep $(GREP_COLOR) "^Xcode" | cut -d " " -f2)
    ifeq "8.3" "$(word 1, $(sort 8.3 $(XCODE_VER)))"
      ARCH_LDFLAGS += -F/Applications/Xcode.app/Contents/SharedFrameworks \
                      -framework CoreSymbolicationDT \
                      -Wl,-rpath,/Applications/Xcode.app/Contents/SharedFrameworks
    endif

    MIG_RET := $(shell mig -header mac/mach_exc.h -user mac/mach_excUser.c -sheader mac/mach_excServer.h \
                 -server mac/mach_excServer.c $(SDK)/usr/include/mach/mach_exc.defs &>/dev/null; echo $$?)
    ifeq ($(MIG_RET),1)
        $(error mig failed to generate RPC code)
    endif
    ARCH_SRCS := $(sort $(wildcard mac/*.c))
    # OS Darwin
else ifeq ($(OS),NetBSD)
    ARCH := NETBSD

    ARCH_SRCS := $(sort $(wildcard netbsd/*.c))
    ARCH_CFLAGS := -std=c11 -I/usr/local/include -I/usr/pkg/include \
                   -Wextra -Wno-override-init \
                   -funroll-loops -D_KERNTYPES
    ARCH_LDFLAGS := -L/usr/local/lib -L/usr/pkg/lib \
                    -pthread -lcapstone -lrt \
                    -Wl,--rpath=/usr/pkg/lib

    # OS NetBSD
else
    ARCH := POSIX

    ARCH_SRCS := $(sort $(wildcard posix/*.c))
    ARCH_CFLAGS := -std=c11 -I/usr/local/include \
                   -Wextra -Wno-initializer-overrides -Wno-override-init \
                   -Wno-unknown-warning-option -Wno-unknown-pragmas \
                   -funroll-loops
    ARCH_LDFLAGS := -pthread -L/usr/local/lib
    # OS Posix
endif

CFLAGS_BLOCKS =
COMPILER = $(shell $(CC) -v 2>&1 | \
  grep $(GREP_COLOR) -oE '((gcc|clang) version|LLVM version.*clang)' | \
  grep $(GREP_COLOR) -oE '(clang|gcc)' | head -n1)
ifeq ($(COMPILER),clang)
  ARCH_CFLAGS += -Wno-initializer-overrides -Wno-unknown-warning-option
  ARCH_CFLAGS += -Wno-gnu-empty-initializer -Wno-format-pedantic
  ARCH_CFLAGS += -Wno-gnu-statement-expression
  CFLAGS_BLOCKS = -fblocks

  ifneq ($(OS),Darwin)
    ARCH_LDFLAGS += -lBlocksRuntime
  endif
endif

SRCS := $(COMMON_SRCS) $(ARCH_SRCS)
OBJS := $(SRCS:.c=.o)

LHFUZZ_SRCS := $(sort $(wildcard libhfuzz/*.c))
LHFUZZ_OBJS := $(LHFUZZ_SRCS:.c=.o)
LHFUZZ_ARCH := libhfuzz/libhfuzz.a
HFUZZ_INC ?= $(shell pwd)

LCOMMON_SRCS := $(sort $(wildcard libhfcommon/*.c))
LCOMMON_OBJS := $(LCOMMON_SRCS:.c=.o)
LCOMMON_ARCH := libhfcommon/libhfcommon.a

LNETDRIVER_SRCS := $(sort $(wildcard libhfnetdriver/*.c))
LNETDRIVER_OBJS := $(LNETDRIVER_SRCS:.c=.o)
LNETDRIVER_ARCH := libhfnetdriver/libhfnetdriver.a

# Respect external user defines
CFLAGS += $(COMMON_CFLAGS) $(ARCH_CFLAGS) -D_HF_ARCH_${ARCH}
LDFLAGS += $(COMMON_LDFLAGS) $(ARCH_LDFLAGS)

ifeq ($(DEBUG),true)
    CFLAGS += -g -ggdb
    LDFLAGS += -g -ggdb
endif

# Control Android builds
ANDROID_API           ?= android-26
ANDROID_DEBUG_ENABLED ?= false
ANDROID_CLANG         ?= true
ANDROID_APP_ABI       ?= armeabi-v7a
ANDROID_SKIP_CLEAN    ?= false
NDK_BUILD_ARGS :=

ifeq ($(ANDROID_DEBUG_ENABLED),true)
  NDK_BUILD_ARGS += V=1 NDK_DEBUG=1 APP_OPTIM=debug
endif

# By default ndk-build cleans all project files to ensure that no semi-completed
# builds reach the app package. The following flag disables this check. It's mainly
# purposed to be used with android-all rule where we want recursive invocations
# to keep previous targets' binaries.
ifeq ($(ANDROID_SKIP_CLEAN),true)
  NDK_BUILD_ARGS += NDK_APP.local.cleaned_binaries=true
endif

ifeq ($(ANDROID_CLANG),true)
  ANDROID_NDK_TOOLCHAIN_VER := clang
  # clang works only against APIs >= 23
  ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),armeabi armeabi-v7a))
    ANDROID_NDK_TOOLCHAIN ?= arm-linux-androideabi-clang
    ANDROID_ARCH_CPU := arm
  else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),x86))
    ANDROID_NDK_TOOLCHAIN ?= x86-clang
    ANDROID_ARCH_CPU := x86
  else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),arm64-v8a))
    ANDROID_NDK_TOOLCHAIN ?= aarch64-linux-android-clang
    ANDROID_ARCH_CPU := arm64
  else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),x86_64))
    ANDROID_NDK_TOOLCHAIN ?= x86_64-clang
    ANDROID_ARCH_CPU := x86_64
  else
    $(error Unsuported / Unknown APP_API '$(ANDROID_APP_ABI)')
  endif
else
  ANDROID_NDK_TOOLCHAIN_VER := 4.9
  ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),armeabi armeabi-v7a))
    ANDROID_NDK_TOOLCHAIN ?= arm-linux-androideabi-4.9
    ANDROID_ARCH_CPU := arm
  else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),x86))
    ANDROID_NDK_TOOLCHAIN ?= x86-4.9
    ANDROID_ARCH_CPU := x86
  else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),arm64-v8a))
    ANDROID_NDK_TOOLCHAIN ?= aarch64-linux-android-4.9
    ANDROID_ARCH_CPU := arm64
  else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),x86_64))
    ANDROID_NDK_TOOLCHAIN ?= x86_64-4.9
    ANDROID_ARCH_CPU := x86_64
  else
    $(error Unsuported / Unknown APP_API '$(ANDROID_APP_ABI)')
  endif
endif

SUBDIR_ROOTS := linux mac netbsd posix libhfuzz libhfcommon libhfnetdriver
DIRS := . $(shell find $(SUBDIR_ROOTS) -type d)
CLEAN_PATTERNS := *.o *~ core *.a *.dSYM *.la *.so *.dylib
SUBDIR_GARBAGE := $(foreach DIR,$(DIRS),$(addprefix $(DIR)/,$(CLEAN_PATTERNS)))
MAC_GARGBAGE := $(wildcard mac/mach_exc*)
ANDROID_GARBAGE := obj libs

CLEAN_TARGETS := core Makefile.bak \
  $(OBJS) $(BIN) $(HFUZZ_CC_BIN) \
  $(LHFUZZ_ARCH) $(LHFUZZ_OBJS) \
  $(LCOMMON_ARCH) $(LCOMMON_OBJS) \
  $(LNETDRIVER_ARCH) $(LNETDRIVER_OBJS) \
  $(MAC_GARGBAGE) $(ANDROID_GARBAGE) $(SUBDIR_GARBAGE)

all: $(BIN) $(HFUZZ_CC_BIN) $(LHFUZZ_ARCH) $(LCOMMON_ARCH) $(LNETDRIVER_ARCH)

%.o: %.c
	$(CC) -c $(CFLAGS) $(CFLAGS_BLOCKS) -o $@ $<

%.so: %.c
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $<

%.dylib: %.c
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $<

$(BIN): $(OBJS) $(LCOMMON_ARCH)
	$(LD) -o $(BIN) $(OBJS) $(LDFLAGS)

$(HFUZZ_CC_BIN): $(LCOMMON_ARCH) $(LHFUZZ_ARCH) $(LNETDRIVER_ARCH) $(HFUZZ_CC_SRCS)
	$(LD) -o $@ $(HFUZZ_CC_SRCS) $(LDFLAGS) $(CFLAGS) $(CFLAGS_BLOCKS) -D_HFUZZ_INC_PATH=$(HFUZZ_INC)

$(LCOMMON_OBJS): $(LCOMMON_SRCS)
	$(CC) -c $(CFLAGS) $(LIBS_CFLAGS) -o $@ $(@:.o=.c)

$(LCOMMON_ARCH): $(LCOMMON_OBJS)
	$(AR) rcs $(LCOMMON_ARCH) $(LCOMMON_OBJS)

$(LHFUZZ_OBJS): $(LHFUZZ_SRCS)
	$(CC) -c $(CFLAGS) $(LIBS_CFLAGS) -o $@ $(@:.o=.c)

$(LHFUZZ_ARCH): $(LHFUZZ_OBJS) $(LCOMMON_OBJS)
	$(AR) rcs $(LHFUZZ_ARCH) $(LHFUZZ_OBJS) $(LCOMMON_OBJS)

$(LNETDRIVER_OBJS): $(LNETDRIVER_SRCS)
	$(CC) -c $(CFLAGS) $(LIBS_CFLAGS) -o $@ $(@:.o=.c)

$(LNETDRIVER_ARCH): $(LNETDRIVER_OBJS) $(LCOMMON_OBJS)
	$(AR) rcs $(LNETDRIVER_ARCH) $(LNETDRIVER_OBJS) $(LCOMMON_OBJS)

.PHONY: clean
clean:
	$(RM) -r $(CLEAN_TARGETS)

.PHONY: indent
indent:
	clang-format -style="{BasedOnStyle: Google, IndentWidth: 4, ColumnLimit: 100, AlignAfterOpenBracket: DontAlign, AllowShortFunctionsOnASingleLine: false, AlwaysBreakBeforeMultilineStrings: false}" -i -sort-includes  *.c *.h */*.c */*.h

.PHONY: depend
depend: all
	makedepend -Y. -Y* -- *.c */*.c

.PHONY: android
android:
	$(info ***************************************************************)
	$(info *                 Use Android NDK 15 or newer                 *)
	$(info ***************************************************************)
	@ANDROID_API=$(ANDROID_API) third_party/android/scripts/compile-libunwind.sh \
	third_party/android/libunwind $(ANDROID_ARCH_CPU)

	@ANDROID_API=$(ANDROID_API) third_party/android/scripts/compile-capstone.sh \
	third_party/android/capstone $(ANDROID_ARCH_CPU)

  ifeq ($(ANDROID_CLANG),true)
		@ANDROID_API=$(ANDROID_API) third_party/android/scripts/compile-libBlocksRuntime.sh \
		third_party/android/libBlocksRuntime $(ANDROID_ARCH_CPU)
  endif

	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android/Android.mk \
    APP_PLATFORM=$(ANDROID_API) APP_ABI=$(ANDROID_APP_ABI) \
    NDK_TOOLCHAIN=$(ANDROID_NDK_TOOLCHAIN) NDK_TOOLCHAIN_VERSION=$(ANDROID_NDK_TOOLCHAIN_VER) \
    $(NDK_BUILD_ARGS) APP_MODULES='honggfuzz hfuzz'

# Loop all ABIs and pass-through flags since visibility is lost due to sub-process
.PHONY: android-all
android-all:
	@echo "Cleaning workspace:"
	$(MAKE) clean
	@echo ""

	@for abi in armeabi armeabi-v7a arm64-v8a x86 x86_64; do \
	  ANDROID_APP_ABI=$$abi ANDROID_SKIP_CLEAN=true ANDROID_CLANG=$(ANDROID_CLANG) \
	  ANDROID_API=$(ANDROID_API) ANDROID_DEBUG_ENABLED=$(ANDROID_DEBUG_ENABLED) \
	  $(MAKE) android || { \
	    echo "Recursive make failed"; exit 1; }; \
	  echo ""; \
	done

.PHONY: android-clean-deps
android-clean-deps:
	@for cpu in arm arm64 x86 x86_64; do \
	  make -C "third_party/android/capstone" clean; \
	  rm -rf "third_party/android/capstone/$$cpu"; \
	  make -C "third_party/android/libunwind" clean; \
	  rm -rf "third_party/android/libunwind/$$cpu"; \
	  ndk-build -C "third_party/android/libBlocksRuntime" \
	    NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk clean; \
	  rm -rf "third_party/android/libBlocksRuntime/$$cpu"; \
	done

PREFIX		?= /usr/local
BIN_PATH	=$(PREFIX)/bin

install: all
	mkdir -p -m 755 $${DESTDIR}$(BIN_PATH)
	install -m 755 honggfuzz $${DESTDIR}$(BIN_PATH)
	install -m 755 hfuzz_cc/hfuzz-cc $${DESTDIR}$(BIN_PATH)
	install -m 755 hfuzz_cc/hfuzz-clang $${DESTDIR}$(BIN_PATH)
	install -m 755 hfuzz_cc/hfuzz-clang++ $${DESTDIR}$(BIN_PATH)
	install -m 755 hfuzz_cc/hfuzz-gcc $${DESTDIR}$(BIN_PATH)
	install -m 755 hfuzz_cc/hfuzz-g++ $${DESTDIR}$(BIN_PATH)

# DO NOT DELETE

cmdline.o: cmdline.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
cmdline.o: display.h libhfcommon/files.h libhfcommon/common.h
cmdline.o: libhfcommon/log.h
display.o: display.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
display.o: libhfcommon/log.h
fuzz.o: fuzz.h honggfuzz.h libhfcommon/util.h arch.h input.h
fuzz.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
fuzz.o: libhfcommon/log.h mangle.h report.h sanitizers.h socketfuzzer.h
fuzz.o: subproc.h
honggfuzz.o: cmdline.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
honggfuzz.o: display.h fuzz.h input.h libhfcommon/files.h
honggfuzz.o: libhfcommon/common.h libhfcommon/log.h socketfuzzer.h subproc.h
input.o: input.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
input.o: libhfcommon/files.h libhfcommon/common.h mangle.h subproc.h
input.o: libhfcommon/log.h
mangle.o: mangle.h honggfuzz.h libhfcommon/util.h input.h
mangle.o: libhfcommon/common.h libhfcommon/log.h
report.o: report.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
report.o: libhfcommon/log.h
sanitizers.o: sanitizers.h honggfuzz.h libhfcommon/util.h cmdline.h
sanitizers.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
sanitizers.o: libhfcommon/log.h
socketfuzzer.o: socketfuzzer.h honggfuzz.h libhfcommon/util.h
socketfuzzer.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
socketfuzzer.o: libhfcommon/log.h libhfcommon/ns.h
subproc.o: subproc.h honggfuzz.h libhfcommon/util.h arch.h fuzz.h
subproc.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
subproc.o: libhfcommon/log.h
hfuzz_cc/hfuzz-cc.o: honggfuzz.h libhfcommon/util.h libhfcommon/common.h
hfuzz_cc/hfuzz-cc.o: libhfcommon/files.h libhfcommon/common.h
hfuzz_cc/hfuzz-cc.o: libhfcommon/log.h
libhfcommon/files.o: libhfcommon/files.h libhfcommon/common.h
libhfcommon/files.o: libhfcommon/common.h libhfcommon/log.h
libhfcommon/files.o: libhfcommon/util.h
libhfcommon/log.o: libhfcommon/log.h libhfcommon/common.h libhfcommon/util.h
libhfcommon/ns.o: libhfcommon/ns.h libhfcommon/common.h libhfcommon/files.h
libhfcommon/ns.o: libhfcommon/common.h libhfcommon/log.h
libhfcommon/util.o: libhfcommon/util.h libhfcommon/common.h
libhfcommon/util.o: libhfcommon/files.h libhfcommon/common.h
libhfcommon/util.o: libhfcommon/log.h
libhfnetdriver/netdriver.o: libhfnetdriver/netdriver.h honggfuzz.h
libhfnetdriver/netdriver.o: libhfcommon/util.h libhfcommon/common.h
libhfnetdriver/netdriver.o: libhfcommon/files.h libhfcommon/common.h
libhfnetdriver/netdriver.o: libhfcommon/log.h libhfcommon/ns.h
libhfuzz/fetch.o: libhfuzz/fetch.h honggfuzz.h libhfcommon/util.h
libhfuzz/fetch.o: libhfcommon/common.h libhfcommon/files.h
libhfuzz/fetch.o: libhfcommon/common.h libhfcommon/log.h
libhfuzz/instrument.o: libhfuzz/instrument.h honggfuzz.h libhfcommon/util.h
libhfuzz/instrument.o: libhfcommon/common.h libhfcommon/log.h
libhfuzz/linux.o: libhfcommon/common.h libhfcommon/files.h
libhfuzz/linux.o: libhfcommon/common.h libhfcommon/log.h libhfcommon/ns.h
libhfuzz/linux.o: libhfuzz/libhfuzz.h
libhfuzz/memorycmp.o: libhfcommon/common.h libhfuzz/instrument.h
libhfuzz/persistent.o: honggfuzz.h libhfcommon/util.h libhfcommon/common.h
libhfuzz/persistent.o: libhfcommon/files.h libhfcommon/common.h
libhfuzz/persistent.o: libhfcommon/log.h libhfuzz/fetch.h
libhfuzz/persistent.o: libhfuzz/instrument.h libhfuzz/libhfuzz.h
linux/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h
linux/arch.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
linux/arch.o: libhfcommon/log.h libhfcommon/ns.h linux/perf.h linux/trace.h
linux/arch.o: sanitizers.h subproc.h
linux/bfd.o: linux/bfd.h linux/unwind.h honggfuzz.h libhfcommon/util.h
linux/bfd.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
linux/bfd.o: libhfcommon/log.h
linux/perf.o: linux/perf.h honggfuzz.h libhfcommon/util.h
linux/perf.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
linux/perf.o: libhfcommon/log.h linux/pt.h
linux/pt.o: linux/pt.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
linux/pt.o: libhfcommon/log.h
linux/trace.o: linux/trace.h honggfuzz.h libhfcommon/util.h
linux/trace.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
linux/trace.o: libhfcommon/log.h linux/bfd.h linux/unwind.h sanitizers.h
linux/trace.o: socketfuzzer.h subproc.h
linux/unwind.o: linux/unwind.h honggfuzz.h libhfcommon/util.h
linux/unwind.o: libhfcommon/common.h libhfcommon/log.h
mac/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h libhfcommon/common.h
mac/arch.o: libhfcommon/files.h libhfcommon/common.h libhfcommon/log.h
mac/arch.o: subproc.h
netbsd/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h
netbsd/arch.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
netbsd/arch.o: libhfcommon/log.h libhfcommon/ns.h netbsd/trace.h subproc.h
netbsd/trace.o: netbsd/trace.h honggfuzz.h libhfcommon/util.h
netbsd/trace.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
netbsd/trace.o: libhfcommon/log.h netbsd/unwind.h socketfuzzer.h subproc.h
netbsd/unwind.o: netbsd/unwind.h honggfuzz.h libhfcommon/util.h
netbsd/unwind.o: libhfcommon/common.h libhfcommon/log.h
posix/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h
posix/arch.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
posix/arch.o: libhfcommon/log.h subproc.h
