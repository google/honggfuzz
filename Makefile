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

# --- Out-of-tree build support ---
# Set BUILD_DIR to build in a separate directory. When unset, builds in-tree
# as before. Example: make -f /path/to/honggfuzz/Makefile BUILD_DIR=/tmp/build
#
# SRCDIR: absolute path to the source tree (where this Makefile lives)
SRCDIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# BUILD_DIR: where build artifacts go. Defaults to SRCDIR (in-tree build).
BUILD_DIR ?=

# When BUILD_DIR is set, use it; otherwise everything is relative to SRCDIR
# (preserving original behaviour).
ifdef BUILD_DIR
  # Resolve to absolute path and strip trailing slash
  override BUILD_DIR := $(patsubst %/,%,$(abspath $(BUILD_DIR)))
  _OBJDIR = $(BUILD_DIR)
else
  _OBJDIR = $(SRCDIR)
endif

# Let make find sources in the source tree
VPATH := $(SRCDIR)

# Common for all architectures
CC ?= gcc
LD = $(CC)
BIN := $(_OBJDIR)/honggfuzz
HFUZZ_CC_BIN := $(_OBJDIR)/hfuzz_cc/hfuzz-cc
HFUZZ_CC_SRCS := hfuzz_cc/hfuzz-cc.c
COMMON_CFLAGS := -std=c11 -I/usr/local/include -D_GNU_SOURCE -Wall -Wextra -Werror -Wno-format-truncation -Wno-override-init -I$(SRCDIR)
COMMON_LDFLAGS := -pthread -L/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lm
COMMON_SRCS := $(sort $(notdir $(wildcard $(SRCDIR)/*.c)))
CFLAGS ?= -O3 -mtune=native -funroll-loops
LDFLAGS ?=
LIBS_CFLAGS ?= -fPIC -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0  # fortify-source intercepts some functions, so we disable it for libraries
GREP_COLOR ?=
BUILD_OSSFUZZ_STATIC ?= false # for https://github.com/google/oss-fuzz
BUILD_LINUX_NO_BFD ?= false # for users who don't want to use libbfd/binutils

REALOS = $(shell uname -s)
OS ?= $(shell uname -s)
MARCH ?= $(shell uname -m)
KERNEL ?= $(shell uname -r)

ifeq ($(OS)$(findstring Microsoft,$(KERNEL)),Linux) # matches Linux but excludes WSL (Windows Subsystem for Linux)
    ARCH := LINUX

    ARCH_CFLAGS := -D_FILE_OFFSET_BITS=64
    ARCH_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/linux/*.c)))
    ARCH_LDFLAGS := -L/usr/local/include
    ifeq ($(BUILD_OSSFUZZ_STATIC),true)
            ARCH_LDFLAGS += -Wl,-Bstatic \
                            `pkg-config --libs --static libunwind-ptrace libunwind-generic` \
                            -lopcodes -lbfd -liberty -lz \
                            -Wl,-Bdynamic
    else
            ARCH_LDFLAGS += -lunwind-ptrace -lunwind-generic -lunwind  -llzma \
                            -lopcodes -lbfd
    endif
    ifeq ($(BUILD_LINUX_NO_BFD),true)
            ARCH_CFLAGS += -D_HF_LINUX_NO_BFD
    endif
    ARCH_LDFLAGS += -lrt -ldl -lm -latomic

    ifeq ("$(wildcard /usr/local/include/intel-pt.h)","/usr/local/include/intel-pt.h")
        ARCH_CFLAGS += -D_HF_LINUX_INTEL_PT_LIB
        ARCH_CFLAGS += -I/usr/local/include
        ARCH_LDFLAGS += -L/usr/local/lib -lipt -Wl,--rpath=/usr/local/lib
    endif
    ifeq ("$(wildcard /usr/include/intel-pt.h)","/usr/include/intel-pt.h")
        ARCH_CFLAGS += -D_HF_LINUX_INTEL_PT_LIB
        ARCH_LDFLAGS += -lipt
    endif

# OS Linux
else ifeq ($(OS),Darwin)
    ARCH := DARWIN

    ARCH_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/mac/*.c)) mac/mach_excServer.c mac/mach_excUser.c)

    # MacOS-X grep seem to use colors unconditionally
    GREP_COLOR = --color=never

    # Figure out which crash reporter to use.
    CRASHWRANGLER := third_party/mac
    OS_VERSION := $(shell sw_vers -productVersion)
    OS_MAJOR_VERSION := $(shell echo $(OS_VERSION) | cut -f1 -d.)
    OS_MINOR_VERSION := $(shell echo $(OS_VERSION) | cut -f2 -d.)

    ifeq ($(OS_MAJOR_VERSION), 13)
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
    else ifeq ($(OS_MAJOR_VERSION), 12)
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
    else ifeq ($(OS_MAJOR_VERSION), 11)
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
    else ifeq ($(OS_MAJOR_VERSION), 10)
        ifeq ($(OS_MINOR_VERSION), 15)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
        else ifeq ($(OS_MINOR_VERSION), 14)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
        else ifeq ($(OS_MINOR_VERSION), 13)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
        else ifeq ($(OS_MINOR_VERSION), 12)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Sierra.o
        else ifeq ($(OS_MINOR_VERSION), 11)
            # El Capitan didn't break compatibility
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Yosemite.o
        else ifeq ($(OS_MINOR_VERSION), 10)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Yosemite.o
        else ifeq ($(OS_MINOR_VERSION), 9)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Mavericks.o
        else ifeq ($(OS_MINOR_VERSION), 8)
            CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Mountain_Lion.o
        endif
    endif

    ifeq ($(CRASH_REPORT), )
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
    ARCH_CFLAGS := -isysroot $(SDK) \
                   -x objective-c -pedantic -fblocks \
                   -Wno-unused-parameter \
                   -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
                   -Wreturn-type -Wpointer-arith -Wno-gnu-case-range -Wno-gnu-designator \
                   -Wno-deprecated-declarations -Wno-unknown-pragmas -Wno-attributes \
                   -Wno-embedded-directive
    ARCH_LDFLAGS := -F/System/Library/PrivateFrameworks -framework CoreSymbolication -framework IOKit \
                    -F$(SDK_V)/System/Library/Frameworks -F$(SDK_V)/System/Library/PrivateFrameworks \
                    -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks \
                    -framework Foundation -framework ApplicationServices -framework Symbolication \
                    -framework CoreServices -framework CrashReporterSupport -framework CoreFoundation \
                    -framework CommerceKit $(CRASH_REPORT)

    XCODE_VER := $(shell xcodebuild -version | grep $(GREP_COLOR) "^Xcode" | cut -d " " -f2)
# OS Darwin
else ifeq ($(OS),NetBSD)
    ARCH := NETBSD

    ARCH_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/netbsd/*.c)))
    ARCH_CFLAGS := -I/usr/pkg/include \
                   -D_KERNTYPES
    ARCH_LDFLAGS := -L/usr/local/lib -L/usr/pkg/lib \
                    -lcapstone -lrt -lm \
                    -Wl,--rpath=/usr/pkg/lib

# OS NetBSD
else
    ARCH := POSIX

    ARCH_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/posix/*.c)))
    ARCH_CFLAGS := -Wno-initializer-overrides \
                   -Wno-unknown-warning-option -Wno-unknown-pragmas
    ARCH_LDFLAGS := -L/usr/local/lib -lm
    ifeq ($(OS),SunOS)
        ARCH_CFLAGS += -m64 -D_POSIX_C_SOURCE=200809L -D__EXTENSIONS__=1
	ARCH_LDFLAGS += -m64 -lkstat -lsocket -lnsl -lkvm
    endif
    ifneq ($(OS),Linux)
        ARCH_LDFLAGS += -latomic
    endif
    ifneq ($(REALOS),OpenBSD)
    ifneq ($(REALOS),Darwin)
        ARCH_LDFLAGS += -lrt
    endif
    endif
# OS Posix
endif

CFLAGS_BLOCKS :=
COMPILER = $(shell $(CC) -v 2>&1 | \
  grep $(GREP_COLOR) -oE '((gcc|clang) version|LLVM version.*clang)' | \
  grep $(GREP_COLOR) -oE '(clang|gcc)' | head -n1)
ifeq ($(COMPILER),clang)
  ARCH_CFLAGS += -Wno-initializer-overrides -Wno-unknown-warning-option
  ARCH_CFLAGS += -Wno-gnu-empty-initializer -Wno-format-pedantic
  ARCH_CFLAGS += -Wno-gnu-statement-expression
  ARCH_CFLAGS += -mllvm -inline-threshold=2000
  CFLAGS_BLOCKS = -fblocks

  ifneq ($(REALOS),Darwin)
    ARCH_LDFLAGS += -Wl,-Bstatic -lBlocksRuntime -Wl,-Bdynamic
  endif
endif
ifeq ($(COMPILER),gcc)
  ARCH_CFLAGS += -finline-limit=4000
endif

SRCS := $(COMMON_SRCS) $(ARCH_SRCS)
OBJS := $(addprefix $(_OBJDIR)/,$(SRCS:.c=.o))

LHFUZZ_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/libhfuzz/*.c)))
LHFUZZ_OBJS := $(addprefix $(_OBJDIR)/,$(LHFUZZ_SRCS:.c=.o))
LHFUZZ_ARCH := $(_OBJDIR)/libhfuzz/libhfuzz.a
LHFUZZ_SHARED := $(_OBJDIR)/libhfuzz/libhfuzz.so
HFUZZ_INC ?= $(SRCDIR)

LCOMMON_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/libhfcommon/*.c)))
LCOMMON_OBJS := $(addprefix $(_OBJDIR)/,$(LCOMMON_SRCS:.c=.o))
LCOMMON_ARCH := $(_OBJDIR)/libhfcommon/libhfcommon.a

LNETDRIVER_SRCS := $(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/libhfnetdriver/*.c)))
LNETDRIVER_OBJS := $(addprefix $(_OBJDIR)/,$(LNETDRIVER_SRCS:.c=.o))
LNETDRIVER_ARCH := $(_OBJDIR)/libhfnetdriver/libhfnetdriver.a

# Respect external user defines
REALOS_UPPER = $(shell echo $(REALOS) | tr '[:lower:]' '[:upper:]')
CFLAGS += $(COMMON_CFLAGS) $(ARCH_CFLAGS) -D_HF_ARCH_${ARCH} -D_HF_ARCH_${REALOS_UPPER}
LDFLAGS += $(COMMON_LDFLAGS) $(ARCH_LDFLAGS)

ifdef DEBUG
    CFLAGS += -g -ggdb -g3
    LDFLAGS += -g -ggdb -g3
endif

# Control Android builds
ANDROID_API           ?= android-30 # Minimal working version is android-30 (ndk 22)
ANDROID_DEBUG_ENABLED ?= false
ANDROID_APP_ABI       ?= arm64-v8a
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

ANDROID_NDK_TOOLCHAIN_VER := clang
# clang works only against APIs >= 23
ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),armeabi-v7a))
  ANDROID_NDK_TOOLCHAIN ?= arm-linux-androideabi-clang
  ANDROID_NDK_COMPILER_PREFIX := armv7a-linux-androideabi
  ANDROID_ARCH_CPU := arm
else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),x86))
  ANDROID_NDK_TOOLCHAIN ?= x86-clang
  ANDROID_NDK_COMPILER_PREFIX := i686-linux-android
  ANDROID_ARCH_CPU := x86
else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),arm64-v8a))
  ANDROID_NDK_TOOLCHAIN ?= aarch64-linux-android-clang
  ANDROID_NDK_COMPILER_PREFIX := aarch64-linux-android
  ANDROID_ARCH_CPU := arm64
else ifeq ($(ANDROID_APP_ABI),$(filter $(ANDROID_APP_ABI),x86_64))
  ANDROID_NDK_TOOLCHAIN ?= x86_64-clang
  ANDROID_NDK_COMPILER_PREFIX := x86_64-linux-android
  ANDROID_ARCH_CPU := x86_64
else
   $(error Unsuported / Unknown APP_API '$(ANDROID_APP_ABI)')
endif


SUBDIR_ROOTS := linux mac netbsd posix libhfuzz libhfcommon libhfnetdriver
DIRS := . $(shell find $(SUBDIR_ROOTS) -type d 2>/dev/null)
CLEAN_PATTERNS := *.o *~ core *.a *.dSYM *.la *.so *.dylib
SUBDIR_GARBAGE := $(foreach DIR,$(DIRS),$(addprefix $(DIR)/,$(CLEAN_PATTERNS)))
MAC_GARGBAGE := $(wildcard mac/mach_exc*)
ANDROID_GARBAGE := obj libs

CLEAN_TARGETS := core Makefile.bak \
  $(OBJS) $(BIN) $(HFUZZ_CC_BIN) \
  $(LHFUZZ_ARCH) $(LHFUZZ_SHARED) $(LHFUZZ_OBJS) \
  $(LCOMMON_ARCH) $(LCOMMON_OBJS) \
  $(LNETDRIVER_ARCH) $(LNETDRIVER_OBJS) \
  $(MAC_GARGBAGE) $(ANDROID_GARBAGE) $(SUBDIR_GARBAGE)

# Collect all output directories that need to exist in BUILD_DIR
_BUILD_SUBDIRS := $(sort $(dir $(OBJS) $(LHFUZZ_OBJS) $(LCOMMON_OBJS) $(LNETDRIVER_OBJS) $(BIN) $(HFUZZ_CC_BIN)))

all: $(BIN) $(HFUZZ_CC_BIN) $(LHFUZZ_ARCH) $(LHFUZZ_SHARED) $(LCOMMON_ARCH) $(LNETDRIVER_ARCH)

# Enable second expansion for order-only prerequisite directory creation
.SECONDEXPANSION:

# Create build output directories on demand
$(_BUILD_SUBDIRS):
	mkdir -p $@

# Generic rule: compile .c -> .o in _OBJDIR
$(_OBJDIR)/%.o: %.c | $$(dir $$@)
	$(CC) -c $(CFLAGS) $(CFLAGS_BLOCKS) -o $@ $<

mac/mach_exc.h mac/mach_excServer.c mac/mach_excServer.h mac/mach_excUser.c &:
	mig -header mac/mach_exc.h -user mac/mach_excUser.c -sheader mac/mach_excServer.h \
		-server mac/mach_excServer.c $(SDK)/usr/include/mach/mach_exc.defs

$(_OBJDIR)/mac/arch.o: mac/arch.c mac/mach_exc.h mac/mach_excServer.h | $$(dir $$@)
	$(CC) -c $(CFLAGS) $(CFLAGS_BLOCKS) -o $@ $<

$(_OBJDIR)/%.so: %.c | $$(dir $$@)
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $<

$(_OBJDIR)/%.dylib: %.c | $$(dir $$@)
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $<

$(BIN): $(OBJS) $(LCOMMON_ARCH) | $$(dir $$@)
	$(LD) -o $(BIN) $(OBJS) $(LCOMMON_ARCH) $(LDFLAGS)

$(HFUZZ_CC_BIN): $(LCOMMON_ARCH) $(LHFUZZ_ARCH) $(LNETDRIVER_ARCH) $(HFUZZ_CC_SRCS) | $$(dir $$@)
	$(LD) -o $@ $(SRCDIR)/$(HFUZZ_CC_SRCS) $(LCOMMON_ARCH) $(LDFLAGS) $(CFLAGS) $(CFLAGS_BLOCKS) -D_HFUZZ_INC_PATH=$(HFUZZ_INC)

$(LCOMMON_OBJS): $(LCOMMON_SRCS)

$(LCOMMON_ARCH): $(LCOMMON_OBJS) | $$(dir $$@)
	$(AR) rcs $(LCOMMON_ARCH) $(LCOMMON_OBJS)

$(LHFUZZ_OBJS): $(LHFUZZ_SRCS)

# Specific pattern rules for library objects (need LIBS_CFLAGS)
$(_OBJDIR)/libhfcommon/%.o: libhfcommon/%.c | $$(dir $$@)
	$(CC) -c $(CFLAGS) $(LIBS_CFLAGS) -o $@ $<

$(_OBJDIR)/libhfuzz/%.o: libhfuzz/%.c | $$(dir $$@)
	$(CC) -c $(CFLAGS) $(LIBS_CFLAGS) -o $@ $<

$(_OBJDIR)/libhfnetdriver/%.o: libhfnetdriver/%.c | $$(dir $$@)
	$(CC) -c $(CFLAGS) $(LIBS_CFLAGS) -o $@ $<

$(LHFUZZ_ARCH): $(LHFUZZ_OBJS) | $$(dir $$@)
	$(AR) rcs $(LHFUZZ_ARCH) $(LHFUZZ_OBJS)

$(LHFUZZ_SHARED): $(LHFUZZ_OBJS) $(LCOMMON_OBJS) | $$(dir $$@)
	$(LD) -shared $(LHFUZZ_OBJS) $(LCOMMON_OBJS) $(LDFLAGS) -o $@

$(LNETDRIVER_OBJS): $(LNETDRIVER_SRCS)

$(LNETDRIVER_ARCH): $(LNETDRIVER_OBJS) | $$(dir $$@)
	$(AR) rcs $(LNETDRIVER_ARCH) $(LNETDRIVER_OBJS)

.PHONY: clean
clean:
	$(RM) -r $(CLEAN_TARGETS)

.PHONY: indent
indent:
	cd $(SRCDIR) && clang-format -i -sort-includes  *.c *.h */*.c */*.h

.PHONY: depend
depend: all
	cd $(SRCDIR) && makedepend -Y. -Y* -- *.c */*.c

.PHONY: android
android:
	$(info ***************************************************************)
	$(info *                 Use Android NDK 22 or newer                 *)
	$(info ***************************************************************)
	@ANDROID_API=$(ANDROID_API) ANDROID_NDK_COMPILER_PREFIX=$(ANDROID_NDK_COMPILER_PREFIX) $(SRCDIR)/third_party/android/scripts/compile-libunwind.sh \
	$(SRCDIR)/third_party/android/libunwind $(ANDROID_ARCH_CPU)

	@ANDROID_API=$(ANDROID_API) ANDROID_NDK_COMPILER_PREFIX=$(ANDROID_NDK_COMPILER_PREFIX) $(SRCDIR)/third_party/android/scripts/compile-capstone.sh \
	$(SRCDIR)/third_party/android/capstone $(ANDROID_ARCH_CPU)

	@ANDROID_API=$(ANDROID_API) ANDROID_NDK_COMPILER_PREFIX=$(ANDROID_NDK_COMPILER_PREFIX) $(SRCDIR)/third_party/android/scripts/compile-libBlocksRuntime.sh \
	$(SRCDIR)/third_party/android/libBlocksRuntime $(ANDROID_ARCH_CPU)

	ndk-build NDK_PROJECT_PATH=$(SRCDIR) APP_BUILD_SCRIPT=$(SRCDIR)/android/Android.mk \
    APP_PLATFORM=$(ANDROID_API) APP_ABI=$(ANDROID_APP_ABI) \
    NDK_TOOLCHAIN=$(ANDROID_NDK_TOOLCHAIN) NDK_TOOLCHAIN_VERSION=$(ANDROID_NDK_TOOLCHAIN_VER) \
    $(NDK_BUILD_ARGS) APP_MODULES='honggfuzz hfuzz hfnetdriver'

# Loop all ABIs and pass-through flags since visibility is lost due to sub-process
.PHONY: android-all
android-all:
	@echo "Cleaning workspace:"
	$(MAKE) clean
	@echo ""

	for abi in armeabi-v7a arm64-v8a x86 x86_64; do \
	  ANDROID_APP_ABI=$$abi ANDROID_SKIP_CLEAN=true \
	  ANDROID_API=$(ANDROID_API) ANDROID_DEBUG_ENABLED=$(ANDROID_DEBUG_ENABLED) \
	  $(MAKE) android || { \
	    echo "Recursive make failed"; exit 1; }; \
	  echo ""; \
	done

.PHONY: android-clean-deps
android-clean-deps:
	@for cpu in arm arm64 x86 x86_64; do \
	  make -C "$(SRCDIR)/third_party/android/capstone" clean; \
	  rm -rf "$(SRCDIR)/third_party/android/capstone/$$cpu"; \
	  make -C "$(SRCDIR)/third_party/android/libunwind" clean; \
	  rm -rf "$(SRCDIR)/third_party/android/libunwind/$$cpu"; \
	  ndk-build -C "$(SRCDIR)/third_party/android/libBlocksRuntime" \
	    NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk clean; \
	  rm -rf "$(SRCDIR)/third_party/android/libBlocksRuntime/$$cpu"; \
	done

PREFIX		?= /usr/local
BIN_PATH	= $(PREFIX)/bin
INC_PATH	= $(PREFIX)/include

install: all
	mkdir -p -m 755 $${DESTDIR}$(BIN_PATH)
	install -m 755 $(BIN) $${DESTDIR}$(BIN_PATH)
	install -m 755 $(HFUZZ_CC_BIN) $${DESTDIR}$(BIN_PATH)
	install -m 755 $(SRCDIR)/hfuzz_cc/hfuzz-clang $${DESTDIR}$(BIN_PATH)
	install -m 755 $(SRCDIR)/hfuzz_cc/hfuzz-clang++ $${DESTDIR}$(BIN_PATH)
	install -m 755 $(SRCDIR)/hfuzz_cc/hfuzz-gcc $${DESTDIR}$(BIN_PATH)
	install -m 755 $(SRCDIR)/hfuzz_cc/hfuzz-g++ $${DESTDIR}$(BIN_PATH)
	install -d $${DESTDIR}$(INC_PATH)/libhfcommon
	install -d $${DESTDIR}$(INC_PATH)/libhfuzz
	install -d $${DESTDIR}$(INC_PATH)/libhnetdriver
	install -m 755 $(SRCDIR)/includes/libhfcommon/*.h $${DESTDIR}$(INC_PATH)/libhfcommon
	install -m 755 $(SRCDIR)/includes/libhfuzz/*.h $${DESTDIR}$(INC_PATH)/libhfuzz
	install -m 755 $(SRCDIR)/includes/libhfnetdriver/*.h $${DESTDIR}$(INC_PATH)/libhnetdriver

# DO NOT DELETE

$(_OBJDIR)/cmdline.o: cmdline.h honggfuzz.h libhfcommon/util.h display.h
$(_OBJDIR)/cmdline.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/cmdline.o: libhfcommon/log.h
$(_OBJDIR)/dict.o: dict.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/dict.o: libhfcommon/log.h
$(_OBJDIR)/display.o: display.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/display.o: libhfcommon/log.h
$(_OBJDIR)/fuzz.o: fuzz.h arch.h honggfuzz.h libhfcommon/util.h input.h
$(_OBJDIR)/fuzz.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/fuzz.o: libhfcommon/log.h report.h sanitizers.h socketfuzzer.h subproc.h
$(_OBJDIR)/honggfuzz.o: cmdline.h honggfuzz.h libhfcommon/util.h dict.h display.h fuzz.h
$(_OBJDIR)/honggfuzz.o: input.h libhfcommon/common.h libhfcommon/files.h
$(_OBJDIR)/honggfuzz.o: libhfcommon/common.h libhfcommon/log.h socketfuzzer.h subproc.h
$(_OBJDIR)/input.o: input.h honggfuzz.h libhfcommon/util.h dict.h fuzz.h
$(_OBJDIR)/input.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/input.o: libhfcommon/log.h mangle.h power.h subproc.h
$(_OBJDIR)/mangle.o: mangle.h honggfuzz.h libhfcommon/util.h input.h
$(_OBJDIR)/mangle.o: libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/power.o: power.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/report.o: report.h honggfuzz.h libhfcommon/util.h sanitizers.h
$(_OBJDIR)/report.o: libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/sanitizers.o: sanitizers.h honggfuzz.h libhfcommon/util.h cmdline.h
$(_OBJDIR)/sanitizers.o: libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/socketfuzzer.o: socketfuzzer.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/socketfuzzer.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/socketfuzzer.o: libhfcommon/log.h libhfcommon/ns.h
$(_OBJDIR)/subproc.o: subproc.h honggfuzz.h libhfcommon/util.h arch.h fuzz.h
$(_OBJDIR)/subproc.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/subproc.o: libhfcommon/log.h
$(_OBJDIR)/hfuzz_cc/hfuzz-cc.o: honggfuzz.h libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/hfuzz_cc/hfuzz-cc.o: libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/hfuzz_cc/hfuzz-cc.o: libhfcommon/log.h
$(_OBJDIR)/libhfcommon/files.o: libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/libhfcommon/files.o: libhfcommon/log.h libhfcommon/util.h
$(_OBJDIR)/libhfcommon/log.o: libhfcommon/log.h libhfcommon/common.h libhfcommon/util.h
$(_OBJDIR)/libhfcommon/ns.o: libhfcommon/ns.h libhfcommon/common.h libhfcommon/files.h
$(_OBJDIR)/libhfcommon/ns.o: libhfcommon/log.h libhfcommon/util.h
$(_OBJDIR)/libhfcommon/util.o: libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/libhfcommon/util.o: libhfcommon/files.h libhfcommon/log.h
$(_OBJDIR)/libhfnetdriver/netdriver.o: libhfnetdriver/netdriver.h honggfuzz.h
$(_OBJDIR)/libhfnetdriver/netdriver.o: libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/libhfnetdriver/netdriver.o: libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/libhfnetdriver/netdriver.o: libhfcommon/log.h libhfcommon/ns.h
$(_OBJDIR)/libhfuzz/fetch.o: libhfuzz/fetch.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/libhfuzz/fetch.o: libhfcommon/files.h libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/libhfuzz/instrument.o: libhfuzz/instrument.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/libhfuzz/instrument.o: libhfcommon/common.h libhfcommon/files.h
$(_OBJDIR)/libhfuzz/instrument.o: libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/libhfuzz/linux.o: libhfcommon/common.h libhfcommon/files.h
$(_OBJDIR)/libhfuzz/linux.o: libhfcommon/common.h libhfcommon/log.h libhfcommon/ns.h
$(_OBJDIR)/libhfuzz/linux.o: libhfuzz/libhfuzz.h
$(_OBJDIR)/libhfuzz/memorycmp.o: libhfcommon/common.h libhfcommon/util.h
$(_OBJDIR)/libhfuzz/memorycmp.o: libhfuzz/instrument.h
$(_OBJDIR)/libhfuzz/performance.o: libhfuzz/performance.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/libhfuzz/performance.o: libhfcommon/log.h libhfuzz/instrument.h
$(_OBJDIR)/libhfuzz/persistent.o: honggfuzz.h libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/libhfuzz/persistent.o: libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/libhfuzz/persistent.o: libhfcommon/log.h libhfuzz/fetch.h
$(_OBJDIR)/libhfuzz/persistent.o: libhfuzz/instrument.h libhfuzz/libhfuzz.h
$(_OBJDIR)/libhfuzz/persistent.o: libhfuzz/performance.h
$(_OBJDIR)/linux/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h
$(_OBJDIR)/linux/arch.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/linux/arch.o: libhfcommon/log.h libhfcommon/ns.h linux/perf.h linux/trace.h
$(_OBJDIR)/linux/arch.o: sanitizers.h subproc.h
$(_OBJDIR)/linux/bfd.o: linux/bfd.h linux/unwind.h sanitizers.h honggfuzz.h
$(_OBJDIR)/linux/bfd.o: libhfcommon/util.h dict.h libhfcommon/common.h
$(_OBJDIR)/linux/bfd.o: libhfcommon/files.h libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/linux/perf.o: linux/perf.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/linux/perf.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/linux/perf.o: libhfcommon/log.h linux/pt.h
$(_OBJDIR)/linux/pt.o: linux/pt.h honggfuzz.h libhfcommon/util.h libhfcommon/common.h
$(_OBJDIR)/linux/pt.o: libhfcommon/log.h
$(_OBJDIR)/linux/trace.o: linux/trace.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/linux/trace.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/linux/trace.o: libhfcommon/log.h linux/bfd.h linux/unwind.h sanitizers.h
$(_OBJDIR)/linux/trace.o: report.h socketfuzzer.h subproc.h
$(_OBJDIR)/linux/unwind.o: linux/unwind.h sanitizers.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/linux/unwind.o: libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/mac/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h libhfcommon/common.h
$(_OBJDIR)/mac/arch.o: libhfcommon/files.h libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/mac/arch.o: subproc.h
$(_OBJDIR)/netbsd/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h
$(_OBJDIR)/netbsd/arch.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/netbsd/arch.o: libhfcommon/log.h libhfcommon/ns.h netbsd/trace.h subproc.h
$(_OBJDIR)/netbsd/trace.o: netbsd/trace.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/netbsd/trace.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/netbsd/trace.o: libhfcommon/log.h netbsd/unwind.h sanitizers.h report.h
$(_OBJDIR)/netbsd/trace.o: subproc.h
$(_OBJDIR)/netbsd/unwind.o: netbsd/unwind.h sanitizers.h honggfuzz.h libhfcommon/util.h
$(_OBJDIR)/netbsd/unwind.o: libhfcommon/common.h libhfcommon/log.h
$(_OBJDIR)/posix/arch.o: arch.h honggfuzz.h libhfcommon/util.h fuzz.h
$(_OBJDIR)/posix/arch.o: libhfcommon/common.h libhfcommon/files.h libhfcommon/common.h
$(_OBJDIR)/posix/arch.o: libhfcommon/log.h report.h sanitizers.h subproc.h
