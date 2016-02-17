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


# Common for all architectures
BIN := honggfuzz
COMMON_CFLAGS := -D_GNU_SOURCE -Wall -Werror -Wframe-larger-than=51200
COMMON_LDFLAGS := -lm
COMMON_SRCS := honggfuzz.c cmdline.c display.c log.c files.c fuzz.c report.c mangle.c util.c
INTERCEPTOR_SRCS := $(wildcard interceptor/*.c)

OS ?= $(shell uname -s)
MARCH ?= $(shell uname -m)

ifeq ($(OS),Linux)
    ARCH := LINUX
    ARCH_DSUFFIX := .so
    CC ?= gcc
    LD = $(CC)
    ARCH_CFLAGS := -std=c11 -I. -I/usr/local/include -I/usr/include \
                   -Wextra -Wno-initializer-overrides -Wno-override-init \
                   -Wno-unknown-warning-option -funroll-loops -O2 \
                   -D_FILE_OFFSET_BITS=64
    ARCH_LDFLAGS := -L/usr/local/include -L/usr/include \
                    -lpthread -lunwind-ptrace -lunwind-generic -lbfd -lopcodes -lrt
    ARCH_SRCS := $(wildcard linux/*.c)

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
        $(info ***************************************************************)
        $(info Development libraries which are most likely missing on your OS:)
        $(info $(WARN_LIBRARY))
        $(info ***************************************************************)
    endif

    ifeq ($(MARCH),$(filter $(MARCH),x86_64 i386))
        # Support for popcnt (used in linux/perf.c)
        ARCH_CFLAGS += -msse4.2
    endif       # MARCH
    # OS Linux
else ifeq ($(OS),Darwin)
    ARCH := DARWIN
    ARCH_DSUFFIX := .dylib
    CRASHWRANGLER := third_party/mac
    OS_VERSION := $(shell sw_vers -productVersion)
    ifneq (,$(findstring 10.11,$(OS_VERSION)))
        # El Capitan didn't break compatibility
        SDK_NAME := "macosx10.11"
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Yosemite.o
    else ifneq (,$(findstring 10.10,$(OS_VERSION)))
        SDK_NAME := "macosx10.10"
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Yosemite.o
    else ifneq (,$(findstring 10.9,$(OS_VERSION)))
        SDK_NAME := "macosx10.9"
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Mavericks.o
    else ifneq (,$(findstring 10.8,$(OS_VERSION)))
        SDK_NAME := "macosx10.8"
        CRASH_REPORT := $(CRASHWRANGLER)/CrashReport_Mountain_Lion.o
    else
        $(error Unsupported MAC OS X version)
    endif
    SDK := $(shell xcrun --sdk $(SDK_NAME) --show-sdk-path 2>/dev/null)
    ifeq (,$(findstring MacOSX.platform,$(SDK)))
        XC_PATH := $(shell xcode-select -p)
        $(error $(SDK_NAME) not found in $(XC_PATH))
    endif
    CC := $(shell xcrun --sdk $(SDK_NAME) --find cc)
    LD := $(shell xcrun --sdk $(SDK_NAME) --find cc)
    ARCH_CFLAGS := -arch x86_64 -O3 -std=c99 -isysroot $(SDK) -I. \
                   -x objective-c -pedantic \
                   -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
                   -Wreturn-type -Wpointer-arith -Wno-gnu-case-range -Wno-gnu-designator \
                   -Wno-deprecated-declarations -Wno-unknown-pragmas -Wno-attributes
    ARCH_LDFLAGS := -F/System/Library/PrivateFrameworks -framework CoreSymbolication -framework IOKit \
                    -F$(SDK)/System/Library/Frameworks -F$(SDK)/System/Library/PrivateFrameworks \
                    -framework Foundation -framework ApplicationServices -framework Symbolication \
                    -framework CoreServices -framework CrashReporterSupport -framework CoreFoundation \
                    -framework CommerceKit $(CRASH_REPORT)
    MIG_RET := $(shell mig -header mac/mach_exc.h -user mac/mach_excUser.c -sheader mac/mach_excServer.h \
                 -server mac/mach_excServer.c $(SDK)/usr/include/mach/mach_exc.defs &>/dev/null; echo $$?)
    ifeq ($(MIG_RET),1)
        $(error mig failed to generate RPC code)
    endif
    ARCH_SRCS := $(wildcard mac/*.c)
    # OS Darwin
else
    ARCH := POSIX
    ARCH_DSUFFIX := .so
    CC ?= gcc
    LD = $(CC)
    ARCH_SRCS := $(wildcard posix/*.c)
    ARCH_CFLAGS := -std=c11 -I. -I/usr/local/include -I/usr/include \
                   -Wextra -Wno-initializer-overrides -Wno-override-init \
                   -Wno-unknown-warning-option -funroll-loops -O2
    ARCH_LDFLAGS := -lpthread -L/usr/local/include -L/usr/include
    # OS Posix
endif

SRCS := $(COMMON_SRCS) $(ARCH_SRCS)
OBJS := $(SRCS:.c=.o)
INTERCEPTOR_LIBS := $(INTERCEPTOR_SRCS:.c=$(ARCH_DSUFFIX))

# Respect external user defines
CFLAGS += $(COMMON_CFLAGS) $(ARCH_CFLAGS) -D_HF_ARCH_${ARCH}
LDFLAGS += $(COMMON_LDFLAGS) $(ARCH_LDFLAGS)

ifeq ($(DEBUG),true)
    CFLAGS += -g -ggdb
endif

# Control Android builds
ANDROID_DEBUG_ENABLED ?= false
ANDROID_APP_ABI       ?= armeabi-v7a
ANDROID_API           ?= android-21
ANDROID_NDK_TOOLCHAIN ?=
NDK_BUILD_ARGS :=
ifeq ($(ANDROID_DEBUG_ENABLED),true)
    NDK_BUILD_ARGS += V=1 NDK_DEBUG=1 APP_OPTIM=debug
endif

SUBDIR_ROOTS := linux mac posix interceptor
DIRS := . $(shell find $(SUBDIR_ROOTS) -type d)
CLEAN_PATTERNS := *.o *~ core *.a *.dSYM *.la *.so *.dylib
SUBDIR_GARBAGE := $(foreach DIR,$(DIRS),$(addprefix $(DIR)/,$(CLEAN_PATTERNS)))
MAC_GARGBAGE := $(wildcard mac/mach_exc*)
ANDROID_GARBAGE := obj libs

all: $(BIN) $(INTERCEPTOR_LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

%.so: %.c
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $<

%.dylib: %.c
	$(CC) -fPIC -shared $(CFLAGS) -o $@ $<

$(BIN): $(OBJS)
	$(LD) -o $(BIN) $(OBJS) $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) -r core $(OBJS) $(BIN) $(MAC_GARGBAGE) $(ANDROID_GARBAGE) $(SUBDIR_GARBAGE)

.PHONY: indent
indent:
	indent -linux -l100 -lc100 -nut -i4 *.c *.h */*.c */*.h; rm -f *~ */*~

.PHONY: depend
depend:
	makedepend -Y. -Y* -- $(SRCS)

.PHONY: android
android:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android/Android.mk \
                  APP_PLATFORM=$(ANDROID_API) APP_ABI=$(ANDROID_APP_ABI) \
                  NDK_TOOLCHAIN=$(ANDROID_NDK_TOOLCHAIN) $(NDK_BUILD_ARGS)


# DO NOT DELETE

honggfuzz.o: common.h cmdline.h log.h files.h fuzz.h util.h
cmdline.o: cmdline.h common.h log.h files.h util.h
display.o: common.h display.h log.h util.h
log.o: log.h common.h
files.o: common.h files.h log.h
fuzz.o: common.h fuzz.h arch.h display.h files.h log.h mangle.h report.h
fuzz.o: util.h
report.o: common.h report.h log.h util.h
mangle.o: common.h mangle.h log.h util.h
util.o: common.h files.h log.h
linux/ptrace_utils.o: common.h linux/ptrace_utils.h files.h linux/bfd.h
linux/ptrace_utils.o: linux/unwind.h log.h util.h
linux/sancov.o: common.h linux/sancov.h util.h files.h log.h
linux/perf.o: common.h linux/perf.h files.h linux/pt.h log.h util.h
linux/bfd.o: common.h linux/bfd.h files.h log.h util.h
linux/pt.o: common.h linux/pt.h log.h
linux/unwind.o: common.h linux/unwind.h log.h
linux/arch.o: common.h arch.h linux/perf.h linux/ptrace_utils.h
linux/arch.o: linux/sancov.h log.h util.h files.h
