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


CC ?= gcc
CFLAGS += -c -std=c11 -I. -I/usr/local/include -I/usr/include \
	-D_GNU_SOURCE \
	-Wall -Wextra -Wno-initializer-overrides -Wno-override-init -Wno-unknown-warning-option -Werror \
	-funroll-loops -O2

LD = $(CC)
LDFLAGS += -lm -lpthread -L/usr/local/include -L/usr/include

SRCS = honggfuzz.c log.c files.c fuzz.c report.c mangle.c util.c

OBJS = $(SRCS:.c=.o)
BIN = honggfuzz

OS ?= $(shell uname -s)
MARCH ?= $(shell uname -m)

ARCH_SRCS := $(wildcard posix/*.c)
ARCH = POSIX

ifeq ($(OS),Linux)
	ARCH = LINUX
	CFLAGS +=  -D_FILE_OFFSET_BITS=64
	LDFLAGS += -lunwind-ptrace -lunwind-generic -lbfd -lopcodes
	ARCH_SRCS := $(wildcard linux/*.c)

	ifeq ("$(wildcard /usr/include/bfd.h)","")
		WARN_LIBRARY += "binutils-dev "
	endif
	ifeq ("$(wildcard /usr/include/libunwind-ptrace.h)","")
		WARN_LIBRARY += "libunwind-dev/libunwind8-dev "
	endif

	ifeq ($(MARCH),x86_64)
		# Support for popcnt (used in linux/perf.c)
		CFLAGS += -msse4.2
	endif	# MARCH
	ifeq ($(MARCH),i386)
		# Support for popcnt (used in linux/perf.c)
		CFLAGS += -msse4.2
	endif	# MARCH
endif	# OS

ifeq ($(OS),Darwin)
	CC ?= cc
	CFLAGS = -arch x86_64 -O3 -g -ggdb -c -std=c99 -I. -I~/.homebrew/include -I/usr/include \
	    -x objective-c \
		-D_GNU_SOURCE \
		-pedantic \
		-Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wcast-align \
		-Wreturn-type -Wpointer-arith
	LD ?= cc
	LDFLAGS = -F/System/Library/PrivateFrameworks -framework CoreSymbolication -framework IOKit \
		-framework Foundation -framework ApplicationServices -framework Symbolication \
		-framework CoreServices -framework CrashReporterSupport -framework CoreFoundation \
		-framework CommerceKit -lm -L/usr/include -L$(shell echo ~)/.homebrew/lib
	ARCH_SRCS = $(wildcard mac/*.c)
	MIG_OUTPUT = mach_exc.h mach_excUser.c mach_excServer.h mach_excServer.c
	MIG_OBJECTS = mach_excUser.o mach_excServer.o
	#CRASH_REPORT = third_party/CrashReport_Yosemite.o
	CRASH_REPORT = third_party/CrashReport_Mavericks.o
	ARCH = DARWIN
endif

SRCS += $(ARCH_SRCS)
CFLAGS += -D_HF_ARCH_${ARCH}

all: warn_libs $(BIN)

.c.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

warn_libs:
ifdef WARN_LIBRARY
	@/bin/echo -e "*********************************************************"
	@/bin/echo -e "Development libraries which are most likely missing on your OS:"
	@/bin/echo    "$(WARN_LIBRARY)"
	@/bin/echo -e "*********************************************************"
else
endif

$(BIN): $(MIG_OBJECTS) $(OBJS)
	$(LD) -o $(BIN) $(OBJS) $(MIG_OBJECTS) $(CRASH_REPORT) $(LDFLAGS)

$(MIG_OUTPUT): /usr/include/mach/mach_exc.defs
	mig -header mach_exc.h -user mach_excUser.c -sheader mach_excServer.h -server mach_excServer.c /usr/include/mach/mach_exc.defs

$(MIG_OBJECTS): $(MIG_OUTPUT)
	$(CC) $(CFLAGS) mach_excUser.c
	$(CC) $(CFLAGS) mach_excServer.c

clean:
	$(RM) core $(OBJS) $(BIN) $(MIG_OUTPUT) $(MIG_OBJECTS)

indent:
	indent -linux -l100 -lc100 -nut -i4 -sob -c33 -cp33 *.c *.h */*.c */*.h; rm -f *~ */*~

depend:
	makedepend -Y. -Y* -- $(SRCS)

# DO NOT DELETE

honggfuzz.o: common.h log.h files.h fuzz.h util.h
log.o: common.h log.h
files.o: common.h files.h log.h
fuzz.o: common.h fuzz.h arch.h files.h log.h report.h util.h
util.o: common.h log.h
report.o: common.h report.h log.h util.h
linux/arch.o: common.h arch.h linux/perf.h linux/ptrace.h log.h util.h
linux/bfd.o: common.h linux/bfd.h files.h log.h util.h
linux/perf.o: common.h linux/perf.h log.h
linux/ptrace.o: common.h linux/ptrace.h files.h linux/bfd.h linux/unwind.h
linux/ptrace.o: log.h util.h
linux/unwind.o: common.h linux/unwind.h log.h
