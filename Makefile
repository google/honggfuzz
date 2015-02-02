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


CC = gcc
CFLAGS += -c -std=gnu11 -I. -I/usr/local/include -I/usr/include \
	-D_GNU_SOURCE \
	-Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
	-Wreturn-type -Wpointer-arith -Wextra -Wno-override-init

LD = gcc
LDFLAGS += -lm -L/usr/local/include -L/usr/include

SRCS = honggfuzz.c log.c files.c fuzz.c util.c

OBJS = $(SRCS:.c=.o)
BIN = honggfuzz

OS = $(shell uname -s)

ARCH_SRCS := arch_posix.c

ifeq ($(OS),Linux)
	LDFLAGS += -lcapstone
	ARCH_SRCS = arch_linux.c
endif
ifeq ($(OS),Darwin)
	CC ?= cc
	CFLAGS += -arch x86_64 -O3 -g -ggdb -c -std=c99 -I. -I~/.homebrew/include -I/usr/include \
	    -x objective-c \
		-D_GNU_SOURCE \
		-pedantic \
		-Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wcast-align \
		-Wreturn-type -Wpointer-arith
	LD ?= cc
	LDFLAGS += -F/System/Library/PrivateFrameworks -framework CoreSymbolication -framework IOKit \
		-framework Foundation -framework ApplicationServices -framework Symbolication \
		-framework CoreServices -framework CrashReporterSupport -framework CoreFoundation \
		-framework CommerceKit -lm -L/usr/include -L$(shell echo ~)/.homebrew/lib
	ARCH_SRCS = arch_mac.c
	MIG_OUTPUT = mach_exc.h mach_excUser.c mach_excServer.h mach_excServer.c
	MIG_OBJECTS = mach_excUser.o mach_excServer.o
	CRASH_REPORT = third_party/CrashReport_Yosemite.o
endif
SRCS += $(ARCH_SRCS)

all: $(BIN)

.c.o: %.c
	$(CC) $(CFLAGS) $<

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
	indent -linux -l100 -lc100 -nut -i4 -sob -c33 -cp33 *.c *.h; rm -f *~

depend:
	makedepend -Y. -- $(SRCS)

# DO NOT DELETE

honggfuzz.o: common.h log.h files.h fuzz.h util.h
log.o: common.h log.h
files.o: common.h files.h log.h
fuzz.o: common.h fuzz.h log.h arch.h util.h files.h
util.o: common.h log.h
arch_linux.o: common.h arch.h log.h util.h
