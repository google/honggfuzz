#   honggfuzz - Makefile
#   -----------------------------------------
#
#   Author: Robert Swiecki <swiecki@google.com>
#
#   Copyright 2010 by Google Inc. All Rights Reserved.
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
CFLAGS ?= -O3 -g -ggdb -c -std=c99 -I. -I/usr/local/include -I/usr/include \
	-D_GNU_SOURCE \
	-pedantic \
	-Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wcast-align \
	-Wreturn-type -Wpointer-arith

LD := gcc
LDFLAGS ?= -lm -L/usr/local/include -L/usr/include
OS ?= $(shell uname -s)

SRCS = honggfuzz.c log.c files.c fuzz.c util.c

ARCH_SRCS := arch_posix.c
ifeq ($(OS),Linux)
	LDFLAGS += -ludis86
	CFLAGS += -D_HAVE_ARCH_PTRACE
	ARCH_SRCS = arch_ptrace.c
endif
ifeq ($(OS),Darwin)
	LDFLAGS += -ludis86
	ARCH_SRCS = arch_mac.c
endif
SRCS += $(ARCH_SRCS)

OBJS = $(SRCS:.c=.o)
BIN = honggfuzz

all: $(BIN)

.c.o: %.c
	@(echo CC $<; $(CC) $(CFLAGS) $<)

$(BIN): $(OBJS)
	@(echo LD $@; $(LD) -o $(BIN) $(OBJS) $(LDFLAGS))

clean:
	@(echo CLEAN; $(RM) core $(OBJS) $(BIN))

indent:
	@(echo INDENT; indent -linux -l100 -lc100 -nut -i4 -sob -c33 -cp33 *.c *.h; rm -f *~)
# DO NOT DELETE
