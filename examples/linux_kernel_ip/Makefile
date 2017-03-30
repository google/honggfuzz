CC ?= gcc
LD = $(CC)
BIN := tun
SRCS := tun.c
CFLAGS := -std=c11
LDFLAGS := ~/src/honggfuzz/libhfuzz/libhfuzz.a

OBJS := $(SRCS:.c=.o)

all: $(BIN)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

$(BIN): $(OBJS)
	$(LD) -o $(BIN) $(OBJS) $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) -r core $(OBJS) $(BIN) *~ */*~

.PHONY: indent
indent:
	clang-format-4.0 -style=WebKit -i --sort-includes $(SRCS)
