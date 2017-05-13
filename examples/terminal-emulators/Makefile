HFUZZ_CC ?= ../../hfuzz_cc/hfuzz-clang
CC ?= cc

CFLAGS += -std=c99

BIN = terminal-test
LIBCLOSE = libclose.so

all: $(BIN) $(LIBCLOSE)

$(BIN): $(BIN:=.c)
	$(HFUZZ_CC) $(CFLAGS) $(LDFLAGS) -o $(BIN) $<

$(LIBCLOSE): $(LIBCLOSE:.so=.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $(LIBCLOSE) $<

clean:
	rm -f -- $(BIN) $(LIBCLOSE)
