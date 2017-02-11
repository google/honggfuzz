CC ?= gcc
CFLAGS ?= -fno-stack-protector -Wno-builtin-memcpy-chk-size

BINS = badcode1 badcode2

all: $(BINS)
	@(echo CC $<; $(CC) $(CFLAGS) $<.c -o $<)

clean:
	@(echo CLEAN; $(RM) $(BINS))
