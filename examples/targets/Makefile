CC ?= gcc
CFLAGS ?= -fno-stack-protector

BINS = badcode1

all: $(BINS)
	@(echo CC $<; $(CC) $(CFLAGS) $<.c -o $<)

clean:
	@(echo CLEAN; $(RM) $(BINS))
