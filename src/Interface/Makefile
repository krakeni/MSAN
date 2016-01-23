# -*- Makefile -*-

BINARIES = interface
CFLAGS	 = -std=gnu99 -Wall -Wextra -O0 -ggdb3 -fstack-protector

all: $(BINARIES)

interface: client_interface.c
	$(CC) $(CFLAGS) $< -o $@ -lm

clean:
	rm -f $(BINARIES)
