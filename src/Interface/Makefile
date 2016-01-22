# -*- Makefile -*-

BINARIES = interface
CFLAGS	 = -std=gnu99 -Wall -Wextra -O0 -ggdb3 -fstack-protector -lm

all: $(BINARIES)

interface: client_interface.c 
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(BINARIES)
