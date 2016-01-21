# -*- Makefile -*-

BINARIES = frontend
CFLAGS	 = -std=gnu99 -Wall -Wextra -O0 -ggdb3 -fstack-protector
LDFLAGS	 = -fPIC -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

all: $(BINARIES)

frontend: frontend.c ../rush.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f $(BINARIES)
