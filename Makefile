# -*- Makefile -*-

CFLAGS	 = -std=gnu99 -Wall -Wextra -O0 -ggdb3 -fstack-protector
#SRC=src/lib.c
#OBJ=$(SRC:.c=.o)

all: backend frontend interface

backend: src/backend.c src/lib.c
	$(CC) $(CFLAGS) $< -o $@ -lm

frontend: src/frontend.c src/lib.c
	$(CC) $(CFLAGS) $< -o $@ -lm

interface: src/client_interface.c src/lib.c
	$(CC) $(CFLAGS) $< -o $@ -lm

clean:
	rm -f interface backend frontend
	rm -f src/*.o
