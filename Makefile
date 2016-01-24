# -*- Makefile -*-

CFLAGS	 = -std=gnu99 -Wall -Wextra -O0 -ggdb3 -fstack-protector
SRC=src/lib.c
OBJ=$(SRC:.c=.o)

all: backend frontend interface

backend: $(OBJ) src/backend.c
	$(CC) $(CFLAGS) $^ -o $@ -lm

frontend: $(OBJ) src/frontend.c
	$(CC) $(CFLAGS) $^ -o $@ -lm

interface: $(OBJ) src/client_interface.c
	$(CC) $(CFLAGS) $^ -o $@ -lm

clean:
	rm -f interface backend frontend
	rm -f src/*.o
