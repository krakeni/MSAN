# -*- Makefile -*-

CFLAGS	 = -std=gnu99 -Wall -Wextra -O0 -ggdb3 -fstack-protector
SSLLIB = -I/opt/ssl/include/ -L/opt/ssl/lib/ -lcrypto
SRC=src/lib.c src/handlers.c
OBJ=$(SRC:.c=.o)

all: backend frontend interface

backend: $(OBJ) src/backend.c
	$(CC) $(CFLAGS) $^ $(SSLLIB) -o $@ -lm

frontend: $(OBJ) src/frontend.c
	$(CC) $(CFLAGS) $^ $(SSLLIB) -o $@ -lm

interface: $(OBJ) src/client_interface.c
	$(CC) $(CFLAGS) $^ $(SSLLIB) -o $@ -lm

clean:
	rm -f interface backend frontend
	rm -f src/*.o
