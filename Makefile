CC = cc

OPENSSL_PREFIX = /opt/homebrew/opt/openssl

CFLAGS = -Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib
LDLIBS = -lssl -lcrypto

TARGETS = client server

.PHONY: all clean

all: $(TARGETS)

client: client.c func.c func.h
	$(CC) $(CFLAGS) $(LDFLAGS) client.c func.c $(LDLIBS) -o client

server: server.c func.c func.h
	$(CC) $(CFLAGS) $(LDFLAGS) server.c func.c $(LDLIBS) -o server

clean:
	rm -f client server *.o
