CC = cc

OPENSSL_PREFIX = /opt/homebrew/opt/openssl

CFLAGS = -Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib
LDLIBS = -lssl -lcrypto

TARGETS = client server

.PHONY: all clean

all: $(TARGETS)

client: client.c com.c com.h key.c key.h encrypt.c encrypt.h
	$(CC) $(CFLAGS) $(LDFLAGS) client.c com.c key.c encrypt.c $(LDLIBS) -o client

server: server.c com.c com.h key.c key.h encrypt.c encrypt.h 
	$(CC) $(CFLAGS) $(LDFLAGS) server.c com.c key.c encrypt.c $(LDLIBS) -o server
clean:
	rm -f client server *.o
