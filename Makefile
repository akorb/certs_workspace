CC=gcc
CFLAGS=-g -I /usr/include/mbedtls2
LDFLAGS=-l:libmbedtls.so.2.28.3 -l:libmbedx509.so.2.28.3 -l:libmbedcrypto.so.2.28.3

.PHONY: all
all:
	$(CC) -o main $(CFLAGS) $(LDFLAGS) main.c
