CC=gcc
CFLAGS=-g -I /usr/include/mbedtls2 -I gen
LDFLAGS=-l:libmbedtls.so.2.28.4 -l:libmbedx509.so.2.28.4 -l:libmbedcrypto.so.2.28.4

include gen/Makefile.am.libasncodec

.PHONY: all
all:
	$(CC) -o main $(CFLAGS) $(LDFLAGS) $(ASN_MODULE_CFLAGS) $(ASN_MODULE_SRCS) main.c

clean:
	rm -f *.crt *.pem  main
