CC=gcc
CFLAGS=-g -I /usr/include/mbedtls2 -I gen
LDFLAGS=-l:libmbedtls.so.2.28.4 -l:libmbedx509.so.2.28.4 -l:libmbedcrypto.so.2.28.4

OPTEE_ROOT = $(error Please set the OPTEE_ROOT argument, e.g., with `make OPTEE_ROOT=~/optee`)
CERTS_IN_FOLDER=keys_in
CERTS_OUT_FOLDER=certs_out

include gen/Makefile.am.libasncodec

.PHONY: all
all: main

TCIs.h:
	sh scripts/tcis_of_bootchain_as_c_arrays.sh $(OPTEE_ROOT) > $@

main: main.c TCIs.h
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(ASN_MODULE_CFLAGS) $(ASN_MODULE_SRCS) main.c

clean:
	rm -f $(CERTS_OUT_FOLDER)/*.crt main TCIs.h

clean-all: clean
	rm -f $(CERTS_IN_FOLDER)/*.pem
