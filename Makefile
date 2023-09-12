OPTEE_ROOT = $(error Please set the OPTEE_ROOT argument, e.g., with `make OPTEE_ROOT=~/optee`)
ASN1C_GEN_PATH ?= $(OPTEE_ROOT)/asn1c_generations
MBEDTLS_PATH ?= $(OPTEE_ROOT)/mbedtls

CC=gcc
CFLAGS=-g -I mbedtls/include -I $(ASN1C_GEN_PATH)
LDFLAGS=-static

KEYS_IN_FOLDER ?= keys_in
CERTS_OUT_FOLDER ?= certs_out
HEADER_OUT ?= headers_out

include $(ASN1C_GEN_PATH)/Makefile.am.libasncodec

KEY_FILES = $(KEYS_IN_FOLDER)/manufacturer.pem \
			$(KEYS_IN_FOLDER)/bl1.pem \
			$(KEYS_IN_FOLDER)/bl2.pem \
			$(KEYS_IN_FOLDER)/bl31.pem \
			$(KEYS_IN_FOLDER)/bl32.pem


.PHONY: all
all: create_certificates $(HEADER_OUT)/embedded_certs.h $(HEADER_OUT)/TCIs.h

%.pem:
	mkdir -p $(KEYS_IN_FOLDER)
	openssl genrsa -out $@ 2048

.PHONY: keys
keys: $(KEY_FILES)

.PHONY: execute_create_certificates
execute_create_certificates: create_certificates
	./create_certificates

mbedtls:
	$(MAKE) -C $(MBEDTLS_PATH) clean
	$(MAKE) -C $(MBEDTLS_PATH) install DESTDIR=$(shell pwd)/mbedtls
	$(MAKE) -C $(MBEDTLS_PATH) clean

$(HEADER_OUT)/TCIs.h: scripts/tcis_of_bootchain_as_c_arrays.sh
	mkdir -p $(HEADER_OUT)
	sh scripts/tcis_of_bootchain_as_c_arrays.sh $(OPTEE_ROOT) > $@

$(HEADER_OUT)/embedded_certs.h: scripts/certs_as_c_arrays.sh execute_create_certificates
	mkdir -p $(HEADER_OUT)
	sh scripts/certs_as_c_arrays.sh > $@

create_certificates: keys create_certificates.c $(HEADER_OUT)/TCIs.h mbedtls
	$(CC) -o $@ $(CFLAGS) \
	-I $(HEADER_OUT) $(LDFLAGS) \
	-D CERTS_OUTPUT_FOLDER=\"$(CERTS_OUT_FOLDER)\" \
	-D KEYS_INPUT_FOLDER=\"$(KEYS_IN_FOLDER)\" \
	$(ASN_MODULE_CFLAGS) $(addprefix $(ASN1C_GEN_PATH)/,$(ASN_MODULE_SRCS)) \
	$@.c \
	mbedtls/lib/libmbedtls.a mbedtls/lib/libmbedx509.a mbedtls/lib/libmbedcrypto.a

clean:
	rm -rf $(CERTS_OUT_FOLDER)/*.crt create_certificates $(HEADER_OUT)/TCIs.h $(HEADER_OUT)/embedded_certs.h $(HEADER_OUT)/TCIs.h mbedtls certs_out
	$(MAKE) -C $(MBEDTLS_PATH) clean
	rmdir --ignore-fail-on-non-empty $(CERTS_OUT_FOLDER) $(HEADER_OUT) 2> /dev/null || true

clean-all: clean
	rm -f $(KEYS_IN_FOLDER)/*.pem
	rmdir --ignore-fail-on-non-empty $(KEYS_IN_FOLDER) 2> /dev/null || true
