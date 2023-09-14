OPTEE_ROOT = $(error Please set the OPTEE_ROOT argument, e.g., with `make OPTEE_ROOT=~/optee`)
ASN1C_GEN_PATH ?= $(OPTEE_ROOT)/asn1c_generations
MBEDTLS_PATH ?= $(OPTEE_ROOT)/mbedtls

KEYS_IN_FOLDER ?= keys_in
CERTS_OUT_FOLDER ?= certs_out
HEADER_OUT ?= headers_out

include $(ASN1C_GEN_PATH)/Makefile.am.libasncodec

CC=gcc
CFLAGS=-g -I mbedtls/include -I $(ASN1C_GEN_PATH)
CFLAGS += -I $(HEADER_OUT)
CFLAGS += -D CERTS_OUTPUT_FOLDER=\"$(CERTS_OUT_FOLDER)\"
CFLAGS += -D KEYS_INPUT_FOLDER=\"$(KEYS_IN_FOLDER)\"
CFLAGS += -Wall
CFLAGS += $(ASN_MODULE_CFLAGS)
LDFLAGS=-static


KEY_FILES = $(KEYS_IN_FOLDER)/manufacturer.pem \
			$(KEYS_IN_FOLDER)/bl1.pem \
			$(KEYS_IN_FOLDER)/bl2.pem \
			$(KEYS_IN_FOLDER)/bl31.pem \
			$(KEYS_IN_FOLDER)/bl32.pem


.PHONY: all keys execute_create_certificates clean clean-all

all: create_certificates $(HEADER_OUT)/cert_root.h $(HEADER_OUT)/cert_chain.h $(HEADER_OUT)/boot_chain_keys.h $(HEADER_OUT)/TCIs.h

%.pem:
	mkdir -p $(KEYS_IN_FOLDER)
	openssl genrsa -out $@ 2048

keys: $(KEY_FILES)

execute_create_certificates: create_certificates
	./create_certificates

mbedtls:
	$(MAKE) -C $(MBEDTLS_PATH) clean
	$(MAKE) -C $(MBEDTLS_PATH) install DESTDIR=$(shell pwd)/mbedtls
	$(MAKE) -C $(MBEDTLS_PATH) clean

$(HEADER_OUT)/TCIs.h: scripts/print_tci_header.sh
	mkdir -p $(HEADER_OUT)
	sh $< $(OPTEE_ROOT) > $@

$(HEADER_OUT)/boot_chain_keys.h: scripts/print_key_header.sh
	mkdir -p $(HEADER_OUT)
	sh $< $(KEYS_IN_FOLDER) > $@ 

$(HEADER_OUT)/cert_root.h: scripts/print_root_certificate_header.sh execute_create_certificates
	mkdir -p $(HEADER_OUT)
	sh $< $(CERTS_OUT_FOLDER) > $@

$(HEADER_OUT)/cert_chain.h: scripts/print_certificate_chain_header.sh execute_create_certificates
	mkdir -p $(HEADER_OUT)
	sh $< $(CERTS_OUT_FOLDER) > $@

create_certificates: create_certificates.c keys $(HEADER_OUT)/TCIs.h mbedtls
	$(CC) -o $@ $(CFLAGS) \
	$(LDFLAGS) \
	$(addprefix $(ASN1C_GEN_PATH)/,$(ASN_MODULE_SRCS)) \
	$< \
	mbedtls/lib/libmbedtls.a mbedtls/lib/libmbedx509.a mbedtls/lib/libmbedcrypto.a

clean:
	rm -rf $(CERTS_OUT_FOLDER)/*.crt create_certificates $(HEADER_OUT)/cert_root.h $(HEADER_OUT)/cert_chain.h $(HEADER_OUT)/boot_chain_keys.h $(HEADER_OUT)/TCIs.h mbedtls certs_out
	$(MAKE) -C $(MBEDTLS_PATH) clean
	rmdir --ignore-fail-on-non-empty $(CERTS_OUT_FOLDER) $(HEADER_OUT) 2> /dev/null || true
	rm -f $(KEYS_IN_FOLDER)/*.pem
	rmdir --ignore-fail-on-non-empty $(KEYS_IN_FOLDER) 2> /dev/null || true
