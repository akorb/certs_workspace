OPTEE_ROOT     ?= ..
ASN1C_GEN_PATH ?= $(OPTEE_ROOT)/asn1c_generations
MBEDTLS_PATH   ?= $(OPTEE_ROOT)/mbedtls

KEYS_IN_FOLDER   = 1_keys
CERTS_OUT_FOLDER = 2_certs
HEADER_OUT      ?= 3_headers

include $(ASN1C_GEN_PATH)/Makefile.am.libasncodec

# Note the order of this list matters
# See https://github.com/Mbed-TLS/mbedtls#compiling
MBEDTLS_LIBRARY_NAMES = libmbedtls.a libmbedx509.a libmbedcrypto.a
MBEDTLS_LIBRARY_PATHS = $(addprefix mbedtls/library/,$(MBEDTLS_LIBRARY_NAMES))

CC = gcc
CFLAGS =
CFLAGS += -g
CFLAGS += -I $(ASN1C_GEN_PATH)
CFLAGS += -I mbedtls/include
CFLAGS += -I $(HEADER_OUT)
CFLAGS += -D CERTS_OUTPUT_FOLDER=\"$(CERTS_OUT_FOLDER)\"
CFLAGS += -D KEYS_INPUT_FOLDER=\"$(KEYS_IN_FOLDER)\"
CFLAGS += -Wall
CFLAGS += $(ASN_MODULE_CFLAGS)
LDFLAGS = -static

CHAIN = manufacturer \
		bl1 \
		bl2 \
		bl31 \
		bl32

KEY_FILES = $(addsuffix .pem, $(addprefix $(KEYS_IN_FOLDER)/,   $(CHAIN)))
CRT_FILES = $(addsuffix .crt, $(addprefix $(CERTS_OUT_FOLDER)/, $(CHAIN)))

.PHONY: all clean

all: create_certificates $(HEADER_OUT)/cert_root.h $(HEADER_OUT)/cert_chain.h $(HEADER_OUT)/boot_chain_keys.h $(HEADER_OUT)/TCIs.h

$(KEY_FILES):
	mkdir -p $(@D)
	openssl genrsa -out $@ 2048

$(CRT_FILES): create_certificates
	./create_certificates

mbedtls:
	cp -r $(MBEDTLS_PATH) .
	$(MAKE) -C mbedtls/library clean

$(MBEDTLS_LIBRARY_PATHS): | mbedtls
	$(MAKE) -C mbedtls/library CC="$(CC)" AR="$(AR)" $(@F)

$(HEADER_OUT)/TCIs.h: scripts/print_tci_header.sh
	mkdir -p $(@D)
	sh $< $(OPTEE_ROOT) > $@

$(HEADER_OUT)/boot_chain_keys.h: scripts/print_key_header.sh $(KEY_FILES)
	mkdir -p $(@D)
	sh $< $(KEYS_IN_FOLDER) > $@ 

$(HEADER_OUT)/cert_root.h: scripts/print_root_certificate_header.sh $(CRT_FILES)
	mkdir -p $(@D)
	sh $< $(CERTS_OUT_FOLDER) > $@

$(HEADER_OUT)/cert_chain.h: scripts/print_certificate_chain_header.sh $(CRT_FILES)
	mkdir -p $(@D)
	sh $< $(CERTS_OUT_FOLDER) > $@

create_certificates: create_certificates.c $(KEY_FILES) $(HEADER_OUT)/TCIs.h $(MBEDTLS_LIBRARY_PATHS)
	$(CC) -o $@ $(CFLAGS) \
	$(LDFLAGS) \
	$(addprefix $(ASN1C_GEN_PATH)/,$(ASN_MODULE_SRCS)) \
	$< $(MBEDTLS_LIBRARY_PATHS)

clean:
	$(MAKE) -C $(MBEDTLS_PATH) clean
	rm -rf $(KEY_FILES) $(CRT_FILES) create_certificates $(HEADER_OUT)/cert_root.h $(HEADER_OUT)/cert_chain.h $(HEADER_OUT)/boot_chain_keys.h $(HEADER_OUT)/TCIs.h mbedtls
	rmdir --ignore-fail-on-non-empty $(CERTS_OUT_FOLDER) $(HEADER_OUT) $(KEYS_IN_FOLDER) 2> /dev/null || true
