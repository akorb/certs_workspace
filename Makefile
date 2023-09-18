OPTEE_ROOT     ?= ..
ALIAS_CERT_EXT_PATH ?= $(OPTEE_ROOT)/alias_cert_extension
MBEDTLS_PATH   ?= $(OPTEE_ROOT)/mbedtls

KEYS_IN_FOLDER   = 1_keys
CERTS_OUT_FOLDER = 2_certs
HEADER_OUT       = 3_headers

HEADER_FILES = cert_root.h \
               cert_chain.h \
               boot_chain_final_key.h \
               TCIs.h
HEADER_INSTALL_TARGETS = $(addprefix install-, $(HEADER_FILES))

include $(ALIAS_CERT_EXT_PATH)/Makefile.am.libasncodec

# Note the order of this list matters
# See https://github.com/Mbed-TLS/mbedtls#compiling
MBEDTLS_LIBRARY_NAMES = libmbedtls.a libmbedx509.a libmbedcrypto.a
MBEDTLS_LIBRARY_PATHS = $(addprefix mbedtls/library/,$(MBEDTLS_LIBRARY_NAMES))

CC = gcc
CFLAGS  = -g
CFLAGS += -I $(ALIAS_CERT_EXT_PATH)
CFLAGS += -I mbedtls/include
CFLAGS += -I $(HEADER_OUT)
CFLAGS += -D CERTS_OUTPUT_FOLDER=\"$(CERTS_OUT_FOLDER)\"
CFLAGS += -D KEYS_INPUT_FOLDER=\"$(KEYS_IN_FOLDER)\"
CFLAGS += -Wall
CFLAGS += $(ASN_MODULE_CFLAGS)
LDFLAGS = -static

# First element must be root certificate
CHAIN = manufacturer \
		bl1 \
		bl2 \
		bl31 \
		bl32

KEY_FILES = $(addprefix $(KEYS_IN_FOLDER)/,   $(addsuffix .pem, $(CHAIN)))
CRT_FILES = $(addprefix $(CERTS_OUT_FOLDER)/, $(addsuffix .crt, $(CHAIN)))

.PHONY: all clean $(HEADER_INSTALL_TARGETS)

all: create_certificates $(addprefix $(HEADER_OUT)/, $(HEADER_FILES))

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

$(HEADER_OUT)/TCIs.h: templates/TCIs.h
	mkdir -p "$(@D)"
	cp $< $@

$(HEADER_OUT)/boot_chain_final_key.h: scripts/print_final_key_header.sh $(lastword $(KEY_FILES))
	mkdir -p $(@D)
	sh $< $(KEYS_IN_FOLDER) > $@ 

$(HEADER_OUT)/cert_root.h: scripts/print_root_certificate_header.sh $(firstword $(CRT_FILES))
	mkdir -p $(@D)
	sh $< $(CERTS_OUT_FOLDER) > $@

$(HEADER_OUT)/cert_chain.h: scripts/print_certificate_chain_header.sh $(wordlist 2, 100, $(CRT_FILES))
	mkdir -p $(@D)
	sh $< $(CERTS_OUT_FOLDER) > $@

create_certificates: create_certificates.c $(KEY_FILES) $(HEADER_OUT)/TCIs.h $(MBEDTLS_LIBRARY_PATHS)
	$(CC) -o $@ $(CFLAGS) \
	$(LDFLAGS) \
	$(addprefix $(ALIAS_CERT_EXT_PATH)/,$(ASN_MODULE_SRCS)) \
	$< $(MBEDTLS_LIBRARY_PATHS)

$(HEADER_INSTALL_TARGETS): install-%.h: $(HEADER_OUT)/%.h
	cp $< $(INSTALL_PATH)/$(notdir $<)

clean:
	$(MAKE) -C $(MBEDTLS_PATH) clean
	rm -rf $(KEY_FILES) $(CRT_FILES) create_certificates $(addprefix $(HEADER_OUT)/, $(HEADER_FILES)) mbedtls
	rmdir --ignore-fail-on-non-empty $(CERTS_OUT_FOLDER) $(HEADER_OUT) $(KEYS_IN_FOLDER) 2> /dev/null || true
