#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_X509_CRT_WRITE_C) ||                            \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||   \
    !defined(MBEDTLS_ERROR_C) || !defined(MBEDTLS_SHA256_C) ||       \
    !defined(MBEDTLS_PEM_WRITE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_X509_CRT_WRITE_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
                   "MBEDTLS_FS_IO and/or MBEDTLS_SHA256_C and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
                   "MBEDTLS_ERROR_C not defined.\n");
    mbedtls_exit(0);
}
#else

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DFL_SUBJECT_KEY "subject.key"
#define DFL_ISSUER_KEY "ca.key"
#define DFL_OUTPUT_FILENAME "cert.crt"
#define DFL_SUBJECT_NAME "CN=Cert,O=mbed TLS,C=UK"
#define DFL_ISSUER_NAME "CN=CA,O=mbed TLS,C=UK"
#define DFL_NOT_BEFORE "20230725000000"
#define DFL_NOT_AFTER "99991231235959"
#define DFL_SERIAL "1"
#define DFL_SELFSIGN 0
#define DFL_IS_CA 0
#define DFL_MAX_PATHLEN -1
#define DFL_KEY_USAGE 0
#define DFL_NS_CERT_TYPE 0
#define DFL_VERSION 3
#define DFL_AUTH_IDENT 1
#define DFL_SUBJ_IDENT 1
#define DFL_CONSTRAINTS 1
#define DFL_DIGEST MBEDTLS_MD_SHA256

/*
Generated via https://kjur.github.io/jsrsasign/tool/tool_asn1encoder.html with:

{
    "seq": [
        {
            "seq": [
                {
                    "oid": {
                        "oid": "2.23.133.5.4.100.6"
                    }
                }
            ]
        }
    ]
}
*/
static const uint8_t certificate_policy_val_IDevID[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x06};
static const uint8_t certificate_policy_val_LDevID[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x07};

static const uint8_t attestation_extension_value_preface[] = {
    0x30, 0x31, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20};

// SHA256, 256 Bits = 32 Bytes
#define TCI_LEN 32
#define CERTIFICATE_POLICY_VAL_LEN sizeof(certificate_policy_val_IDevID)

static const char dice_attestation_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};
static const uint8_t tci_bl1[TCI_LEN] = {0x4c, 0xce, 0xfa, 0x68, 0x7d, 0x38, 0xbe, 0x8f,
                                         0xe1, 0x85, 0xc0, 0xbf, 0x92, 0xb2, 0x8c, 0xdb,
                                         0x69, 0xe8, 0x27, 0xe0, 0xe2, 0x39, 0x20, 0xbe,
                                         0x2c, 0xcf, 0x4a, 0xb2, 0xba, 0x0d, 0xe9, 0x60};

/*
 * global options
 */
typedef struct cert_info
{
    const char *subject_key;    /* filename of the subject key file     */
    const char *issuer_key;     /* filename of the issuer key file      */
    const char *output_file;    /* where to store the constructed CRT   */
    const char *subject_name;   /* subject name for certificate         */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string                 */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    int authority_identifier;   /* add authority identifier to CRT      */
    int subject_identifier;     /* add subject identifier to CRT        */
    int basic_constraints;      /* add basic constraints ext to CRT     */
    int version;                /* CRT version                          */
    mbedtls_md_type_t md;       /* Hash used for signing                */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
    const uint8_t *certificate_policy_val;
    const uint8_t *tci; /* Trused Componentent Identifier aka Firmware ID (FWID)*/
} cert_info;

int write_certificate(mbedtls_x509write_cert *crt, const char *output_file)
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset(output_buf, 0, 4096);
    if ((ret = mbedtls_x509write_crt_pem(crt, output_buf, 4096,
                                         NULL, NULL)) < 0)
    {
        return ret;
    }

    len = strlen((char *)output_buf);

    if ((f = fopen(output_file, "w")) == NULL)
    {
        return -1;
    }

    if (fwrite(output_buf, 1, len, f) != len)
    {
        fclose(f);
        return -1;
    }

    fclose(f);

    return 0;
}

// https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
// This macro works only when each number is below 128
// Otherwise, use this converter: https://misc.daniel-marschall.de/asn.1/oid-converter/online.php
// Just remove the first two octets of the output, since they are ASN.1 encoding specific
#define OID(o1, o2, ...)          \
    {                             \
        40 * o1 + o2, __VA_ARGS__ \
    }

int create_certificate(cert_info ci)
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                       *subject_key = &loaded_subject_key;
    char buf[1024];
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;

    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&loaded_issuer_key);
    mbedtls_pk_init(&loaded_subject_key);
    mbedtls_mpi_init(&serial);
    memset(buf, 0, 1024);

    mbedtls_printf("\n");

    // Parse serial to MPI
    //
    mbedtls_printf("  . Reading serial number...");
    fflush(stdout);

    if ((ret = mbedtls_mpi_read_string(&serial, 10, ci.serial)) != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_mpi_read_string "
                       "returned -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 1.1. Load the keys
     */
    if (!ci.selfsign)
    {
        mbedtls_printf("  . Loading the subject key ...");
        fflush(stdout);

        ret = mbedtls_pk_parse_keyfile(&loaded_subject_key, ci.subject_key,
                                       NULL);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, 1024);
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile "
                           "returned -0x%04x - %s\n\n",
                           (unsigned int)-ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    mbedtls_printf("  . Loading the issuer key ...");
    fflush(stdout);

    ret = mbedtls_pk_parse_keyfile(&loaded_issuer_key, ci.issuer_key,
                                   NULL);
    if (ret != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile "
                       "returned -x%02x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (ci.selfsign)
    {
        ci.subject_name = ci.issuer_name;
        subject_key = issuer_key;
    }

    mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

    /*
     * 1.0. Check the names for validity
     */
    if ((ret = mbedtls_x509write_crt_set_subject_name(&crt, ci.subject_name)) != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_subject_name "
                       "returned -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, ci.issuer_name)) != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_issuer_name "
                       "returned -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    mbedtls_printf("  . Setting certificate values ...");
    fflush(stdout);

    mbedtls_x509write_crt_set_version(&crt, ci.version);
    mbedtls_x509write_crt_set_md_alg(&crt, ci.md);

    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_serial "
                       "returned -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity(&crt, ci.not_before, ci.not_after);
    if (ret != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_validity "
                       "returned -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.basic_constraints != 0)
    {
        mbedtls_printf("  . Adding the Basic Constraints extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_basic_constraints(&crt, ci.is_ca,
                                                          ci.max_pathlen);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, 1024);
            mbedtls_printf(" failed\n  !  x509write_crt_set_basic_constraints "
                           "returned -0x%04x - %s\n\n",
                           (unsigned int)-ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

#if defined(MBEDTLS_SHA1_C)
    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.subject_identifier != 0)
    {
        mbedtls_printf("  . Adding the Subject Key Identifier ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, 1024);
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_subject"
                           "_key_identifier returned -0x%04x - %s\n\n",
                           (unsigned int)-ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.authority_identifier != 0)
    {
        mbedtls_printf("  . Adding the Authority Key Identifier ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, 1024);
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_authority_"
                           "key_identifier returned -0x%04x - %s\n\n",
                           (unsigned int)-ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }
#endif /* MBEDTLS_SHA1_C */

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.key_usage != 0)
    {
        mbedtls_printf("  . Adding the Key Usage extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_key_usage(&crt, ci.key_usage);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, 1024);
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_key_usage "
                           "returned -0x%04x - %s\n\n",
                           (unsigned int)-ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.ns_cert_type != 0)
    {
        mbedtls_printf("  . Adding the NS Cert Type extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_ns_cert_type(&crt, ci.ns_cert_type);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, 1024);
            mbedtls_printf(" failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
                           "returned -0x%04x - %s\n\n",
                           (unsigned int)-ret, buf);
            goto exit;
        }

        mbedtls_printf(" ok\n");
    }

    if (ci.certificate_policy_val)
    {
        mbedtls_printf("  . Add certificate policy extension...");

        mbedtls_x509write_crt_set_extension(&crt, MBEDTLS_OID_CERTIFICATE_POLICIES, MBEDTLS_OID_SIZE(MBEDTLS_OID_CERTIFICATE_POLICIES), 0, ci.certificate_policy_val, CERTIFICATE_POLICY_VAL_LEN);
        mbedtls_printf(" ok\n");
    }

    if (ci.tci)
    {
        mbedtls_printf("  . Add DICE attestation extension...");
        uint8_t attestation_extension_value[sizeof(attestation_extension_value_preface) + TCI_LEN];

        // Set preface
        memcpy(attestation_extension_value, attestation_extension_value_preface, sizeof(attestation_extension_value_preface));
        // Set TCI
        memcpy(&attestation_extension_value[sizeof(attestation_extension_value_preface)], ci.tci, TCI_LEN);

        mbedtls_x509write_crt_set_extension(&crt, dice_attestation_oid, sizeof(dice_attestation_oid), 0, attestation_extension_value, sizeof(attestation_extension_value));
        mbedtls_printf(" ok\n");
    }

    /*
     * 1.2. Writing the certificate
     */
    mbedtls_printf("  . Writing the certificate...");
    fflush(stdout);

    if ((ret = write_certificate(&crt, ci.output_file)) != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  write_certificate -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&loaded_subject_key);
    mbedtls_pk_free(&loaded_issuer_key);
    mbedtls_mpi_free(&serial);

    return exit_code;
}

void verify()
{
    // From https://stackoverflow.com/a/72722115/2050020

    int32_t r;
    uint32_t flags = 0;

    mbedtls_x509_crt ca, chain;

    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&chain);

    do
    {
        r = mbedtls_x509_crt_parse_file(&ca, "manufacturer.crt");
        if (EXIT_SUCCESS != r)
            break;

        r = mbedtls_x509_crt_parse_file(&chain, "bl1.crt");
        if (EXIT_SUCCESS != r)
            break;

        r = mbedtls_x509_crt_parse_file(&chain, "bl2.crt");
        if (EXIT_SUCCESS != r)
            break;

        r = mbedtls_x509_crt_parse_file(&chain, "bl31.crt");
        if (EXIT_SUCCESS != r)
            break;

        r = mbedtls_x509_crt_parse_file(&chain, "bl32.crt");
        if (EXIT_SUCCESS != r)
            break;

        r = mbedtls_x509_crt_parse_file(&chain, "ekcert.crt");
        if (EXIT_SUCCESS != r)
            break;

        if ((r = mbedtls_x509_crt_verify(&chain, &ca, NULL, NULL, &flags,
                                         NULL, NULL)) != 0)
        {
            char vrfy_buf[512];
            mbedtls_printf(" failed\n");
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            mbedtls_printf("%s\n", vrfy_buf);
        }
        else
            mbedtls_printf(" Verify OK\n");

    } while (0);

    if (0 != r)
        mbedtls_printf("Error: 0x%04x; flag: %u\n", r, flags);
}

static const uint8_t crt_bl32[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADA7MQwwCgYDVQQDDANCTDEx\n\
HTAbBgNVBAoMFEVMMyBSdW50aW1lIFNvZnR3YXJlMQwwCgYDVQQGEwNHRVIwIBcN\n\
MjMwNzI1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDAxDDAKBgNVBAMMA0JMMTES\n\
MBAGA1UECgwJT1AtVEVFIE9TMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQCZHmB/jGls35xWyGtguxIRIvaX1ncTBdKyrXPbBm5T\n\
+7CraPLgQpLVhAN1oN67XOXNNLiaKCb0/I2MgLsq0+SI1YYPZU5nSRZ9rVVtTMym\n\
8AtASwPjDOBJm/s6Hp9+Q8gxHazYEH9BCc2v6j9A3kjV6cslynaiwZvN4K+aix6k\n\
1mdoTitJylhVN1k/1a2ZsFHicLPnWPtXgOoZ0PDdN6YLZbS0Ka6BdAEuKTVH/UHz\n\
4bVz3eAsLM881cIHyAzhauPanpcs2FuAC6HOSn6AXPuTfiBcTuwFFw0PFVIGhZaW\n\
/bptcc3elB60Mqy5EwjeJaV2C4/Bc4LoqqDFuJl8ES5jAgMBAAGjgbkwgbYwDwYD\n\
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUG5tZTkK8L26sIIQ1mWTom4eb6t8wHwYD\n\
VR0jBBgwFoAUs3Ke3i8pF+A9ceYDmcHSshvYnFIwDgYDVR0PAQH/BAQDAgIEMBQG\n\
A1UdIAQNMAswCQYHZ4EFBQRkBzA9BgZngQUFBAEEMzAxpi8wLQYJYIZIAWUDBAIB\n\
BCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDANBgkqhkiG9w0BAQsF\n\
AAOCAQEAgqPZLeICZ9AKjTK3V+NCv6LuPuvx9ZRTIPv3Tfwmr36qfCQ3G/cwAoUR\n\
uzjr4XHl4ABFfiIB9DRzmQwkzpQuYWZtW+Z6zDZ4BpZwFnayaMXuAvk+uC/Z4D/V\n\
GZCXBV25RodNpiYrrAJJPvOjStc82P5YOsqStOh07jtIcI0M33Vk20VrrKpQ/HTK\n\
l2nwcziFaZBABpjRHjvFSFPUjeRzv8CVIKuaRUy8TOqLS2xOr2TW/u1i7urrYW3N\n\
TnP85FFwP4YajI91iDzI9UTjRnrhe1k+wmNL/EaYt2Hm5N3bct5p0Mxeff1r87z7\n\
ACi2j3Jaf1J94i2Wz6GlTRRBYYMuWw==\n\
-----END CERTIFICATE-----";

static const uint8_t key_bl32[] =
"-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZHmB/jGls35xW\n\
yGtguxIRIvaX1ncTBdKyrXPbBm5T+7CraPLgQpLVhAN1oN67XOXNNLiaKCb0/I2M\n\
gLsq0+SI1YYPZU5nSRZ9rVVtTMym8AtASwPjDOBJm/s6Hp9+Q8gxHazYEH9BCc2v\n\
6j9A3kjV6cslynaiwZvN4K+aix6k1mdoTitJylhVN1k/1a2ZsFHicLPnWPtXgOoZ\n\
0PDdN6YLZbS0Ka6BdAEuKTVH/UHz4bVz3eAsLM881cIHyAzhauPanpcs2FuAC6HO\n\
Sn6AXPuTfiBcTuwFFw0PFVIGhZaW/bptcc3elB60Mqy5EwjeJaV2C4/Bc4LoqqDF\n\
uJl8ES5jAgMBAAECggEANbBIjsCpoLLBa06IFBlUCu0zAOeCxglHKT6XfoeBPPJm\n\
Lpw0eTzupm5NFjwrjQ/URgFD702/5yv85/SlbC1zFyWjhZd0h9PBTpzt9M62fZxy\n\
nX8QJFc596V5UBY3v3q94bbxiaszK5dn51RgDHtEl7kL8brNoWD4pBYyDKLWQl6e\n\
eFyOpa3RQRny3cp02qK+QQjgmrdrSjP6rPzk6rF3FpypWhBU9iPPTw61+4YvRpK5\n\
7ZtQfxtup9UPX5oepvARIxXt3nWExICr5yRfMObJ4IR9qnszR4/yXMccRtMHPrxF\n\
t1V+iIy89QuBkfPyhXqs9nnlLBLbD1E6AjA3EEu4TQKBgQDG6ULiCWz6qxSodibM\n\
9vqzmBsEIrl5++NTe7xU0jpwP3GFZCHzRlMN74jJODBpuIwvFavfMzm2cVePB9Mw\n\
HjK4yv2V4AOBXarPKLUwoN2y30n2A7UMZNVv6P+s3XKuXOJTI8E/k3NUOt0H00kD\n\
HlEPlnK9iY3UqwJuf2K3U38STQKBgQDFEJIDFMohR3aJ9JYtfIIP25NkOtJzOwQQ\n\
eJ7I18oPxKjhxe6kmu7NadcD2Lho7lwWJyXo55JIvuKfKlcP1FFC08sVLmzSIqEq\n\
QbfKgiWRSocadz/sX4uDqaWg0QGBTzIQQhWC5AyBFWrCaK1WGC60wLkX2JGbvvRX\n\
vDQgFQK7bwKBgAbiM6pW4SqbmQ9rZ1RYh7yHWwf9m6WZDfjpo07cJ6GS0H7pRDOD\n\
D4S/8V/lTeeat185xMTopOqnaXxNrQVRRjgW7kethPGJKEwbAIo6RvHVwF1/K1jO\n\
dIR278Ivt7RJCpwN9LYaiDc2AkgvC6vL9MoxTq84f2wIrwDb77KgdRlRAoGAJto6\n\
f2ME6wTE6TQQu80Vc3zuFU/HmDJlfb3aSGzLCMrUJRc6Erf9JwCcBMUgrod4HmH/\n\
hmjJnZAM7CaT3aoVj2BkZLuvdsqfDc7BJqr8LyYLdvtV3guEXSQAZLFwY4cyrqPo\n\
y9KcaILJdqTer9+6raZll776DkPatsWDXWPnEv8CgYEArXmRBpTf/f4Emu7wk8Dn\n\
ZvWDaeDatH/iCS6DzS9ZGsIwaBk0C1CKZfE9vjfW4TCs79mowdVsP8LLdcEGva8A\n\
SO9u/JAbum//Pcn0HuPwNT7W3o2nai/u5MYp670H2Y9PYNc8wIrkf1Fswp0LDElw\n\
LEcjyM3xY1lzeNnNR7YORnI=\n\
-----END PRIVATE KEY-----";

int main(void)
{
    mbedtls_x509_crt ctx_tmp;
    mbedtls_x509_crt_init(&ctx_tmp);
    mbedtls_x509_crt_parse(&ctx_tmp, crt_bl32, sizeof(crt_bl32));

    char buf[100] = { 0 };
    mbedtls_x509_dn_gets(buf, sizeof(buf), &(ctx_tmp.issuer));

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_pk_parse_key(&key, key_bl32, sizeof(key_bl32), NULL, 0);
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

    const char name_manufacturer[] = "CN=Manufacturer,O=Cool company,C=GER";
    const char name_bl1[] = "CN=BL1,O=AP Trusted ROM,C=GER";
    const char name_bl2[] = "CN=BL2,O=Trusted Boot Firmware,C=GER";
    const char name_bl31[] = "CN=BL31,O=EL3 Runtime Software,C=GER";
    const char name_bl32[] = "CN=BL32,O=OP-TEE OS,C=GER";
    const char name_ekcert[] = "CN=EKCert,O=TPM EK,C=GER";

    cert_info cis[6];
    memset(cis, 0, sizeof(cis));
    cert_info *cert_info_manufacturer = &cis[0];
    cert_info *cert_info_bl1 = &cis[1];
    cert_info *cert_info_bl2 = &cis[2];
    cert_info *cert_info_bl31 = &cis[3];
    cert_info *cert_info_bl32 = &cis[4];
    cert_info *cert_info_ekcert = &cis[5];

    cert_info_manufacturer->subject_key = "manufacturer.pem";
    cert_info_manufacturer->issuer_key = "manufacturer.pem";
    cert_info_manufacturer->output_file = "manufacturer.crt";
    cert_info_manufacturer->subject_name = name_manufacturer;
    cert_info_manufacturer->issuer_name = name_manufacturer;
    cert_info_manufacturer->not_before = DFL_NOT_BEFORE;
    cert_info_manufacturer->not_after = DFL_NOT_AFTER;
    cert_info_manufacturer->serial = DFL_SERIAL;
    cert_info_manufacturer->selfsign = 1;
    cert_info_manufacturer->is_ca = 1;
    cert_info_manufacturer->max_pathlen = DFL_MAX_PATHLEN;
    cert_info_manufacturer->key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
    cert_info_manufacturer->ns_cert_type = DFL_NS_CERT_TYPE;
    cert_info_manufacturer->version = DFL_VERSION - 1;
    cert_info_manufacturer->md = DFL_DIGEST;
    cert_info_manufacturer->subject_identifier = DFL_SUBJ_IDENT;
    cert_info_manufacturer->authority_identifier = DFL_AUTH_IDENT;
    cert_info_manufacturer->basic_constraints = DFL_CONSTRAINTS;

    cert_info_bl1->subject_key = "bl1.pem";
    cert_info_bl1->issuer_key = "manufacturer.pem";
    cert_info_bl1->output_file = "bl1.crt";
    cert_info_bl1->subject_name = name_bl1;
    cert_info_bl1->issuer_name = name_manufacturer;
    cert_info_bl1->not_before = DFL_NOT_BEFORE;
    cert_info_bl1->not_after = DFL_NOT_AFTER;
    cert_info_bl1->serial = DFL_SERIAL;
    cert_info_bl1->selfsign = 0;
    cert_info_bl1->is_ca = 1;
    cert_info_bl1->max_pathlen = DFL_MAX_PATHLEN;
    cert_info_bl1->key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
    cert_info_bl1->ns_cert_type = DFL_NS_CERT_TYPE;
    cert_info_bl1->version = DFL_VERSION - 1;
    cert_info_bl1->md = DFL_DIGEST;
    cert_info_bl1->subject_identifier = DFL_SUBJ_IDENT;
    cert_info_bl1->authority_identifier = DFL_AUTH_IDENT;
    cert_info_bl1->basic_constraints = DFL_CONSTRAINTS;
    cert_info_bl1->certificate_policy_val = certificate_policy_val_IDevID;
    cert_info_bl1->tci = tci_bl1;

    cert_info_bl2->subject_key = "bl2.pem";
    cert_info_bl2->issuer_key = "bl1.pem";
    cert_info_bl2->output_file = "bl2.crt";
    cert_info_bl2->subject_name = name_bl2;
    cert_info_bl2->issuer_name = name_bl1;
    cert_info_bl2->not_before = DFL_NOT_BEFORE;
    cert_info_bl2->not_after = DFL_NOT_AFTER;
    cert_info_bl2->serial = DFL_SERIAL;
    cert_info_bl2->selfsign = 0;
    cert_info_bl2->is_ca = 1;
    cert_info_bl2->max_pathlen = DFL_MAX_PATHLEN;
    cert_info_bl2->key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
    cert_info_bl2->ns_cert_type = DFL_NS_CERT_TYPE;
    cert_info_bl2->version = DFL_VERSION - 1;
    cert_info_bl2->md = DFL_DIGEST;
    cert_info_bl2->subject_identifier = DFL_SUBJ_IDENT;
    cert_info_bl2->authority_identifier = DFL_AUTH_IDENT;
    cert_info_bl2->basic_constraints = DFL_CONSTRAINTS;
    cert_info_bl2->certificate_policy_val = certificate_policy_val_LDevID;
    cert_info_bl2->tci = tci_bl1;

    cert_info_bl31->subject_key = "bl31.pem";
    cert_info_bl31->issuer_key = "bl2.pem";
    cert_info_bl31->output_file = "bl31.crt";
    cert_info_bl31->subject_name = name_bl31;
    cert_info_bl31->issuer_name = name_bl2;
    cert_info_bl31->not_before = DFL_NOT_BEFORE;
    cert_info_bl31->not_after = DFL_NOT_AFTER;
    cert_info_bl31->serial = DFL_SERIAL;
    cert_info_bl31->selfsign = 0;
    cert_info_bl31->is_ca = 1;
    cert_info_bl31->max_pathlen = DFL_MAX_PATHLEN;
    cert_info_bl31->key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
    cert_info_bl31->ns_cert_type = DFL_NS_CERT_TYPE;
    cert_info_bl31->version = DFL_VERSION - 1;
    cert_info_bl31->md = DFL_DIGEST;
    cert_info_bl31->subject_identifier = DFL_SUBJ_IDENT;
    cert_info_bl31->authority_identifier = DFL_AUTH_IDENT;
    cert_info_bl31->basic_constraints = DFL_CONSTRAINTS;
    cert_info_bl31->certificate_policy_val = certificate_policy_val_LDevID;
    cert_info_bl31->tci = tci_bl1;

    cert_info_bl32->subject_key = "bl32.pem";
    cert_info_bl32->issuer_key = "bl31.pem";
    cert_info_bl32->output_file = "bl32.crt";
    cert_info_bl32->subject_name = name_bl32;
    cert_info_bl32->issuer_name = name_bl31;
    cert_info_bl32->not_before = DFL_NOT_BEFORE;
    cert_info_bl32->not_after = DFL_NOT_AFTER;
    cert_info_bl32->serial = DFL_SERIAL;
    cert_info_bl32->selfsign = 0;
    cert_info_bl32->is_ca = 1;
    cert_info_bl32->max_pathlen = DFL_MAX_PATHLEN;
    cert_info_bl32->key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
    cert_info_bl32->ns_cert_type = DFL_NS_CERT_TYPE;
    cert_info_bl32->version = DFL_VERSION - 1;
    cert_info_bl32->md = DFL_DIGEST;
    cert_info_bl32->subject_identifier = DFL_SUBJ_IDENT;
    cert_info_bl32->authority_identifier = DFL_AUTH_IDENT;
    cert_info_bl32->basic_constraints = DFL_CONSTRAINTS;
    cert_info_bl32->certificate_policy_val = certificate_policy_val_LDevID;
    cert_info_bl32->tci = tci_bl1;

    cert_info_ekcert->subject_key = "ekcert.pem";
    cert_info_ekcert->issuer_key = "bl32.pem";
    cert_info_ekcert->output_file = "ekcert.crt";
    cert_info_ekcert->subject_name = name_ekcert;
    cert_info_ekcert->issuer_name = name_bl32;
    cert_info_ekcert->not_before = DFL_NOT_BEFORE;
    cert_info_ekcert->not_after = DFL_NOT_AFTER;
    cert_info_ekcert->serial = DFL_SERIAL;
    cert_info_ekcert->selfsign = 0;
    cert_info_ekcert->is_ca = 0;
    cert_info_ekcert->max_pathlen = DFL_MAX_PATHLEN;
    cert_info_ekcert->key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
    cert_info_ekcert->ns_cert_type = DFL_NS_CERT_TYPE;
    cert_info_ekcert->version = DFL_VERSION - 1;
    cert_info_ekcert->md = DFL_DIGEST;
    cert_info_ekcert->subject_identifier = DFL_SUBJ_IDENT;
    cert_info_ekcert->authority_identifier = DFL_AUTH_IDENT;
    cert_info_ekcert->basic_constraints = DFL_CONSTRAINTS;
    cert_info_ekcert->certificate_policy_val = certificate_policy_val_LDevID;
    cert_info_ekcert->tci = tci_bl1;

    int exit_code;
    for (int i = 0; i < sizeof(cis) / sizeof(cis[0]); i++)
    {
        exit_code = create_certificate(cis[i]);
        if (exit_code != 0)
        {
            mbedtls_exit(exit_code);
        }
    }

    verify();

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&     \
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C && \
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */
