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
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
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
#define DFL_NOT_BEFORE "20010101000000"
#define DFL_NOT_AFTER "20301231235959"
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
} cert_info;

int write_certificate(mbedtls_x509write_cert *crt, const char *output_file,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng)
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset(output_buf, 0, 4096);
    if ((ret = mbedtls_x509write_crt_pem(crt, output_buf, 4096,
                                         f_rng, p_rng)) < 0)
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
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                       *subject_key = &loaded_subject_key;
    char buf[1024];
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "crt example app";

    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&loaded_issuer_key);
    mbedtls_pk_init(&loaded_subject_key);
    mbedtls_mpi_init(&serial);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&issuer_crt);
    memset(buf, 0, 1024);

    mbedtls_printf("\n");

    /*
     * 0. Seed the PRNG
     */
    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  mbedtls_ctr_drbg_seed returned %d - %s\n",
                       ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

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

    mbedtls_printf("  . Add extension...");

    /*
    Generated via https://kjur.github.io/jsrsasign/tool/tool_asn1encoder.html with:

    {
        "seq": [
            {
                "seq": [
                    {
                        "oid": {
                            "oid": "2.23.133.5.4.100.9"
                        }
                    }
                ]
            }
        ]
    }
    */
    const uint8_t certificate_policy_val[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x09};
    mbedtls_x509write_crt_set_extension(&crt, MBEDTLS_OID_CERTIFICATE_POLICIES, MBEDTLS_OID_SIZE(MBEDTLS_OID_CERTIFICATE_POLICIES), 0, certificate_policy_val, sizeof(certificate_policy_val));

    uint8_t attestation_extension_data[19 + 32] = {
        0x30, 0x31, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20
        // The remaining 32 bytes (containing the hash) are not set yet
    };

    const char hash[32] = {0x4c, 0xce, 0xfa, 0x68, 0x7d, 0x38, 0xbe, 0x8f,
                           0xe1, 0x85, 0xc0, 0xbf, 0x92, 0xb2, 0x8c, 0xdb,
                           0x69, 0xe8, 0x27, 0xe0, 0xe2, 0x39, 0x20, 0xbe,
                           0x2c, 0xcf, 0x4a, 0xb2, 0xba, 0x0d, 0xe9, 0x60};

    const char attestation_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};
    memcpy(&attestation_extension_data[19], hash, 32);
    mbedtls_x509write_crt_set_extension(&crt, attestation_oid, sizeof(attestation_oid), 0, attestation_extension_data, sizeof(attestation_extension_data));
    mbedtls_printf(" ok\n");

    /*
     * 1.2. Writing the certificate
     */
    mbedtls_printf("  . Writing the certificate...");
    fflush(stdout);

    if ((ret = write_certificate(&crt, ci.output_file,
                                 mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        mbedtls_strerror(ret, buf, 1024);
        mbedtls_printf(" failed\n  !  write_certificate -0x%04x - %s\n\n",
                       (unsigned int)-ret, buf);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_x509_crt_free(&issuer_crt);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&loaded_subject_key);
    mbedtls_pk_free(&loaded_issuer_key);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return exit_code;
}

int main(void)
{
    cert_info ci;
    ci.subject_key = DFL_SUBJECT_KEY;
    ci.issuer_key = DFL_ISSUER_KEY;
    ci.output_file = DFL_OUTPUT_FILENAME;
    ci.subject_name = DFL_SUBJECT_NAME;
    ci.issuer_name = DFL_ISSUER_NAME;
    ci.not_before = DFL_NOT_BEFORE;
    ci.not_after = DFL_NOT_AFTER;
    ci.serial = DFL_SERIAL;
    ci.selfsign = DFL_SELFSIGN;
    ci.is_ca = DFL_IS_CA;
    ci.max_pathlen = DFL_MAX_PATHLEN;
    ci.key_usage = DFL_KEY_USAGE;
    ci.ns_cert_type = DFL_NS_CERT_TYPE;
    ci.version = DFL_VERSION - 1;
    ci.md = DFL_DIGEST;
    ci.subject_identifier = DFL_SUBJ_IDENT;
    ci.authority_identifier = DFL_AUTH_IDENT;
    ci.basic_constraints = DFL_CONSTRAINTS;

    ci.subject_key = "key.pem";
    ci.issuer_key = "key.pem";

    printf("ci.subject_key = %s\n", ci.subject_key);
    printf("ci.issuer_key = %s\n", ci.issuer_key);
    printf("ci.output_file = %s\n", ci.output_file);
    printf("ci.subject_name = %s\n", ci.subject_name);
    printf("ci.issuer_name = %s\n", ci.issuer_name);
    printf("ci.not_before = %s\n", ci.not_before);
    printf("ci.not_after = %s\n", ci.not_after);
    printf("ci.serial = %p\n", ci.serial);
    printf("ci.selfsign = %d\n", ci.selfsign);
    printf("ci.is_ca = %d\n", ci.is_ca);
    printf("ci.max_pathlen = %d\n", ci.max_pathlen);
    printf("ci.key_usage = %d\n", ci.key_usage);
    printf("ci.ns_cert_type = %d\n", ci.ns_cert_type);
    printf("ci.version = %d\n", ci.version);
    printf("ci.md = %d\n", ci.md);
    printf("ci.subject_identifier = %d\n", ci.subject_identifier);
    printf("ci.authority_identifier = %d\n", ci.authority_identifier);
    printf("ci.basic_constraints = %d\n", ci.basic_constraints);

    int exit_code = create_certificate(ci);

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_X509_CRT_WRITE_C && MBEDTLS_X509_CRT_PARSE_C &&     \
          MBEDTLS_FS_IO && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C && \
          MBEDTLS_ERROR_C && MBEDTLS_PEM_WRITE_C */
