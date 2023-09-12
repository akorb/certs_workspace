#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_X509_CRT_WRITE_C) ||                            \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||   \
    !defined(MBEDTLS_ERROR_C) || !defined(MBEDTLS_SHA256_C) ||       \
    !defined(MBEDTLS_PEM_WRITE_C)
int main(void)
{
    printf("MBEDTLS_X509_CRT_WRITE_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
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

#include <DiceTcbInfo.h>

// Generated during `make`
#include "TCIs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

#define DFL_NOT_BEFORE "20230725000000"
#define DFL_NOT_AFTER "99991231235959"
#define DFL_SERIAL "1"
#define DFL_MAX_PATHLEN -1
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
// ASN.1 encoded
static const uint8_t certificate_policy_val_IDevID[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x06};
static const uint8_t certificate_policy_val_LDevID[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x07};

// Raw values! Not encoded to ASN.1 yet
// Therefore, usable for ASN1c generated code, but not for mbedtls code
const asn_oid_arc_t sha256_oid[] = {2, 16, 840, 1, 101, 3, 4, 2, 1};

#define CERTIFICATE_POLICY_VAL_LEN sizeof(certificate_policy_val_IDevID)

// ASN.1 encoded
static const char dice_attestation_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};

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
    int tci_len;        /* Trused Componentent Identifier aka Firmware ID (FWID)*/
} cert_info;

static const char certficate_names[][64] = {
    CERTS_OUTPUT_FOLDER "/manufacturer.crt",
    CERTS_OUTPUT_FOLDER "/bl1.crt",
    CERTS_OUTPUT_FOLDER "/bl2.crt",
    CERTS_OUTPUT_FOLDER "/bl31.crt",
    CERTS_OUTPUT_FOLDER "/bl32.crt",
};

static int write_certificate(mbedtls_x509write_cert *crt, const char *output_file)
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

static int generate_attestation_extension_data(uint8_t *output_buf, const size_t outbut_buf_len,
                                               const asn_oid_arc_t *hash_type_oid, const size_t hash_type_oid_len,
                                               const uint8_t *hash, const size_t hash_len)
{
    int ret;
    DiceTcbInfo_t *tcbInfo = calloc(1, sizeof(*tcbInfo));
    assert(tcbInfo);

    FWID_t *fwid = calloc(1, sizeof(*fwid));
    OBJECT_IDENTIFIER_set_arcs(&fwid->hashAlg, hash_type_oid, hash_type_oid_len / sizeof(hash_type_oid[0]));
    fwid->digest.buf = malloc(hash_len);
    memcpy(fwid->digest.buf, hash, hash_len);
    fwid->digest.size = hash_len;

    tcbInfo->fwids = calloc(1, sizeof(*tcbInfo->fwids));
    ret = ASN_SEQUENCE_ADD(&tcbInfo->fwids->list, fwid);
    assert(ret == 0);

    asn_enc_rval_t ec = der_encode_to_buffer(&asn_DEF_DiceTcbInfo, tcbInfo, output_buf, outbut_buf_len);
    ASN_STRUCT_FREE(asn_DEF_DiceTcbInfo, tcbInfo);

    return ec.encoded;
}

static int create_certificate(cert_info ci)
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                       *subject_key = &loaded_subject_key;
    char buf[256];
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;

    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&loaded_issuer_key);
    mbedtls_pk_init(&loaded_subject_key);
    mbedtls_mpi_init(&serial);

    // Parse serial to MPI
    //
    printf("Reading serial number...");
    fflush(stdout);

    if ((ret = mbedtls_mpi_read_string(&serial, 10, ci.serial)) != 0)
    {
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  mbedtls_mpi_read_string "
               "returned -0x%04x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 1.1. Load the keys
     */
    if (!ci.selfsign)
    {
        printf("Loading the subject key ...");
        fflush(stdout);

        ret = mbedtls_pk_parse_keyfile(&loaded_subject_key, ci.subject_key,
                                       NULL);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, sizeof(buf));
            printf(" failed\n  !  mbedtls_pk_parse_keyfile "
                   "returned -0x%04x - %s\n\n",
                   (unsigned int)-ret, buf);
            goto exit;
        }

        printf(" ok\n");
    }

    printf("Loading the issuer key ...");
    fflush(stdout);

    ret = mbedtls_pk_parse_keyfile(&loaded_issuer_key, ci.issuer_key,
                                   NULL);
    if (ret != 0)
    {
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  mbedtls_pk_parse_keyfile "
               "returned -x%02x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    printf(" ok\n");

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
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  mbedtls_x509write_crt_set_subject_name "
               "returned -0x%04x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    if ((ret = mbedtls_x509write_crt_set_issuer_name(&crt, ci.issuer_name)) != 0)
    {
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  mbedtls_x509write_crt_set_issuer_name "
               "returned -0x%04x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    printf("Setting certificate values ...");
    fflush(stdout);

    mbedtls_x509write_crt_set_version(&crt, ci.version);
    mbedtls_x509write_crt_set_md_alg(&crt, ci.md);

    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0)
    {
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  mbedtls_x509write_crt_set_serial "
               "returned -0x%04x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_validity(&crt, ci.not_before, ci.not_after);
    if (ret != 0)
    {
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  mbedtls_x509write_crt_set_validity "
               "returned -0x%04x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    printf(" ok\n");

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.basic_constraints != 0)
    {
        printf("Adding the Basic Constraints extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_basic_constraints(&crt, ci.is_ca,
                                                          ci.max_pathlen);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, sizeof(buf));
            printf(" failed\n  !  x509write_crt_set_basic_constraints "
                   "returned -0x%04x - %s\n\n",
                   (unsigned int)-ret, buf);
            goto exit;
        }

        printf(" ok\n");
    }

#if defined(MBEDTLS_SHA1_C)
    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.subject_identifier != 0)
    {
        printf("Adding the Subject Key Identifier ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, sizeof(buf));
            printf(" failed\n  !  mbedtls_x509write_crt_set_subject"
                   "_key_identifier returned -0x%04x - %s\n\n",
                   (unsigned int)-ret, buf);
            goto exit;
        }

        printf(" ok\n");
    }

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.authority_identifier != 0)
    {
        printf("Adding the Authority Key Identifier ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, sizeof(buf));
            printf(" failed\n  !  mbedtls_x509write_crt_set_authority_"
                   "key_identifier returned -0x%04x - %s\n\n",
                   (unsigned int)-ret, buf);
            goto exit;
        }

        printf(" ok\n");
    }
#endif /* MBEDTLS_SHA1_C */

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.key_usage != 0)
    {
        printf("Adding the Key Usage extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_key_usage(&crt, ci.key_usage);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, sizeof(buf));
            printf(" failed\n  !  mbedtls_x509write_crt_set_key_usage "
                   "returned -0x%04x - %s\n\n",
                   (unsigned int)-ret, buf);
            goto exit;
        }

        printf(" ok\n");
    }

    if (ci.version == MBEDTLS_X509_CRT_VERSION_3 &&
        ci.ns_cert_type != 0)
    {
        printf("Adding the NS Cert Type extension ...");
        fflush(stdout);

        ret = mbedtls_x509write_crt_set_ns_cert_type(&crt, ci.ns_cert_type);
        if (ret != 0)
        {
            mbedtls_strerror(ret, buf, sizeof(buf));
            printf(" failed\n  !  mbedtls_x509write_crt_set_ns_cert_type "
                   "returned -0x%04x - %s\n\n",
                   (unsigned int)-ret, buf);
            goto exit;
        }

        printf(" ok\n");
    }

    if (ci.certificate_policy_val)
    {
        printf("Add certificate policy extension...");

        mbedtls_x509write_crt_set_extension(&crt, MBEDTLS_OID_CERTIFICATE_POLICIES, MBEDTLS_OID_SIZE(MBEDTLS_OID_CERTIFICATE_POLICIES), 0, ci.certificate_policy_val, CERTIFICATE_POLICY_VAL_LEN);
        printf(" ok\n");
    }

    if (ci.tci)
    {
        printf("Add DICE attestation extension...");

        uint8_t out_buf[128];

        int data_size = generate_attestation_extension_data(out_buf, sizeof(out_buf), sha256_oid, sizeof(sha256_oid), ci.tci, ci.tci_len);
        if (data_size <= 0)
        {
            printf("Failed to create DICE attestation extension. Return value: %d\n", data_size);
        }
        else
        {
            mbedtls_x509write_crt_set_extension(&crt, dice_attestation_oid, sizeof(dice_attestation_oid), 0, out_buf, data_size);
            printf(" ok\n");
        }
    }

    /*
     * 1.2. Writing the certificate
     */
    printf("Writing the certificate...");
    fflush(stdout);

    if ((ret = write_certificate(&crt, ci.output_file)) != 0)
    {
        mbedtls_strerror(ret, buf, sizeof(buf));
        printf(" failed\n  !  write_certificate -0x%04x - %s\n\n",
               (unsigned int)-ret, buf);
        goto exit;
    }

    printf(" ok\n");
    printf("\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&loaded_subject_key);
    mbedtls_pk_free(&loaded_issuer_key);
    mbedtls_mpi_free(&serial);

    return exit_code;
}

static void verify()
{
    // From https://stackoverflow.com/a/72722115/2050020

    int32_t r;
    uint32_t flags = 0;

    mbedtls_x509_crt ca, chain;

    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&chain);

    r = mbedtls_x509_crt_parse_file(&ca, certficate_names[0]);
    if (r != 0)
    {
        char buf[256];
        mbedtls_strerror(r, buf, sizeof(buf));
        printf("Failed to parse %s\nmbedtls_x509_crt_parse_file -0x%04x - %s\n\n",
               certficate_names[0], (unsigned int)-r, buf);
    }

    for (int i = 1; i < ARRAY_LEN(certficate_names); i++)
    {
        r = mbedtls_x509_crt_parse_file(&chain, certficate_names[i]);
        if (r != 0)
        {
            char buf[256];
            mbedtls_strerror(r, buf, sizeof(buf));
            printf("Failed to parse %s\nmbedtls_x509_crt_parse_file -0x%04x - %s\n\n",
                   certficate_names[i], (unsigned int)-r, buf);
        }
    }

    printf("Verifying signatures of certificate chain...");
    fflush(stdout);
    if ((r = mbedtls_x509_crt_verify(&chain, &ca, NULL, NULL, &flags,
                                     NULL, NULL)) != 0)
    {
        char vrfy_buf[512];
        printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
        printf("%s\n", vrfy_buf);
    }
    else
        printf(" ok\n");

    mbedtls_x509_crt_free(&ca);
    mbedtls_x509_crt_free(&chain);
}

static int ensureOutFolderExists()
{
    struct stat st;
    if (stat(CERTS_OUTPUT_FOLDER, &st) == -1)
        if (mkdir(CERTS_OUTPUT_FOLDER, 0755) == -1)
        {
            perror("mkdir");
            return 1;
        }
    return 0;
}

int main(void)
{
    const char name_manufacturer[] = "CN=Manufacturer,O=Cool company,C=GER";
    const char name_bl1[] = "CN=BL1,O=AP Trusted ROM,C=GER";
    const char name_bl2[] = "CN=BL2,O=Trusted Boot Firmware,C=GER";
    const char name_bl31[] = "CN=BL31,O=EL3 Runtime Software,C=GER";
    const char name_bl32[] = "CN=BL32,O=OP-TEE OS,C=GER";
    const char name_ekcert[] = "CN=EKCert,O=TPM EK,C=GER";

    cert_info cis[5];
    memset(cis, 0, sizeof(cis));
    cert_info *cert_info_manufacturer = &cis[0];
    cert_info *cert_info_bl1 = &cis[1];
    cert_info *cert_info_bl2 = &cis[2];
    cert_info *cert_info_bl31 = &cis[3];
    cert_info *cert_info_bl32 = &cis[4];

    if (ensureOutFolderExists() != 0)
        return 1;

    cert_info_manufacturer->subject_key = KEYS_INPUT_FOLDER "/manufacturer.pem";
    cert_info_manufacturer->issuer_key = KEYS_INPUT_FOLDER "/manufacturer.pem";
    cert_info_manufacturer->output_file = certficate_names[0];
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

    cert_info_bl1->subject_key = KEYS_INPUT_FOLDER "/bl1.pem";
    cert_info_bl1->issuer_key = KEYS_INPUT_FOLDER "/manufacturer.pem";
    cert_info_bl1->output_file = certficate_names[1];
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
    cert_info_bl1->tci = NULL;

    cert_info_bl2->subject_key = KEYS_INPUT_FOLDER "/bl2.pem";
    cert_info_bl2->issuer_key = KEYS_INPUT_FOLDER "/bl1.pem";
    cert_info_bl2->output_file = certficate_names[2];
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
    cert_info_bl2->tci = tci_bl2;
    cert_info_bl2->tci_len = sizeof(tci_bl2);

    cert_info_bl31->subject_key = KEYS_INPUT_FOLDER "/bl31.pem";
    cert_info_bl31->issuer_key = KEYS_INPUT_FOLDER "/bl2.pem";
    cert_info_bl31->output_file = certficate_names[3];
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
    cert_info_bl31->tci = tci_bl31;
    cert_info_bl31->tci_len = sizeof(tci_bl31);

    cert_info_bl32->subject_key = KEYS_INPUT_FOLDER "/bl32.pem";
    cert_info_bl32->issuer_key = KEYS_INPUT_FOLDER "/bl31.pem";
    cert_info_bl32->output_file = certficate_names[4];
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
    cert_info_bl32->tci = tci_bl32;
    cert_info_bl32->tci_len = sizeof(tci_bl32);

    int exit_code;
    for (int i = 0; i < ARRAY_LEN(cis); i++)
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
