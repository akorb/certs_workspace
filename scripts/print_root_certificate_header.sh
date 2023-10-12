if [ "$#" -ne 1 ]; then
    echo 'Missing argument.'
    echo 'Give (only) the directory path to the certificates.'
    exit 1
fi

. scripts/common.sh

CERTS_FOLDER=$1

CONTENT=\
"/**
 * This is the certificiate of the manufacturer which needs to be inherently trusted
 * and therefore, acts as the root of trust for the certificate chain.
 */
$(print_ascii_file_as_c_array "${CERTS_FOLDER}" manufacturer crt crt_)"

surround_with_header_guards "CERT_ROOT_H" "${CONTENT}"
