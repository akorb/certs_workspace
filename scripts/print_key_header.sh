if [ "$#" -ne 1 ]; then
    echo 'Missing argument.'
    echo 'Give (only) the path to the keyfile.'
    exit 1
fi

source scripts/common.sh

CONTENT=$(print_ascii_file_as_c_array keys_in bl32 pem key_)

sh scripts/print_header.sh "KEY_FILE_H" "${CONTENT}"
