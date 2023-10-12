if [ "$#" -ne 1 ]; then
    echo 'Missing argument.'
    echo 'Give (only) the path to the directory containing the key files.'
    exit 1
fi

KEY_FILES_PATH=$1

. scripts/common.sh

CONTENT=$(print_ascii_file_as_c_array "${KEY_FILES_PATH}" bl32 pem key_)

surround_with_header_guards "KEY_FILE_H" "${CONTENT}"
