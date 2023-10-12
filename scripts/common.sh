print_ascii_file_as_c_array ()
{
    dir=$1
    filename=$2  # Without extension
    extension=$3
    array_prefix=$4
    printf 'static const unsigned char %s%s[] =\n"' "${array_prefix}" "${filename}"
    head -n -1 "${dir}/${filename}.${extension}" | awk '$0=$0"\\n\\"'
    tail -n 1 "${dir}/${filename}.${extension}" | awk '$0=$0"\";"'
}

surround_with_header_guards ()
{
    if [ "$#" -ne 2 ]; then
        echo 'Missing arguments.'
        echo 'Give (only) the header preprocessor name and the headers content.'
        exit 1
    fi

    HEADER_PREPROCESSOR_NAME=$1
    BODY=$2

    echo "#ifndef ${HEADER_PREPROCESSOR_NAME}"
    echo "#define ${HEADER_PREPROCESSOR_NAME}"
    echo ""

    printf "%s" "${BODY}"

    echo ""
    echo "#endif /* ${HEADER_PREPROCESSOR_NAME} */"
}
