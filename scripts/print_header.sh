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

echo "$2"

echo ""
echo "#endif /* ${HEADER_PREPROCESSOR_NAME} */"
