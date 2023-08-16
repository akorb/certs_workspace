if [ "$#" -ne 1 ]; then
    echo 'Missing argument.'
    echo 'Give (only) the path to the root of the OPTEE repositories.'
    exit 1
fi

print_array_of_file_hash ()
{
    # Arg 1: filename
    # Arg 2: layer name
    BYTES=$(sha256sum $1 | \
        awk '{ print $1 }' | \
        xxd -r -p | \
        xxd -i)
    echo "static const char tci_$2[] = {${BYTES}};"
}

OPTEE_ROOT=$1

echo '#ifndef INCLUDE_TCIs'
echo '#define INCLUDE_TCIs'
echo ''
# print_array_of_file_hash ${OPTEE_ROOT}/trusted-firmware-a/build/fvp/release/bl1.bin bl1
print_array_of_file_hash ${OPTEE_ROOT}/trusted-firmware-a/build/fvp/release/bl2.bin bl2
print_array_of_file_hash ${OPTEE_ROOT}/trusted-firmware-a/build/fvp/release/bl31.bin bl31
print_array_of_file_hash ${OPTEE_ROOT}/optee_os/out/arm/core/tee-header_v2.bin bl32
echo ''
echo '#endif'
