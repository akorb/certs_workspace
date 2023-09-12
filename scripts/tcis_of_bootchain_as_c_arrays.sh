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
    echo "static const unsigned char tci_$2[] = {${BYTES}};"
}

OPTEE_ROOT=$1

echo '#ifndef INCLUDE_TCIs_H'
echo '#define INCLUDE_TCIs_H'
echo ''
# print_array_of_file_hash ${OPTEE_ROOT}/trusted-firmware-a/build/fvp/release/bl1.bin bl1
print_array_of_file_hash ${OPTEE_ROOT}/trusted-firmware-a/build/fvp/release/bl2.bin bl2
print_array_of_file_hash ${OPTEE_ROOT}/trusted-firmware-a/build/fvp/release/bl31.bin bl31
print_array_of_file_hash ${OPTEE_ROOT}/optee_os/out/arm/core/tee-header_v2.bin bl32

echo ''
echo '/*'
echo "This is just fixed. I didn't find a way to extract it from any of the fTPM TA files."
echo 'So, we need to boot, measure the fTPM and put the values here.'
echo 'My ra_verifier tool outputs the FWIDs. You can copy paste it and generate this code here with:'
echo 'echo "<copied FWID>" | xxd -r -p | xxd -i'
echo '*/'
echo 'static const char tci_ekcert[] = {  0x8c, 0x95, 0x2f, 0x35, 0x52, 0x34, 0xe7, 0x8c, 0x79, 0x40, 0xb3, 0x0d,\
  0x62, 0x78, 0x55, 0x42, 0x1e, 0x10, 0x26, 0xd9, 0x7e, 0xc8, 0xf5, 0xaa,\
  0x0c, 0x51, 0x1d, 0x10, 0xb9, 0x48, 0x40, 0x92};'

echo ''
echo '#endif /* INCLUDE_TCIs_H */'
