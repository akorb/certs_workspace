print_ascii_file ()
{
    # Arg 1: filename (without extension)
    # Arg 2: extension
    # Arg 3: Prefix to array name
    echo "static const uint8_t $3$1[] ="
    echo -n '"'
    head -n -1 $1.$2 | awk '$0=$0"\\n\\"'
    tail -n 1 $1.$2 | awk '$0=$0"\";"'
}

print_ascii_file certs_out/manufacturer crt crt_
echo ''

print_ascii_file certs_out/bl1 crt crt_
echo ''

print_ascii_file certs_out/bl2 crt crt_
echo ''

print_ascii_file certs_out/bl31 crt crt_
echo ''

print_ascii_file certs_out/bl32 crt crt_
echo ''

print_ascii_file keys_in/bl32 pem key_
