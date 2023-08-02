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

print_ascii_file manufacturer crt crt_
echo ''

print_ascii_file bl1 crt crt_
echo ''

print_ascii_file bl2 crt crt_
echo ''

print_ascii_file bl31 crt crt_
echo ''

print_ascii_file bl32 crt crt_
echo ''

print_ascii_file bl32 pem key_
