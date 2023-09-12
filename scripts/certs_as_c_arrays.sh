print_ascii_file ()
{
    dir=$1
    filename=$2  # Without extension
    extension=$3
    array_prefix=$4
    echo "static const unsigned char ${array_prefix}${filename}[] ="
    echo -n '"'
    head -n -1 ${dir}/${filename}.${extension} | awk '$0=$0"\\n\\"'
    tail -n 1 ${dir}/${filename}.${extension} | awk '$0=$0"\";"'
}

echo '#ifndef EMBEDDED_CERTS_H'
echo '#define EMBEDDED_CERTS_H'
echo ''

print_ascii_file certs_out manufacturer crt crt_
echo ''

print_ascii_file certs_out bl1 crt crt_
echo ''

print_ascii_file certs_out bl2 crt crt_
echo ''

print_ascii_file certs_out bl31 crt crt_
echo ''

print_ascii_file certs_out bl32 crt crt_
echo ''

print_ascii_file keys_in bl32 pem key_

echo ''
echo '#endif /* EMBEDDED_CERTS_H */'
