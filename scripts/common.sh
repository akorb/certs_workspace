print_ascii_file_as_c_array ()
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
