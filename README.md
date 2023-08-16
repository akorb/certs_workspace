```shell
# Generate RSA key pairs
mkdir -p keys_in
openssl genrsa -out keys_in/manufacturer.pem 2048
openssl genrsa -out keys_in/bl1.pem 2048
openssl genrsa -out keys_in/bl2.pem 2048
openssl genrsa -out keys_in/bl31.pem 2048
openssl genrsa -out keys_in/bl32.pem 2048

# Build this program
make OPTEE_ROOT=<path>

# Execute this program
./main

# Interpret a created certificate
openssl x509 -in certs_out/bl1.crt -text
```

For build-run-check cycle:

```shell
make && ./main && openssl x509 -in certs_out/bl1.crt -text
```
