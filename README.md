```shell
# Generate RSA key pairs
openssl genrsa -out manufacturer.pem 2048
openssl genrsa -out bl1.pem 2048
openssl genrsa -out bl2.pem 2048
openssl genrsa -out bl31.pem 2048
openssl genrsa -out bl32.pem 2048
openssl genrsa -out ekcert.pem 2048

# Build this program
make

# Execute this program
./main

# Interpret the created certificate
openssl x509 -in cert.crt -text
```

For build-run-check cycle:

```shell
make && ./main && openssl x509 -in bl31.crt -text
```

