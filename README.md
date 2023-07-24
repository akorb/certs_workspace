```shell
# Generate RSA key pair
openssl genrsa -out key.pem 2048

# Build this program
make

# Execute this program
./main

# Interpret the created certificate
openssl x509 -in cert.crt -text
```

For build-run-check cycle:

```shell
make && ./main && openssl x509 -in cert.crt -text
```

