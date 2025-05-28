#!/bin/bash

# Generate self-signed certificates for testing
# DO NOT use these in production!

# Generate CA key and certificate
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=TokenShield CA/CN=tokenshield-ca"

# Generate server key and certificate request
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=TokenShield/CN=tokenshield"

# Sign server certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# Create combined PEM file for HAProxy
cat server.crt server.key > server.pem

# Clean up
rm server.csr

echo "Certificates generated successfully!"
echo "- CA certificate: ca.crt"
echo "- Server certificate: server.crt"
echo "- Server key: server.key"
echo "- Combined PEM for HAProxy: server.pem"