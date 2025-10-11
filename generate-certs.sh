#!/usr/bin/env bash
set -e

PASS=changeit

echo "🔑 Generating EC P-256 server keypair..."
openssl ecparam -name prime256v1 -genkey -noout -out server-256.key
openssl req -new -x509 -key server-256.key -days 365 -subj "/CN=SSHD Server" -out server-256.crt
openssl pkcs12 -export -name server -inkey server-256.key -in server-256.crt -out server-ec256.p12 -password pass:$PASS
rm server-256.key server-256.crt

echo "🔑 Generating EC P-384 server keypair..."
openssl ecparam -name secp384r1 -genkey -noout -out server-384.key
openssl req -new -x509 -key server-384.key -days 365 -subj "/CN=SSHD Server" -out server-384.crt
openssl pkcs12 -export -name server -inkey server-384.key -in server-384.crt -out server-ec384.p12 -password pass:$PASS
rm server-384.key server-384.crt

echo "🔑 Generating EC P-521 server keypair..."
openssl ecparam -name secp521r1 -genkey -noout -out server-521.key
openssl req -new -x509 -key server-521.key -days 365 -subj "/CN=SSHD Server" -out server-521.crt
openssl pkcs12 -export -name server -inkey server-521.key -in server-521.crt -out server-ec521.p12 -password pass:$PASS
rm server-521.key server-521.crt

echo "🔑 Generating EC P-256 client keypair..."
openssl ecparam -name prime256v1 -genkey -noout -out client-256.key
openssl req -new -x509 -key client-256.key -days 365 -subj "/CN=SSHD Client" -out client-256.crt
openssl pkcs12 -export -name client -inkey client-256.key -in client-256.crt -out client-ec256.p12 -password pass:$PASS
rm client-256.key client-256.crt

echo "🔑 Generating EC P-384 client keypair..."
openssl ecparam -name secp384r1 -genkey -noout -out client-384.key
openssl req -new -x509 -key client-384.key -days 365 -subj "/CN=SSHD Client" -out client-384.crt
openssl pkcs12 -export -name client -inkey client-384.key -in client-384.crt -out client-ec384.p12 -password pass:$PASS
rm client-384.key client-384.crt

echo "🔑 Generating EC P-521 client keypair..."
openssl ecparam -name secp521r1 -genkey -noout -out client-521.key
openssl req -new -x509 -key client-521.key -days 365 -subj "/CN=SSHD Client" -out client-521.crt
openssl pkcs12 -export -name client -inkey client-521.key -in client-521.crt -out client-ec521.p12 -password pass:$PASS
rm client-521.key client-521.crt

echo "✅ Done."
