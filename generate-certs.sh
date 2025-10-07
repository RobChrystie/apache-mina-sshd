#!/usr/bin/env bash
set -e

PASS=changeit

echo "🔑 Generating EC P-521 server keypair..."
openssl ecparam -name secp521r1 -genkey -noout -out server.key
openssl req -new -x509 -key server.key -days 365 -subj "/CN=SSHD Server" -out server.crt
openssl pkcs12 -export -name server -inkey server.key -in server.crt -out server-ec521.p12 -password pass:$PASS

echo "🔑 Generating EC P-521 client keypair..."
openssl ecparam -name secp521r1 -genkey -noout -out client.key
openssl req -new -x509 -key client.key -days 365 -subj "/CN=SSHD Client" -out client.crt
openssl pkcs12 -export -name client -inkey client.key -in client.crt -out client-ec521.p12 -password pass:$PASS

echo "✅ Done."
