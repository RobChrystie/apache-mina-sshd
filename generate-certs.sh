#!/usr/bin/env bash
set -e  # portable across shells

PASS="changeit"
DAYS=365
ROOT_DIR="ec-certs"
CA_DIR="${ROOT_DIR}/ca"

mkdir -p "${CA_DIR}"

# ───────────────────────────────
# 🏦 Root CA
# ───────────────────────────────
echo "🔧 Creating Root CA..."

if [[ ! -f "${CA_DIR}/root-ca.key" ]]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "${CA_DIR}/root-ca.key"
  openssl req -x509 -new -key "${CA_DIR}/root-ca.key" -days 3650 \
    -subj "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=RootCA/CN=RootCA" \
    -out "${CA_DIR}/root-ca.pem"
  echo "✅ Root CA created: ${CA_DIR}/root-ca.pem"
else
  echo "ℹ️ Root CA already exists, skipping."
fi

# ───────────────────────────────
# 🛠 EC Certificate Generator
# ───────────────────────────────
generate_cert() {
  local name=$1
  local curve=$2
  local bits=$3
  local subj_dn=$4
  local san=$5

  local key_dir="${ROOT_DIR}/${name}"
  mkdir -p "${key_dir}"

  echo "🔑 Generating EC ${curve} ${name} keypair..."
  openssl ecparam -name "${curve}" -genkey -noout -out "${key_dir}/${name}-${bits}.key"

  echo "📄 Creating CSR..."
  openssl req -new -key "${key_dir}/${name}-${bits}.key" \
    -subj "${subj_dn}" -out "${key_dir}/${name}-${bits}.csr"

  # Optional SAN
  local san_cfg=""
  if [[ -n "${san}" ]]; then
    san_cfg=$(mktemp)
    cat >"${san_cfg}" <<EOF
[ v3_req ]
subjectAltName=${san}
EOF
  fi

  echo "🪪 Signing with Root CA..."
  openssl x509 -req -in "${key_dir}/${name}-${bits}.csr" \
    -CA "${CA_DIR}/root-ca.pem" -CAkey "${CA_DIR}/root-ca.key" -CAcreateserial \
    -out "${key_dir}/${name}-${bits}.pem" -days "${DAYS}" -sha256 \
    ${san_cfg:+-extfile "${san_cfg}" -extensions v3_req}

  echo "💼 Creating PKCS#12 keystore..."
  openssl pkcs12 -export \
    -name "${name}" \
    -inkey "${key_dir}/${name}-${bits}.key" \
    -in "${key_dir}/${name}-${bits}.pem" \
    -certfile "${CA_DIR}/root-ca.pem" \
    -out "${key_dir}/${name}-ec${bits}.p12" \
    -password pass:${PASS}

  rm -f "${san_cfg:-}"
  echo "✅ ${name} EC ${bits}-bit certificate complete."
  echo
}

# ───────────────────────────────
# 🛠 RSA Certificate Generator
# ───────────────────────────────
generate_rsa_cert() {
  local name=$1
  local bits=$2
  local subj_dn=$3
  local san=$4

  local key_dir="${ROOT_DIR}/${name}"
  mkdir -p "${key_dir}"

  echo "🔑 Generating RSA ${bits}-bit ${name} keypair..."
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:${bits} -out "${key_dir}/${name}-rsa${bits}.key"

  echo "📄 Creating CSR..."
  openssl req -new -key "${key_dir}/${name}-rsa${bits}.key" \
    -subj "${subj_dn}" -out "${key_dir}/${name}-rsa${bits}.csr"

  local san_cfg=""
  if [[ -n "${san}" ]]; then
    san_cfg=$(mktemp)
    cat >"${san_cfg}" <<EOF
[ v3_req ]
subjectAltName=${san}
EOF
  fi

  echo "🪪 Signing with Root CA..."
  openssl x509 -req -in "${key_dir}/${name}-rsa${bits}.csr" \
    -CA "${CA_DIR}/root-ca.pem" -CAkey "${CA_DIR}/root-ca.key" -CAcreateserial \
    -out "${key_dir}/${name}-rsa${bits}.pem" -days "${DAYS}" -sha256 \
    ${san_cfg:+-extfile "${san_cfg}" -extensions v3_req}

  echo "💼 Creating PKCS#12 keystore..."
  openssl pkcs12 -export \
    -name "${name}" \
    -inkey "${key_dir}/${name}-rsa${bits}.key" \
    -in "${key_dir}/${name}-rsa${bits}.pem" \
    -certfile "${CA_DIR}/root-ca.pem" \
    -out "${key_dir}/${name}-rsa${bits}.p12" \
    -password pass:${PASS}

  rm -f "${san_cfg:-}"
  echo "✅ ${name} RSA ${bits}-bit certificate complete."
  echo
}

# ───────────────────────────────
# 🌐 Server certificates (with SANs)
# ───────────────────────────────
generate_cert "server" "prime256v1" 256 \
  "/C=US/O=TestingEC/OU=Server/CN=server-prime256v1" \
  "DNS:server.local,DNS:localhost,IP:127.0.0.1"

generate_cert "server" "secp384r1" 384 \
  "/C=US/O=TestingEC/OU=Server/CN=server-secp384r1" \
  "DNS:server.local,DNS:localhost,IP:127.0.0.1"

generate_cert "server" "secp521r1" 521 \
  "/C=US/O=TestingEC/OU=Server/CN=server-secp521r1" \
  "DNS:server.local,DNS:localhost,IP:127.0.0.1"

# ───────────────────────────────
# 👤 Client certificates (no SAN)
# ───────────────────────────────
generate_cert "client" "prime256v1" 256 \
  "/C=US/O=TestingEC/OU=Client/CN=client-prime256v1" ""

generate_cert "client" "secp384r1" 384 \
  "/C=US/O=TestingEC/OU=Client/CN=client-secp384r1" ""

generate_cert "client" "secp521r1" 521 \
  "/C=US/O=TestingEC/OU=Client/CN=client-secp521r1" ""

# ───────────────────────────────
# 🌐 RSA Server Certificates
# ───────────────────────────────
generate_rsa_cert "server" 2048 "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=Server/CN=server.local" "DNS:server.local,DNS:localhost,IP:127.0.0.1"
generate_rsa_cert "server" 3072 "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=Server/CN=server.local" "DNS:server.local,DNS:localhost,IP:127.0.0.1"
generate_rsa_cert "server" 4096 "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=Server/CN=server.local" "DNS:server.local,DNS:localhost,IP:127.0.0.1"

# 👤 RSA Client Certificates
generate_rsa_cert "client" 2048 "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=Client/CN=client.local" ""
generate_rsa_cert "client" 3072 "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=Client/CN=client.local" ""
generate_rsa_cert "client" 4096 "/C=US/ST=CA/L=SF/O=ExampleOrg/OU=Client/CN=client.local" ""

echo "🎉 All EC and RSA certificates generated successfully in '${ROOT_DIR}/'"
