#!/usr/bin/env bash
# Створити власний CA і сертифікат сервера для TLS-захисту Modbus.
# ECDSA P-256: короткі ключі, швидке підписування, придатне для вбудованих ПЛК.
set -euo pipefail
cd "$(dirname "$0")/certs"

# Кореневий центр сертифікації (CA)
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=UA/O=Water Utility OKI/CN=OKI Modbus CA"

# Ключ і запит сервера
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -out server.csr \
  -subj "/C=UA/O=Water Utility OKI/CN=plc.local"

# Підпис сертифіката сервера нашим CA (SAN на 127.0.0.1 для перевірки)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days 825 -out server.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1,DNS:plc.local")

rm -f server.csr ca.srl
echo "certs готові: ca.crt, server.crt, server.key"
