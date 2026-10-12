#!/usr/bin/env bash
# Creates a throwaway PKI for the image's TLS smoke test in the directory given:
#   ca.pem                       the test CA the client trusts
#   trusted.pem, trusted.key     server certificate for HOST, signed by the test CA
#   untrusted.pem, untrusted.key server certificate for HOST, signed by a second CA
# Every certificate meets the X.509 strict checks the relay's client enables.
# Usage: make_tls_smoke_pki.sh DIR [HOST]
set -euo pipefail

dir="$1"
host="${2:-tls.example.test}"
mkdir -p "$dir"
cd "$dir"

ca() {
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1-ca.key" -out "$1-ca.pem" -days 2 -subj "/CN=VRM Alert Relay smoke test $1 CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2> /dev/null
}

leaf() {
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$2.key" -out "$2.csr" -subj "/CN=${host}" 2> /dev/null
  printf '%s\n' \
    "subjectAltName=DNS:${host}" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid" > "$2.ext"
  openssl x509 -req -in "$2.csr" -CA "$1-ca.pem" -CAkey "$1-ca.key" -CAcreateserial \
    -days 2 -extfile "$2.ext" -out "$2.pem" 2> /dev/null
  openssl verify -x509_strict -CAfile "$1-ca.pem" "$2.pem"
}

ca test
ca rogue
leaf test trusted
leaf rogue untrusted
cp test-ca.pem ca.pem
rm -f ./*.csr ./*.ext ./*.srl test-ca.key rogue-ca.key rogue-ca.pem test-ca.pem
# The server runs as UID 65532; these throwaway keys protect nothing.
chmod 0644 ./*.pem ./*.key
