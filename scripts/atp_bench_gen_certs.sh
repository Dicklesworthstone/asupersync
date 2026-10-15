#!/usr/bin/env bash
# gen_certs.sh OUTDIR SAN_EXTRA...
# Generates a P-256 CA + leaf (serverAuth EKU, SAN DNS:localhost + IP:127.0.0.1
# + any extra SANs given). Writes ca.pem, leaf.pem, leaf.key into OUTDIR.
set -euo pipefail
OUT="$1"; shift
mkdir -p "$OUT"; cd "$OUT"
SAN="DNS:localhost,IP:127.0.0.1"
for extra in "$@"; do SAN="$SAN,IP:$extra"; done
openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=atpq-bench-ca" -out ca.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
openssl req -new -key leaf.key -subj "/CN=atpq-bench" -out leaf.csr 2>/dev/null
cat > leaf.ext <<EXT
subjectAltName=$SAN
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
EXT
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 3650 -extfile leaf.ext -out leaf.pem 2>/dev/null
echo "wrote $OUT/{ca.pem,leaf.pem,leaf.key} SAN=$SAN"
