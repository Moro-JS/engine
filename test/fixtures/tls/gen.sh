#!/bin/sh
# Regenerates the committed TEST-ONLY PKI. Run from this directory:
#   sh gen.sh
# Output is committed so tests are deterministic on every platform with no
# runtime openssl dependency. 36500-day expiry: these must never rot in CI.
#
# THE LEAF PRIVATE KEYS ARE INTENTIONALLY PUBLIC. Never reuse for anything real.
#
# The CA's private key is not kept: it is created in a temporary directory,
# signs the three leaves below, and is deleted when this script ends. Nothing
# reads it at test time (clients trust ca.pem, servers present the leaves), and
# with the key gone no further certificate can be issued under ca.pem. The CA
# is also constrained to the names the tests use: localhost, *.test, 127.0.0.1
# and ::1.
set -eu

DAYS=36500
PASS=moro-test

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CA_KEY="$WORK/ca.key"
rm -f ca.key

# --- Test CA (ECDSA P-256) ---------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
openssl req -x509 -new -key "$CA_KEY" -days "$DAYS" -sha256 \
  -subj "/CN=MoroJS Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "nameConstraints=critical,permitted;DNS:localhost,permitted;DNS:test,permitted;IP:127.0.0.1/255.255.255.255,permitted;IP:0:0:0:0:0:0:0:1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" \
  -out ca.pem

# SAN extension shared by the localhost-facing leaves
cat > san-localhost.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF

cat > san-alt.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=serverAuth
subjectAltName=DNS:alt.example.test
EOF

# --- localhost leaf, ECDSA P-256 (primary server cert) ------------------------
openssl ecparam -name prime256v1 -genkey -noout -out localhost.key
openssl req -new -key localhost.key -subj "/CN=localhost" -out localhost.csr
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey "$CA_KEY" -CAcreateserial \
  -days "$DAYS" -sha256 -extfile san-localhost.ext -out localhost.pem

# Encrypted copy of the localhost key (passphrase tests). PKCS#8 AES-256.
openssl pkcs8 -topk8 -in localhost.key -passout "pass:$PASS" \
  -v2 aes-256-cbc -out localhost-encrypted.key

# --- RSA-2048 leaf (algorithm coverage) ---------------------------------------
openssl genrsa -out rsa.key 2048
openssl req -new -key rsa.key -subj "/CN=localhost" -out rsa.csr
openssl x509 -req -in rsa.csr -CA ca.pem -CAkey "$CA_KEY" -CAcreateserial \
  -days "$DAYS" -sha256 -extfile san-localhost.ext -out rsa.pem

# --- alt.example.test leaf (SNI second identity) ------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out alt.key
openssl req -new -key alt.key -subj "/CN=alt.example.test" -out alt.csr
openssl x509 -req -in alt.csr -CA ca.pem -CAkey "$CA_KEY" -CAcreateserial \
  -days "$DAYS" -sha256 -extfile san-alt.ext -out alt.pem

# --- self-signed leaf, NOT CA-signed (unknown-CA rejection tests) --------------
openssl ecparam -name prime256v1 -genkey -noout -out selfsigned.key
openssl req -x509 -new -key selfsigned.key -days "$DAYS" -sha256 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -out selfsigned.pem

# --- self-signed Ed448 leaf ----------------------------------------------------
# A key type OpenSSL serves and BoringSSL does not have: the TLS-library tests
# use it to prove that such a server is moved to the OpenSSL binary, not broken.
openssl genpkey -algorithm ed448 -out ed448.key
openssl req -x509 -new -key ed448.key -days "$DAYS" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -out ed448.pem

# --- client certificates (ssl.requestCert / ssl.ca tests) ---------------------
# Two client CAs, their keys discarded like the server CA's, and two client
# leaves under the first, one of them revoked by that CA's CRL. The second CA
# has no leaf: a server that trusts only it accepts no client the tests have,
# which is what they need it for.
cat > client.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF
for n in "" 2; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/client-ca$n.key"
  openssl req -x509 -new -key "$WORK/client-ca$n.key" -days "$DAYS" -sha256 \
    -subj "/CN=MoroJS Test Client CA $n" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "client-ca$n.pem"
done
for leaf in client client-revoked; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$leaf.key"
  openssl req -new -key "$leaf.key" -subj "/CN=test-$leaf" -out "$leaf.csr"
  openssl x509 -req -in "$leaf.csr" -CA client-ca.pem -CAkey "$WORK/client-ca.key" \
    -CAserial "$WORK/client-ca.srl" -CAcreateserial \
    -days "$DAYS" -sha256 -extfile client.ext -out "$leaf.pem"
done
# The first client CA's CRL (ssl.crl tests): it lists client-revoked.pem.
: > "$WORK/index.txt"
echo 01 > "$WORK/crlnumber"
cat > "$WORK/crl.cnf" <<EOF
[ca]
default_ca = client_ca
[client_ca]
database = $WORK/index.txt
crlnumber = $WORK/crlnumber
default_md = sha256
default_crl_days = $DAYS
EOF
openssl ca -config "$WORK/crl.cnf" -cert client-ca.pem -keyfile "$WORK/client-ca.key" -revoke client-revoked.pem
openssl ca -config "$WORK/crl.cnf" -cert client-ca.pem -keyfile "$WORK/client-ca.key" -gencrl -out client-ca.crl.pem

rm -f localhost.csr rsa.csr alt.csr client.csr client-revoked.csr san-localhost.ext san-alt.ext client.ext ca.srl
echo "done - fixture PKI regenerated (the CA key was discarded)"
