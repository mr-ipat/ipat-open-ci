#!/usr/bin/env bash
# IPAT R6.7: ACTUAL openssl CA-signed TLS 1.3 client verification on loopback.
# Disposable synthetic laboratory keys/CA ONLY, never any device credentials.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R67_RUN_SYNTHETIC_MTLS_TEST:-}" == "YES" ]] || {
  echo "R67_REFUSED_NO_EXPLICIT_SYNTHETIC_MTLS_TEST_OPT_IN" >&2
  exit 4
}
cd "$(dirname "$0")/../../../.."
bin=./target/debug/cwmp-mtls-lab
[[ -x "$bin" ]] || { echo "BUILD_CWMP_MTLS_LAB_BINARY_FIRST" >&2; exit 4; }
for program in openssl curl python3; do
  command -v "$program" >/dev/null || { echo "MISSING_LAB_PROGRAM" >&2; exit 4; }
done
# Refuse to interfere with someone else's local listener.
python3 - <<'PY'
import socket
s=socket.socket()
try:
    s.bind(("127.0.0.1",3433))
finally:
    s.close()
PY
tmp="$(mktemp -d /tmp/ipat-r67-mtls.XXXXXXXX)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" >/dev/null 2>&1 || :
    wait "$pid" >/dev/null 2>&1 || :
  fi
  if [[ "$tmp" == /tmp/ipat-r67-mtls.* && -d "$tmp" ]]; then
    rm -rf -- "$tmp"
  fi
}
trap cleanup EXIT
certgen() {
  local prefix="$1" subject="$2" ext="$3"
  openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/$prefix.key"
  openssl req -new -sha256 -key "$tmp/$prefix.key" \
    -subj "/CN=$subject" -out "$tmp/$prefix.csr"
  printf '%s\n' "$ext" > "$tmp/$prefix.ext"
  openssl x509 -req -sha256 -days 1 -in "$tmp/$prefix.csr" \
    -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
    -extfile "$tmp/$prefix.ext" -out "$tmp/$prefix.crt" >/dev/null 2>&1
}
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/ca.key"
openssl req -new -x509 -sha256 -days 2 -key "$tmp/ca.key" \
  -subj "/CN=IPAT SYNTHETIC DISPOSABLE ROOT" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$tmp/ca.crt"
certgen server localhost "$(printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:localhost')"
certgen client synthetic-agent.test.invalid "$(printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=DNS:synthetic-agent.test.invalid')"
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/rogue-ca.key"
openssl req -new -x509 -sha256 -days 1 -key "$tmp/rogue-ca.key" \
  -subj "/CN=IPAT SYNTHETIC UNTRUSTED ROOT" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$tmp/rogue-ca.crt"
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/rogue.key"
openssl req -new -key "$tmp/rogue.key" -subj "/CN=untrusted-agent" \
  -out "$tmp/rogue.csr"
printf '%s\n' 'extendedKeyUsage=clientAuth' > "$tmp/rogue.ext"
openssl x509 -req -sha256 -days 1 -in "$tmp/rogue.csr" \
  -CA "$tmp/rogue-ca.crt" -CAkey "$tmp/rogue-ca.key" \
  -CAcreateserial -extfile "$tmp/rogue.ext" -out "$tmp/rogue.crt" >/dev/null 2>&1
chmod 0600 "$tmp"/*.crt "$tmp"/*.key
# Default OFF, with no private certs and no opt-in cannot open TCP.
if env -u IPAT_RUN_PRIVATE_CWMP_MTLS_LAB "$bin" >/dev/null 2>&1; then
  echo "UNAUTHENTICATED_MTLS_PROCESS_STARTED" >&2; exit 1
fi
reject_candidate() {
  local status=0
  timeout 3 env IPAT_RUN_PRIVATE_CWMP_MTLS_LAB=YES \
    IPAT_R67_TRUSTED_CLIENT_CA_PEM="$tmp/ca.crt" \
    IPAT_R67_SERVER_CERT_PEM="$tmp/server.crt" \
    IPAT_R67_SERVER_KEY_PEM="$1" \
    "$bin" >"$tmp/stdout" 2>"$tmp/stderr" || status=$?
  if [[ "$status" -ne 4 ]]; then
    echo "R67_INVALID_PRIVATE_CERTIFICATE_DID_NOT_FAIL_CLOSED" >&2
    exit 1
  fi
}
# Reject symlinks and file permission degradation BEFORE binding.
ln -s "$tmp/server.key" "$tmp/linked.key"
reject_candidate "$tmp/linked.key"
chmod 0644 "$tmp/server.key"
reject_candidate "$tmp/server.key"
chmod 0600 "$tmp/server.key"
IPAT_RUN_PRIVATE_CWMP_MTLS_LAB=YES \
  IPAT_R67_TRUSTED_CLIENT_CA_PEM="$tmp/ca.crt" \
  IPAT_R67_SERVER_CERT_PEM="$tmp/server.crt" \
  IPAT_R67_SERVER_KEY_PEM="$tmp/server.key" \
  "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
url="https://localhost:3433"
flags=(--silent --show-error --noproxy '*' --resolve localhost:3433:127.0.0.1 \
  --tlsv1.3 --tls-max 1.3 --connect-timeout 2 --max-time 4 \
  --cacert "$tmp/ca.crt")
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl "${flags[@]}" --cert "$tmp/client.crt" --key "$tmp/client.key" \
     "$url/unsupported" --output /dev/null 2>/dev/null; then
    break
  fi
  sleep 0.4
done
# TLS1.3 handshake MUST NOT admit a client without any cert.
if curl "${flags[@]}" "$url/lab/mtls/parse-inform" \
  --output "$tmp/no-client.response" 2>/dev/null; then
  echo "MISSING_CLIENT_CERTIFICATE_WRONGLY_ADMITTED" >&2; exit 1
fi
# A valid unrelated CA and an inappropriate serverAuth-only certificate
# must both fail mTLS at handshake, without reaching any parser route.
if curl "${flags[@]}" --cert "$tmp/rogue.crt" --key "$tmp/rogue.key" \
  "$url/unsupported" --output "$tmp/rogue.response" 2>/dev/null; then
  echo "UNTRUSTED_CLIENT_CA_WRONGLY_ADMITTED" >&2; exit 1
fi
if curl "${flags[@]}" --cert "$tmp/server.crt" --key "$tmp/server.key" \
  "$url/unsupported" --output "$tmp/server-as-client.response" 2>/dev/null; then
  echo "WRONG_CLIENT_EKU_WRONGLY_ADMITTED" >&2; exit 1
fi
# Browser-style server hostname/CA validation MUST remain active too.
if curl "${flags[@]}" --resolve alternate.invalid:3433:127.0.0.1 \
  --cert "$tmp/client.crt" --key "$tmp/client.key" \
  'https://alternate.invalid:3433/unsupported' \
  --output "$tmp/wrong-hostname.response" 2>/dev/null; then
  echo "TLS_SERVER_HOSTNAME_BYPASS_DETECTED" >&2; exit 1
fi
if curl "${flags[@]}" --cacert "$tmp/rogue-ca.crt" \
  --cert "$tmp/client.crt" --key "$tmp/client.key" \
  "$url/unsupported" --output "$tmp/wrong-server-ca.response" 2>/dev/null; then
  echo "TLS_CLIENT_TRUSTED_UNKNOWN_SERVER_CA" >&2; exit 1
fi
cat > "$tmp/inform.xml" <<'XML'
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<soap:Header><cwmp:ID soap:mustUnderstand="1">synthetic-only</cwmp:ID></soap:Header>
<soap:Body><cwmp:Inform>
<DeviceId><Manufacturer>SYNTHETIC</Manufacturer><OUI>001122</OUI>
<ProductClass>NOT-PHYSICAL</ProductClass><SerialNumber>FAKE-SECRET-SERIAL</SerialNumber></DeviceId>
<Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode><CommandKey/></EventStruct></Event>
<MaxEnvelopes>1</MaxEnvelopes><CurrentTime>2026-09-26T12:00:00Z</CurrentTime>
<RetryCount>0</RetryCount><ParameterList/>
</cwmp:Inform></soap:Body></soap:Envelope>
XML
ok="$(curl "${flags[@]}" --cert "$tmp/client.crt" --key "$tmp/client.key" \
  -H "Content-Type: text/xml" -H "X-Client-Cert-Verified: fake-http-header" \
  -H "X-Tenant-Id: synthetic-forged" --data-binary "@$tmp/inform.xml" \
  "$url/lab/mtls/parse-inform" --output "$tmp/allowed.response" --write-out '%{http_code}')"
[[ "$ok" == 200 ]]
grep -Fq '"mtls_certificate_chain_verified":true' "$tmp/allowed.response"
grep -Fq '"tenant_bound":false' "$tmp/allowed.response"
grep -Fq '"device_enrolled":false' "$tmp/allowed.response"
if grep -Fq 'FAKE-SECRET-SERIAL' "$tmp/allowed.response"; then
  echo "SERIAL_ECHOED_FROM_UNTRUSTED_XML" >&2; exit 1
fi
denied="$(curl "${flags[@]}" --cert "$tmp/client.crt" --key "$tmp/client.key" \
  -H "Content-Type: text/xml" -H "X-Tenant-Id: forged" \
  --data-binary "@$tmp/inform.xml" "$url/cwmp" \
  --output "$tmp/denied.response" --write-out '%{http_code}')"
[[ "$denied" == 503 ]]
bad="$(curl "${flags[@]}" --cert "$tmp/client.crt" --key "$tmp/client.key" \
  -H "Content-Type: text/xml" --data '<!DOCTYPE x []><root/>' \
  "$url/lab/mtls/parse-inform" --output "$tmp/malformed.response" \
  --write-out '%{http_code}')"
[[ "$bad" == 400 ]]
if command -v ss >/dev/null 2>&1; then
  address="$(ss -H -lnt '( sport = :3433 )' | awk '{print $4}')"
  [[ "$address" == 127.0.0.1:3433 ]] || {
    echo "UNEXPECTED_MTLS_LISTEN_ADDRESS" >&2; exit 1
  }
fi
echo "R67_REAL_TLS13_CRYPTOGRAPHIC_MUTUAL_AUTH_AND_EKU_NEGATIVE_TESTS=PASS"
echo "R67_TRUE_CLIENT_CA_REQUIRED; DEVICE_TENANT_ENROLLMENT_FALSE; REAL_CWMP_503"
echo "R67_ALL_TEST_KEYS_DISPOSABLE_AND_PRIVATE_LOOPBACK_ONLY"
# Prove script teardown works, not merely that bind was private.
kill "$pid"
wait "$pid" 2>/dev/null || :
pid=""
if command -v ss >/dev/null 2>&1; then
  if ss -H -lnt '( sport = :3433 )' | grep -q .; then
    echo "R67_TEST_LISTENER_NOT_CLEANED" >&2; exit 1
  fi
fi
echo "R67_PRIVATE_LISTENER_TEARDOWN=PASS"
