#!/usr/bin/env bash
# Actual compiled Rust PRIVATE browser OIDC start-state PKCE socket proof.
# Never uses a real IdP, human MFA, token endpoint or physical hardware.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R86_BROWSER_TEST:-}" == YES ]] || { echo R86_EXPLICIT_TEST_OPT_IN_REQUIRED; exit 4; }
cd "$(dirname "$0")/../../../.."
bin=./target/debug/control-api
[[ -x "$bin" ]] || { echo R86_COMPILE_RUST_BINARY_FIRST >&2; exit 4; }
python3 - <<'PY'
import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try: s.bind(("127.0.0.1",3001))
finally: s.close()
PY
tmp="$(mktemp -d /tmp/ipat-r86-browser.XXXXXXXX)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :;fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$tmp/synthetic-rsa.key" >/dev/null 2>&1
openssl pkey -pubout -in "$tmp/synthetic-rsa.key" \
  -out "$tmp/synthetic-rsa.pub" >/dev/null 2>&1
chmod 600 "$tmp"/*.key "$tmp"/*.pub
env -u IPAT_RUN_K3S_LAB -u IPAT_LAB_SCOPED_MEMBERSHIP \
  -u IPAT_R83_REGISTRY_WRITE -u IPAT_R84_SIMULATED_REVIEW \
  IPAT_LAB_WEB=1 IPAT_LAB_OIDC_VERIFY=YES \
  IPAT_LAB_OIDC_PUBLIC_KEY_FILE="$tmp/synthetic-rsa.pub" \
  IPAT_LAB_OIDC_ISSUER="https://id.example.invalid/realms/ipat" \
  IPAT_LAB_OIDC_AUDIENCE="ipat-control-api" \
  IPAT_LAB_OIDC_KID="r86-ephemeral-lab" \
  IPAT_R86_BROWSER_FLOW=YES \
  IPAT_R86_KEYCLOAK_AUTH_ENDPOINT="https://id.example.invalid/realms/ipat/protocol/openid-connect/auth" \
  IPAT_R86_PUBLIC_CLIENT_ID="ipat-browser-lab" \
  "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if python3 -c 'import socket;x=socket.create_connection(("127.0.0.1",3001),.3);x.close()' 2>/dev/null;then break;fi
  sleep 0.5
done
python3 deploy/scripts/lab/r86/browser_http_smoke.py
if command -v ss >/dev/null;then
  addr="$(ss -H -lnt '( sport = :3001 )' | awk '{print $4}')"
  [[ "$addr" == 127.0.0.1:3001 ]] || { echo R86_NOT_EXCLUSIVE_LOOPBACK >&2; exit 1; }
fi
echo R86_ACTUAL_COMPILED_RUST_PRIVATE_OIDC_BROWSER_PKCE_HTTP=PASS
