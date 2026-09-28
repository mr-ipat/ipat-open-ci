#!/usr/bin/env bash
# Synthetic RS256 JWT real HTTP on owner-controlled localhost only.
# NEVER a production IdP, verified tenant membership, or dashboard login.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R69_RUN_SYNTHETIC_HTTP:-}" == YES ]] || { echo R69_NO_EXPLICIT_OPT_IN >&2; exit 4; }
cd "$(dirname "$0")/../../../.."
bin=./target/debug/control-api
[[ -x "$bin" ]] || { echo R69_BUILD_CONTROL_API_FIRST >&2; exit 4; }
for command in openssl python3; do
  command -v "$command" >/dev/null || { echo R69_MISSING_LOCAL_TEST_PREREQUISITE >&2; exit 4; }
done
python3 - <<'PY'
import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try:
    s.bind(("127.0.0.1",3001))
    s.listen(1)
finally: s.close()
PY
tmp="$(mktemp -d /tmp/ipat-r69-jwt.XXXXXXXX)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" >/dev/null 2>&1 || :
    wait "$pid" >/dev/null 2>&1 || :
  fi
  if [[ "$tmp" == /tmp/ipat-r69-jwt.* && -d "$tmp" ]]; then
    rm -rf -- "$tmp"
  fi
}
trap cleanup EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$tmp/issuer-test-only.key" >/dev/null 2>&1
openssl pkey -pubout -in "$tmp/issuer-test-only.key" \
  -out "$tmp/issuer-public.pem" >/dev/null 2>&1
chmod 0600 "$tmp"/*.pem "$tmp"/*.key
# Key provenance and issuer configuration are synthetic and owner-controlled.
IPAT_LAB_WEB=1 IPAT_LAB_OIDC_VERIFY=YES \
  IPAT_LAB_OIDC_PUBLIC_KEY_FILE="$tmp/issuer-public.pem" \
  IPAT_LAB_OIDC_ISSUER='https://id.example.invalid/realms/ipat' \
  IPAT_LAB_OIDC_AUDIENCE=ipat-control-api \
  IPAT_LAB_OIDC_KID=lab-test-only \
  "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if python3 - <<'PY' 2>/dev/null
import socket
with socket.create_connection(("127.0.0.1",3001),0.3): pass
PY
  then break; fi
  sleep 0.5
done
python3 - "$tmp/issuer-test-only.key" <<'PY'
import base64,json,subprocess,sys,time,urllib.request,urllib.error
from pathlib import Path
private=Path(sys.argv[1])
def b64(blob): return base64.urlsafe_b64encode(blob).rstrip(b"=")
def token(*,valid=True):
    now=int(time.time())
    header={"alg":"RS256","typ":"JWT","kid":"lab-test-only"}
    claims={"iss":"https://id.example.invalid/realms/ipat",
        "aud":"ipat-control-api","sub":"synthetic-operator",
        "iat":now,"nbf":now,"exp":now+300,
        "tenant_id":"synthetic-cross-tenant",
        "roles":["platform_owner","tenant_admin"]}
    if not valid: claims["iss"]="https://untrusted.example.invalid/realms/ipat"
    contents=b".".join(b64(json.dumps(obj,separators=(",",":")).encode())
                       for obj in (header,claims))
    signed=subprocess.run(["openssl","dgst","-sha256","-sign",str(private)],
                          input=contents,capture_output=True,check=True).stdout
    return (contents+b"."+b64(signed)).decode("ascii")
root="http://127.0.0.1:3001"
def request(path,method="GET",bearer=None,headers=None):
    h={"Cache-Control":"no-store"}
    if bearer is not None:h["Authorization"]="Bearer "+bearer
    h.update(headers or {})
    req=urllib.request.Request(root+path,method=method,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=3) as resp:
            return resp.status,{k.lower():v for k,v in resp.headers.items()},resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code,{k.lower():v for k,v in exc.headers.items()},exc.read()
valid=token()
good=request("/lab/auth/verify",bearer=valid,
    headers={"X-Tenant-Id":"synthetic-other","X-Role":"platform_owner"})
assert good[0]==200 and good[1].get("cache-control")=="no-store"
assert json.loads(good[2])=={"jwt_signature_verified":True,
    "tenant_membership_verified":False,"business_access_enabled":False,
    "roles_verified":False}
assert b"synthetic-operator" not in good[2]
assert request("/lab/auth/verify")[0]==401
assert request("/lab/auth/verify",bearer=token(valid=False))[0]==401
assert request("/lab/auth/verify",method="POST",bearer=valid)[0]==405
for path in ("/v1/platform/tenants","/v1/tenant/members",
             "/v1/operations/alerts"):
    for method in ("GET","POST"):
        status,_,_=request(path,method,bearer=valid,
            headers={"X-Tenant-Id":"synthetic-other","X-Role":"platform_owner"})
        assert status==401,(path,method,status)
assert request("/v1/devices/FAKE-ONLY",bearer=valid)[0]==401
assert request("/v1/devices/FAKE-ONLY",method="POST",bearer=valid)[0]==405
assert request("/lab/dashboard-preview")[0]==200
print("R69_ACTUAL_LOOPBACK_RS256_VERIFIED_JWT_PRIVATE_HTTP=PASS")
print("R69_SIGNED_TOKEN_STILL_NO_TENANT_MEMBERSHIP_AND_BUSINESS_APIS_401=PASS")
PY
kill "$pid"
wait "$pid" 2>/dev/null || :
pid=""
python3 - <<'PY'
import socket
s=socket.socket();s.settimeout(0.3)
try:
    s.connect(("127.0.0.1",3001))
    raise AssertionError("R69 owned lab listener still running")
except (OSError,ConnectionRefusedError):
    pass
finally:s.close()
print("R69_PRIVATE_TEST_LISTENER_AND_TEMP_KEYS_CLEANED=PASS")
PY
