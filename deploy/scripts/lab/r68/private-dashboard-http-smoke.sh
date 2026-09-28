#!/usr/bin/env bash
# R6.8 ephemeral real HTTP test. Must run only on disposable CI runner.
set -Eeuo pipefail
umask 077
[[ "${GITHUB_ACTIONS:-}" == true &&
   "${IPAT_R68_PRIVATE_HTTP_SMOKE:-}" == YES ]] || {
  echo "R68_REFUSED_DISPOSABLE_CI_AND_EXPLICIT_OPTIN_REQUIRED" >&2
  exit 4
}
cd "$(dirname "$0")/../../../.."
bin=./target/debug/control-api
[[ -x "$bin" ]] || {
  echo "R68_BUILD_CONTROL_API_FIRST" >&2
  exit 4
}
# Do NOT disturb an existing local service, even on CI.
python3 - <<'PY'
import socket
sock=socket.socket()
try:
    # An earlier REAL R8.3 localhost HTTP test may leave outbound TCP sockets
    # in TIME_WAIT after its own Rust child exited. SO_REUSEADDR is safe here
    # only with listen(): an ACTUAL active listener still raises EADDRINUSE.
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(("127.0.0.1",3000))
    sock.listen(1)
finally:
    sock.close()
PY
tmp="$(mktemp -d /tmp/ipat-r68-http.XXXXXXXX)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || :
    wait "$pid" 2>/dev/null || :
  fi
  [[ "$tmp" == /tmp/ipat-r68-http.* && -d "$tmp" ]] && rm -rf -- "$tmp"
  :
}
trap cleanup EXIT
IPAT_LAB_WEB=1 "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl --silent --fail --connect-timeout 1 --max-time 2 \
     --noproxy '*' 'http://127.0.0.1:3000/healthz' >"$tmp/health" 2>/dev/null; then
    break
  fi
  sleep 0.3
done
python3 - <<'PY'
import urllib.request,urllib.error,json
root="http://127.0.0.1:3000"
def request(path,method="GET"):
    req=urllib.request.Request(root+path,method=method,headers={
        "Authorization":"Bearer forged.synthetic.token",
        "X-Tenant-Id":"cross-tenant-forged",
        "X-Verified-Role":"platform_owner",
        "Host":"attacker-tenant.invalid"
    })
    try:
        with urllib.request.urlopen(req,timeout=3) as response:
            return response.status,{k.lower():v for k,v in response.headers.items()},response.read()
    except urllib.error.HTTPError as err:
        return err.code,{k.lower():v for k,v in err.headers.items()},err.read()
for path,mime in [
    ("/lab/dashboard-preview","text/html; charset=utf-8"),
    ("/lab/dashboard-preview.css","text/css; charset=utf-8"),
    ("/lab/dashboard-preview.js","text/javascript; charset=utf-8"),
]:
    code,headers,body=request(path)
    assert code==200 and headers["content-type"]==mime, path
    assert "no-store" in headers["cache-control"]
    assert "default-src 'none'" in headers["content-security-policy"]
    assert len(body)>100
html=request("/lab/dashboard-preview")[2].decode()
assert "Platform Admin" in html and "Tenant Admin" in html
assert "Operasional" in html and "Data contoh sintetis" in html
assert request("/lab/dashboard-preview","POST")[0]==405
phase_code,phase_headers,phase_body=request("/lab/rollout-phase")
assert phase_code==200 and phase_headers["content-type"]=="application/json; charset=utf-8"
assert "no-store" in phase_headers["cache-control"]
phase=json.loads(phase_body)
assert phase["domain_verification_deferred"] is True
assert phase["custom_domains_enabled"] is False
assert phase["public_tenant_hostnames_enabled"] is False
assert phase["tenant_isolation_mandatory"] is True
assert phase["tenant_isolation_end_to_end_verified"] is False
assert phase["authenticated_tenant_data_apis_enabled"] is False
assert phase["physical_device_connected"] is False
assert phase["device_reads_approved"] is False
assert phase["firmware_updates_enabled"] is False
for method in ("POST","PUT","DELETE"):
    assert request("/lab/rollout-phase",method)[0]==405
assert "ISOLASI DATA TENANT TIDAK BOLEH DITUNDA" in html
state=request("/lab/status")
assert state[0]==200
payload=json.loads(state[2])
assert payload["production_access"] is False and payload["authentication_enabled"] is False
for prefix in ("platform","tenant","operations"):
    for method in ("GET","POST","DELETE"):
        code,headers,_=request("/v1/"+prefix+"/overview",method)
        assert code==401,(prefix,method,code)
        assert "no-store" in headers["cache-control"]
assert request("/v1/devices/DEV-08")[0]==401
print("R68_ACTUAL_PRIVATE_HTTP_THREE_DASHBOARD_ASSETS_AND_FORGED_API_DENY=PASS")
PY
if command -v ss >/dev/null 2>&1; then
  address="$(ss -H -lnt '( sport = :3000 )' | awk '{print $4}')"
  [[ "$address" == 127.0.0.1:3000 ]] || {
    echo "R68_PRIVATE_SERVER_BOUND_UNEXPECTED_NETWORK_ADDRESS" >&2; exit 1
  }
fi
kill "$pid"
wait "$pid" 2>/dev/null || :
pid=""
if command -v ss >/dev/null 2>&1; then
  if ss -H -lnt '( sport = :3000 )' | grep -q .; then
    echo "R68_HTTP_SMOKE_DID_NOT_CLEAN_OWN_LISTENER" >&2; exit 1
  fi
fi
echo "R68_EPHEMERAL_CI_PRIVATE_LISTENER_STOPPED=PASS"
