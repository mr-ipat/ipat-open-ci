#!/usr/bin/env bash
# R8.1 real loopback Axum HTTP + genuine independently encoded BBF 1.4.
# Does not open USP MQTT MTP, enroll agents, receive real WAN or send Get.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R81_SYNTHETIC_HTTP:-}" == YES ]] || { echo R81_PRIVATE_HTTP_DENIED >&2; exit 4; }
cd "$(dirname "$0")/../../../.."
bin=./target/debug/usp-controller
[[ -x "$bin" ]] || { echo BUILD_USP_CONTROLLER_FIRST >&2; exit 4; }
[[ -f crates/usp-core/tests/fixtures/usp14_get_response.bin ]] || exit 4
python3 deploy/scripts/lab/r81/generate_golden_usp.py
tmp="$(mktemp -d /tmp/ipat-r81-loopback.XXXXXXXX)"
pid=""
cleanup() {
  if [[ -n "$pid" ]];then kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :;fi
  rm -rf "$tmp"
}
trap cleanup EXIT
if env -u IPAT_RUN_OFFLINE_USP_LAB "$bin" >"$tmp/default-out" 2>&1;then
  echo FAIL_DEFAULT_USP_ACCEPTED >&2;exit 1
fi
env -u IPAT_RUN_K3S_LAB IPAT_RUN_OFFLINE_USP_LAB=1 "$bin" \
  >"$tmp/out" 2>"$tmp/err" &
pid="$!"
for i in {1..20};do
  if python3 -c 'import socket;s=socket.create_connection(("127.0.0.1",3100),.2);s.close()' 2>/dev/null;then
    break
  fi
  sleep .2
done
python3 - <<'PY'
import json,urllib.request,urllib.error
from pathlib import Path
b="http://127.0.0.1:3100"
fixture=Path("crates/usp-core/tests/fixtures/usp14_get_response.bin").read_bytes()
def request(path="/lab/inspect-usp14",data=None,headers=None):
    r=urllib.request.Request(b+path,data=data,headers=headers or {})
    try:
        with urllib.request.urlopen(r,timeout=2) as resp:
            return resp.status,resp.headers,resp.read()
    except urllib.error.HTTPError as err:
        return err.code,err.headers,err.read()
assert request("/healthz")[0]==200
assert request("/v1/usp",data=fixture)[0]==503
assert request(data=fixture,headers={"content-type":"text/xml"})[0]==415
assert request(data=b"fake",headers={"content-type":"application/octet-stream"})[0]==400
duplicated=fixture+bytes([0x3a,0])
assert request(data=duplicated,headers={"content-type":"application/octet-stream"})[0]==400
assert request(data=b"x"*65537,headers={"content-type":"application/octet-stream"})[0]==413
status,headers,raw=request(data=fixture,headers={
    "content-type":"application/octet-stream",
    "x-tenant-id":"pretend-company",
    "x-agent-id":"usp::sim-agent-a"})
assert status==200,status
assert "no-store" in headers["cache-control"]
body=json.loads(raw)
assert body["record_structurally_valid"] is True
assert body["requested_paths"]==1 and body["resolved_paths"]==1
assert body["parameter_values"]==1
assert body["peer_authenticated"] is False and body["tenant_bound"] is False
assert body["usp_session_established"] is False
assert body["device_operations_enabled"] is False
assert body["lab_only"] is True
for sensitive in ("pretend-company","usp::sim-agent-a","SYNTHETIC","Manufacturer"):
    assert sensitive not in raw.decode()
print("R81_ACTUAL_LOOPBACK_RUST_PROTOBUF_HTTP_AND_UNTRUSTED_AGENT_DENY=PASS")
PY
if command -v ss >/dev/null;then
  address="$(ss -H -lnt '( sport = :3100 )' | awk '{print $4}')"
  [[ "$address" == "127.0.0.1:3100" ]] || { echo R81_UNSAFE_BIND >&2;exit 1; }
fi
echo R81_NO_REAL_USP_MTP_AND_EXCLUSIVE_127_0_0_1_BIND_PASS
