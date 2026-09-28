#!/usr/bin/env bash
# R6.6 real local-only Axum HTTP parser smoke; no real device.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R66_EXACT_LOOPBACK_SMOKE:-}" == YES ]] || { echo DENIED; exit 4; }
cd "$(dirname "$0")/../../../.."
bin=./target/debug/cwmp-gateway
[[ -x "$bin" ]] || { echo BUILD_BINARY_FIRST >&2; exit 4; }
tmp="$(mktemp -d /tmp/ipat-r66-local.XXXXXXXX)"
pid=""
cleanup() {
  [[ -z "$pid" ]] || { kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; }
  [[ "$tmp" != /tmp/ipat-r66-local.* ]] || rm -rf "$tmp"
}
trap cleanup EXIT
if env -u IPAT_RUN_OFFLINE_CWMP_LAB "$bin" >/dev/null 2>&1; then
  echo 'FAIL: process starts without opt-in' >&2; exit 1
fi
IPAT_RUN_OFFLINE_CWMP_LAB=1 "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
for i in 1 2 3 4 5 6 7 8 9 10; do
  if python3 -c 'import socket; x=socket.create_connection(("127.0.0.1",3300),0.3); x.close()' 2>/dev/null; then break; fi
  sleep 0.5
done
python3 - <<'PY'
import urllib.request,urllib.error
root="http://127.0.0.1:3300"
def call(path, data=None, kind=None, extra=None):
    h=extra or {}
    if kind is not None: h["content-type"]=kind
    req=urllib.request.Request(root+path,data=data,headers=h)
    try:
        with urllib.request.urlopen(req,timeout=3) as res:
            return res.status,{k.lower():v for k,v in res.headers.items()},res.read()
    except urllib.error.HTTPError as err:
        return err.code,{k.lower():v for k,v in err.headers.items()},err.read()
xml=b"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<soap:Header><cwmp:ID soap:mustUnderstand="1">synthetic-only</cwmp:ID></soap:Header>
<soap:Body><cwmp:Inform><DeviceId><Manufacturer>TEST</Manufacturer>
<OUI>001122</OUI><ProductClass>FAKE-ONT</ProductClass>
<SerialNumber>NOT-A-REAL-DEVICE</SerialNumber></DeviceId>
<Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode><CommandKey/></EventStruct></Event>
<MaxEnvelopes>1</MaxEnvelopes><CurrentTime>2026-09-26T12:00:00Z</CurrentTime>
<RetryCount>0</RetryCount><ParameterList/></cwmp:Inform>
</soap:Body></soap:Envelope>"""
assert call("/healthz")[0]==200
assert call("/cwmp",xml,"text/xml",{"x-tenant-id":"fake","x-client-cert-verified":"true"})[0]==503
good=call("/lab/parse-inform",xml,"text/xml",{"x-tenant-id":"fake"})
assert good[0]==200 and b'"peer_authenticated":false' in good[2]
assert b'"cwmp_response_sent":false' in good[2] and b"NOT-A-REAL-DEVICE" not in good[2]
assert "no-store" in good[1].get("cache-control","")
assert call("/lab/parse-inform",xml,"application/xml")[0]==415
assert call("/lab/parse-inform",b"<!DOCTYPE x []><root/>","text/xml")[0]==400
assert call("/lab/parse-inform",b"x"*65537,"text/xml")[0]==413
assert call("/v1/tenants",xml,"text/xml")[0]==503
print("R66_REAL_LOOPBACK_HTTP_PARSER_AND_UNAUTH_CWMP_DENY=PASS")
PY
if command -v ss >/dev/null; then
  address="$(ss -H -lnt '( sport = :3300 )' | awk '{print $4}')"
  [[ "$address" == 127.0.0.1:3300 ]] || { echo LOOPBACK_BIND_FAILED >&2; exit 1; }
fi
echo R66_EXCLUSIVE_127_0_0_1_BIND_PASS
