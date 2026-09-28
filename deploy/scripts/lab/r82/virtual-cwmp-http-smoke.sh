#!/usr/bin/env bash
# Real Rust Axum loopback SOAP virtual-ONT lab, never real devices.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R82_SYNTHETIC_HTTP:-}" == YES ]] || { echo R82_DENIED; exit 4; }
cd "$(dirname "$0")/../../../.."
bin=./target/debug/cwmp-gateway
[[ -x "$bin" ]] || { echo R82_BUILD_CWMP_FIRST >&2; exit 4; }
tmp="$(mktemp -d /tmp/ipat-r82-http.XXXXXXXX)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
python3 - <<'PY'
import socket
s=socket.socket()
try: assert s.connect_ex(("127.0.0.1",3300)) != 0, "port already used"
finally: s.close()
PY
env -u IPAT_RUN_K3S_LAB IPAT_RUN_OFFLINE_CWMP_LAB=1 \
  IPAT_R82_ENABLE_VIRTUAL_ONT=YES "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
for n in 1 2 3 4 5 6 7 8 9 10; do
  if python3 -c 'import socket;s=socket.create_connection(("127.0.0.1",3300),0.3);s.close()' 2>/dev/null;then break;fi
  sleep 0.4
done
python3 deploy/scripts/lab/r82/virtual_cwmp_http_smoke.py
if command -v ss >/dev/null; then
  addr="$(ss -H -lnt '( sport = :3300 )' | awk '{print $4}')"
  [[ "$addr" == 127.0.0.1:3300 ]] || { echo R82_NOT_LOOPBACK >&2; exit 1; }
fi
echo R82_ACTUAL_RUST_CWMP_SOAP_LOOPBACK_AND_WRITE_DENIAL=PASS
