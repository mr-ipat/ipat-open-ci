#!/usr/bin/env bash
# Strict synthetic ONLY actual Rust HTTP server test; not physical CPE onboarding.
set -Eeuo pipefail
umask 077
[[ "${IPAT_R83_DEMO_HTTP:-}" == YES ]] || { echo R83_OPT_IN_REQUIRED; exit 4; }
cd "$(dirname "$0")/../../../.."
bin=./target/debug/control-api
[[ -x "$bin" ]] || { echo BUILD_CONTROL_API_FIRST >&2; exit 4; }
tmp="$(mktemp -d /tmp/ipat-r83-http.XXXXXXXX)"
pid=""
cleanup(){
  if [[ -n "$pid" ]];then kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :;fi
  rm -rf "$tmp"
}
trap cleanup EXIT
python3 - <<'PY'
import socket
s=socket.socket()
try:assert s.connect_ex(("127.0.0.1",3000))!=0,"port already in use"
finally:s.close()
PY
env -u IPAT_RUN_K3S_LAB -u IPAT_LAB_OIDC_VERIFY \
 -u IPAT_LAB_SCOPED_MEMBERSHIP -u IPAT_R83_REGISTRY_WRITE \
 IPAT_LAB_WEB=1 "$bin" >"$tmp/stdout" 2>"$tmp/stderr" &
pid="$!"
for i in 1 2 3 4 5 6 7 8 9 10;do
 if python3 -c 'import socket;x=socket.create_connection(("127.0.0.1",3000),0.3);x.close()' 2>/dev/null;then break;fi
 sleep .4
done
python3 deploy/scripts/lab/r83/workbench_http_smoke.py
if command -v ss >/dev/null;then
  address="$(ss -H -lnt '( sport = :3000 )' | awk '{print $4}')"
  [[ "$address" == 127.0.0.1:3000 ]] || { echo R83_NOT_EXCLUSIVELY_LOCAL;exit 1; }
fi
echo R83_RESTRICTED_SYNTHETIC_HTTP_AND_HARD_REAL_API_DENIAL=PASS
