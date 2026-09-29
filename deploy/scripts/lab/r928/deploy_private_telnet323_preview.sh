#!/usr/bin/env bash
# Opt-in ONLY nonroot loopback dev preview replacement (NEVER device commands).
set -Eeuo pipefail
umask 077
: "${IPAT_R928_APPROVE_PRIVATE_LAB_CATALOG:?Explicit YES required}"
test "$IPAT_R928_APPROVE_PRIVATE_LAB_CATALOG" = YES
test "$(id -un)" = openai && test "$(id -u)" -ne 0
BASE=/home/openai/.cache/ipat/r928-release
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
OLD_SHA=7e51794041be571536562f7e7f407d5f9958b0fce21906a5aa4a3b88935c0b75
NEW_UNIT_SHA=9d1fe8ed0f9474b53a4e16e7f93eec4f0710f7f8345b57564301e4dbc569eb41
NEW_BIN_SHA=b7f89ce39a0b392ee582d3818e990db74a7111c832761e5d019eb079cfd47245
NEW_SMOKE_SHA=83101eb7af053f682b4a0a89be806507ec42f7fedc0e578a4adf9ab819c2e9c4
ROLLBACK="$BASE/rollback-user-unit.service"
test "$(git -C "$BASE/src" rev-parse HEAD)" = 8bac456c97899bbd27f9db79499565026cdeb1d0
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/target/debug/control-api" | cut -d' ' -f1)" = "$NEW_BIN_SHA"
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = "$NEW_UNIT_SHA"
test "$(sha256sum "$BASE/actual_private_telnet323_http_smoke.py" | cut -d' ' -f1)" = "$NEW_SMOKE_SHA"
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$OLD_SHA"
test ! -e "$ROLLBACK" && test ! -L "$ROLLBACK"
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
install -m 0600 "$UNIT" "$ROLLBACK"
rollback(){
 trap - ERR
 echo 'R928_PRIVATE_DEV_PREVIEW_ROLLBACK_TO_VERIFIED_PREVIOUS_UNIT' >&2
 install -m 0600 "$ROLLBACK" "$UNIT"
 systemctl --user daemon-reload
 systemctl --user reset-failed ipat-r911-preview.service
 systemctl --user restart ipat-r911-preview.service
}
trap rollback ERR
install -m 0600 "$BASE/ipat-r911-preview.service" "$UNIT"
systemctl --user daemon-reload
systemctl --user reset-failed ipat-r911-preview.service
systemctl --user restart ipat-r911-preview.service
ready=false
for _ in $(seq 1 30); do
 if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:3002/lab/device-workbench >/dev/null 2>&1; then
   ready=true; break
 fi
 sleep 0.25
done
test "$ready" = true
IPAT_R928_APPROVE_PRIVATE_LAB_SMOKE=YES python3 "$BASE/actual_private_telnet323_http_smoke.py"
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
trap - ERR
echo 'R928_NONROOT_PRIVATE_C320_CATALOG_DEPLOYMENT_PASS; ZERO_PHYSICAL_DEVICE_ACTIONS'
