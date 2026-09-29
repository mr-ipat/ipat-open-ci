#!/usr/bin/env bash
# Opt-in ONLY nonroot loopback dev preview replacement (NEVER device commands).
set -Eeuo pipefail
umask 077
: "${IPAT_R933_APPROVE_PRIVATE_LAB_CATALOG:?Explicit YES required}"
test "$IPAT_R933_APPROVE_PRIVATE_LAB_CATALOG" = YES
test "$(id -un)" = openai && test "$(id -u)" -ne 0
BASE=/home/openai/.cache/ipat/r933-release
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
OLD_SHA=0632b6fd0d08d94fffdd69118f783dc59317733ac3d4fb68cef1535bff0440c2
NEW_UNIT_SHA=5ab0d992328c68ad6c339f860fa03db325294b22c18489d06cdf5523e4456ede
NEW_BIN_SHA=13380ec652c2259bd721a497205e907b7e4a89f256479ab8e811c4c1a85cc12e
NEW_SMOKE_SHA=8e53d1cd7b25d4b88d984d4717433797602ba889b03425a02015dda03c6174d3
ROLLBACK="$BASE/rollback-user-unit.service"
test "$(git -C "$BASE/src" rev-parse HEAD)" = 10061dff2d9d48656ca7419b6fb774a76437b2a3
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/control-api" | cut -d' ' -f1)" = "$NEW_BIN_SHA"
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = "$NEW_UNIT_SHA"
test "$(sha256sum "$BASE/actual_private_verified_backup_http_smoke.py" | cut -d' ' -f1)" = "$NEW_SMOKE_SHA"
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$OLD_SHA"
test ! -e "$ROLLBACK" && test ! -L "$ROLLBACK"
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
install -m 0600 "$UNIT" "$ROLLBACK"
rollback(){
 trap - ERR
 echo 'R933_PRIVATE_DEV_PREVIEW_ROLLBACK_TO_VERIFIED_PREVIOUS_UNIT' >&2
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
IPAT_R933_APPROVE_PRIVATE_LAB_SMOKE=YES python3 "$BASE/actual_private_verified_backup_http_smoke.py"
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
trap - ERR
echo 'R933_NONROOT_PRIVATE_C320_CATALOG_DEPLOYMENT_PASS; ZERO_PHYSICAL_DEVICE_ACTIONS'
