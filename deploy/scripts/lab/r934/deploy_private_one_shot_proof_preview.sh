#!/usr/bin/env bash
# Opt-in ONLY nonroot loopback dev preview replacement (NEVER device commands).
set -Eeuo pipefail
umask 077
: "${IPAT_R934_APPROVE_PRIVATE_LAB_CATALOG:?Explicit YES required}"
test "$IPAT_R934_APPROVE_PRIVATE_LAB_CATALOG" = YES
test "$(id -un)" = openai && test "$(id -u)" -ne 0
BASE=/home/openai/.cache/ipat/r934-release
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
OLD_SHA=5ab0d992328c68ad6c339f860fa03db325294b22c18489d06cdf5523e4456ede
NEW_UNIT_SHA=10d45985ffaf9d2040cb02216752133230c9e497d14bf55db0f7ba0ff71a63de
NEW_BIN_SHA=b422b6c66d1affbfde54a1afebd4cf98aee87f182e268376f0fd28de6dbbf057
NEW_SMOKE_SHA=2dcde2216ba10251c110f0a258c7152091cbabeaacc9ecd9008ea444def9dfba
ROLLBACK="$BASE/rollback-user-unit.service"
test "$(git -C "$BASE/src" rev-parse HEAD)" = 90663bcccfff0139c721a93b26ae5f224a8f0a4f
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/control-api" | cut -d' ' -f1)" = "$NEW_BIN_SHA"
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = "$NEW_UNIT_SHA"
test "$(sha256sum "$BASE/actual_private_one_shot_http_smoke.py" | cut -d' ' -f1)" = "$NEW_SMOKE_SHA"
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$OLD_SHA"
test ! -e "$ROLLBACK" && test ! -L "$ROLLBACK"
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
install -m 0600 "$UNIT" "$ROLLBACK"
rollback(){
 trap - ERR
 echo 'R934_PRIVATE_DEV_PREVIEW_ROLLBACK_TO_VERIFIED_PREVIOUS_UNIT' >&2
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
IPAT_R934_APPROVE_PRIVATE_LAB_SMOKE=YES python3 "$BASE/actual_private_one_shot_http_smoke.py"
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
trap - ERR
echo 'R934_NONROOT_PRIVATE_C320_CATALOG_DEPLOYMENT_PASS; ZERO_PHYSICAL_DEVICE_ACTIONS'
