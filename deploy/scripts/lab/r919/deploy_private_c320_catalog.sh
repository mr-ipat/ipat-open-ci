#!/usr/bin/env bash
# Opt-in ONLY nonroot loopback dev preview replacement (NEVER device commands).
set -Eeuo pipefail
umask 077
: "${IPAT_R919_APPROVE_PRIVATE_LAB_CATALOG:?Explicit YES required}"
test "$IPAT_R919_APPROVE_PRIVATE_LAB_CATALOG" = YES
test "$(id -un)" = openai && test "$(id -u)" -ne 0
BASE=/home/openai/.cache/ipat/r919-release
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
OLD_SHA=c7c8def73e2b087103f550fd2c67c135032b9e6ada5e7c4c89de9900d706804b
NEW_UNIT_SHA=7d8e09dc50ecc52c4dc15514f98f0b2bdb1b2295538a34f2186b352a5bb47c37
NEW_BIN_SHA=7478f575a8bb2bb9f984ba15a8dd6cd18b68beb3db78d6a7aeaef2e906a8c9a4
NEW_SMOKE_SHA=2c5e477ca4f1b75e6d9f495e08bfeebe105e91c08865d28a26f7864eaca9b488
ROLLBACK="$BASE/rollback-user-unit.service"
test "$(git -C "$BASE/src" rev-parse HEAD)" = 13bed31bf434e0cb2455b0ee5ffd67db4bff5327
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/target/debug/control-api" | cut -d' ' -f1)" = "$NEW_BIN_SHA"
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = "$NEW_UNIT_SHA"
test "$(sha256sum "$BASE/actual_private_c320_catalog_http_smoke.py" | cut -d' ' -f1)" = "$NEW_SMOKE_SHA"
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = "$OLD_SHA"
test ! -e "$ROLLBACK" && test ! -L "$ROLLBACK"
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
install -m 0600 "$UNIT" "$ROLLBACK"
rollback(){
 trap - ERR
 echo 'R919_PRIVATE_DEV_PREVIEW_ROLLBACK_TO_VERIFIED_PREVIOUS_UNIT' >&2
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
IPAT_R919_APPROVE_PRIVATE_LAB_SMOKE=YES python3 "$BASE/actual_private_c320_catalog_http_smoke.py"
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
trap - ERR
echo 'R919_NONROOT_PRIVATE_C320_CATALOG_DEPLOYMENT_PASS; ZERO_PHYSICAL_DEVICE_ACTIONS'
