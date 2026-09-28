#!/usr/bin/env bash
# Restricted DEV-ONLY Site A public-key preview upgrade. NEVER activate WG.
# Nonroot on-login private :3002 only. Original :3000 MUST stay healthy.
set -Eeuo pipefail
umask 077
: "${IPAT_R917_APPROVE_PRIVATE_DEV_PREVIEW:?Require YES for developer-only Site A service}"
test "$IPAT_R917_APPROVE_PRIVATE_DEV_PREVIEW" = YES
test "$(id -un)" = openai && test "$(id -u)" -ne 0
BASE=/home/openai/.cache/ipat/r917-release
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
ROLLBACK="$BASE/rollback-unit.service"
KEY_PARENT=/home/openai/.local/share/ipat/r916-dev-keys
KEY_FILE="$KEY_PARENT/site-a-dev01-lab/public.key"
if test -e "$ROLLBACK"; then
  test "$(sha256sum "$ROLLBACK" | cut -d' ' -f1)" = b0bf33b1012dba4ff8fb967cc9b2b6dda3131e58f824d770e7ffe92dc6b2c0f8
else
  test ! -L "$ROLLBACK"
fi
test "$(git -C "$BASE/src" rev-parse HEAD)" = 7031924e8634d66fcc0b8256b7f6581808b54367
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/target/debug/control-api" | cut -d' ' -f1)" = dac06ed8e93ebaa35e8e0ba138cfdc44ce4ddaad116258cd5dadeed25fc182db
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = c7c8def73e2b087103f550fd2c67c135032b9e6ada5e7c4c89de9900d706804b
test "$(sha256sum "$BASE/actual_private_direct_protocol_http_smoke.py" | cut -d' ' -f1)" = d75a8ffcf5ea5b310c34443e9a9b84c921a2155fabf930012e119963490e5543
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = b0bf33b1012dba4ff8fb967cc9b2b6dda3131e58f824d770e7ffe92dc6b2c0f8
test "$(stat -c %a "$KEY_PARENT")" = 700
test "$(stat -c %a "$KEY_FILE")" = 600
python3 "$BASE/src/deploy/scripts/lab/r916/site_a_keypair.py" --show-public \
 --owner-only-folder "$KEY_PARENT" --site-slug dev01-lab \
 | python3 -c 'import json,sys;x=json.load(sys.stdin);assert len(x["site_a_public_key"])==44 and x["network_actions"]==0'
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
if ! test -e "$ROLLBACK"; then
  install -m 0600 "$UNIT" "$ROLLBACK"
fi
rollback() {
  trap - ERR
  echo R917_ROLLBACK_TO_PRIOR_PRIVATE_LAB_UNIT >&2
  install -m 0600 "$ROLLBACK" "$UNIT"
  systemctl --user daemon-reload
  systemctl --user reset-failed ipat-r911-preview.service
  systemctl --user restart ipat-r911-preview.service
  systemctl --user is-active ipat-r911-preview.service || true
  curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null || true
}
trap rollback ERR
install -m 0600 "$BASE/ipat-r911-preview.service" "$UNIT"
systemctl --user daemon-reload
systemctl --user restart ipat-r911-preview.service
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
# systemd active is NOT the same as application loopback readiness.
ready=false
for _ in $(seq 1 30); do
  if curl --noproxy '*' -fsS --max-time 1 \
      http://127.0.0.1:3002/lab/device-workbench >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.2
done
test "$ready" = true
IPAT_R917_ACTUAL_PRIVATE_HTTP_SMOKE=YES python3 "$BASE/actual_private_direct_protocol_http_smoke.py"
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
trap - ERR
printf '%s\n' 'R917_DEV_DIRECT_FIRST_PRIVATE_VPS_PREVIEW_PASS; ORIGINAL_3000_HEALTHY'
