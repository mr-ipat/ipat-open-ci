#!/usr/bin/env bash
# Restricted DEV-ONLY Site A public-key preview upgrade. NEVER activate WG.
# Nonroot on-login private :3002 only. Original :3000 MUST stay healthy.
set -Eeuo pipefail
umask 077
: "${IPAT_R916_APPROVE_PRIVATE_DEV_PREVIEW:?Require YES for developer-only Site A service}"
test "$IPAT_R916_APPROVE_PRIVATE_DEV_PREVIEW" = YES
test "$(id -un)" = openai && test "$(id -u)" -ne 0
BASE=/home/openai/.cache/ipat/r916-preview
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
ROLLBACK="$BASE/rollback-unit.service"
KEY_PARENT=/home/openai/.local/share/ipat/r916-dev-keys
KEY_FILE="$KEY_PARENT/site-a-dev01-lab/public.key"
if test -e "$ROLLBACK"; then
  test "$(sha256sum "$ROLLBACK" | cut -d' ' -f1)" = 173342749889114bc32c40d75f365b9711036fab72200c65c8d18527bc9fe3df
else
  test ! -L "$ROLLBACK"
fi
test "$(git -C "$BASE/src" rev-parse HEAD)" = 63c42e333e1351b477a073ef5983ffdb100ee1a2
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/target/debug/control-api" | cut -d' ' -f1)" = 3fb2d5369a1e42b35a05ba4c128ab0b8f8414c1997f02c7a1085741587db46da
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = b0bf33b1012dba4ff8fb967cc9b2b6dda3131e58f824d770e7ffe92dc6b2c0f8
test "$(sha256sum "$BASE/actual_private_site_a_http_smoke.py" | cut -d' ' -f1)" = 2d549259a4efb3b3aa0e519979aa229965e316dcd8d2b45646c7e572f9e86ad7
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = 173342749889114bc32c40d75f365b9711036fab72200c65c8d18527bc9fe3df
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
  echo R916_ROLLBACK_TO_PRIOR_PRIVATE_LAB_UNIT >&2
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
IPAT_R916_ACTUAL_PRIVATE_HTTP_SMOKE=YES python3 "$BASE/actual_private_site_a_http_smoke.py"
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
trap - ERR
printf '%s\n' 'R916_DEV_SITE_A_PUBLIC_ONLY_PRIVATE_VPS_PREVIEW_PASS; ORIGINAL_3000_HEALTHY'
