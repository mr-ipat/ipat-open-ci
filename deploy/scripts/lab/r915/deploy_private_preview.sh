#!/usr/bin/env bash
# Owner VPS ONLY. Replace private LAB :3002, preserving original :3000.
# No root, firewall, device credentials, VPN activation or customer I/O.
set -Eeuo pipefail
umask 077
: "${IPAT_R915_APPROVE_PRIVATE_PREVIEW:?Require YES for LAB-only user service}"
test "$IPAT_R915_APPROVE_PRIVATE_PREVIEW" = YES
test "$(id -un)" = openai
test "$(id -u)" -ne 0

BASE=/home/openai/.cache/ipat/r915-preview
UNIT=/home/openai/.config/systemd/user/ipat-r911-preview.service
ROLLBACK="$BASE/rollback-unit.service"
test ! -e "$ROLLBACK"
test "$(git -C "$BASE/src" rev-parse HEAD)" = 7149b0bf62cd9da095798ec4df24976905bab973
test -z "$(git -C "$BASE/src" status --porcelain)"
test "$(sha256sum "$BASE/target/debug/control-api" | cut -d' ' -f1)" = a236e184e8c0e6abaa0feda9095dfb5c2d3e56fd00f343eef61e668d3c41eaa9
test "$(sha256sum "$BASE/ipat-r911-preview.service" | cut -d' ' -f1)" = 173342749889114bc32c40d75f365b9711036fab72200c65c8d18527bc9fe3df
test "$(sha256sum "$BASE/actual_lab_hub_http_smoke.py" | cut -d' ' -f1)" = 5b599ae65c7bafd1430905f64ce89d3c75baf24b9a4a933d950ed3e90637ebaa
test "$(sha256sum "$UNIT" | cut -d' ' -f1)" = 2f9d254675c9080b94287035a0722e1e3c7b41f233fce679bfd50b11b52d72c1
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
install -m 0600 "$UNIT" "$ROLLBACK"
rollback() {
  trap - ERR
  echo "R915_PREVIEW_FAILED_ROLLBACK_TO_PRIOR_USER_UNIT" >&2
  install -m 0600 "$ROLLBACK" "$UNIT"
  systemctl --user daemon-reload
  systemctl --user restart ipat-r911-preview.service
  systemctl --user is-active ipat-r911-preview.service || true
  curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null || true
}
trap rollback ERR

install -m 0600 "$BASE/ipat-r911-preview.service" "$UNIT"
systemctl --user daemon-reload
systemctl --user restart ipat-r911-preview.service
test "$(systemctl --user is-active ipat-r911-preview.service)" = active
IPAT_R915_LAB_HTTP_SMOKE=YES python3 "$BASE/actual_lab_hub_http_smoke.py"
curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:3000/healthz >/dev/null
test "$(systemctl --user is-enabled ipat-r911-preview.service)" = enabled
trap - ERR
echo "R915_ACTUAL_PRIVATE_VPS_PREVIEW_PASS; previous :3000 remains healthy"
