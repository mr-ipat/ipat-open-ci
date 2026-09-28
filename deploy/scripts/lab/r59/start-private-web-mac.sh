#!/usr/bin/env bash
# Mr. iPat / IPAT R5.9 — loopback-only preview, never public production deploy.
# Run ONLY on the authorized Mac after reviewed source reaches clean Git main:
#   IPAT_R59_ENABLE_PRIVATE_WEB=YES bash deploy/scripts/lab/r59/start-private-web-mac.sh
set -Eeuo pipefail
umask 077

die() { printf 'IPAT_R59_PRIVATE_WEB_BLOCKED: %s\n' "$*" >&2; exit 4; }
[[ "$(uname -s)" == Darwin && "${IPAT_R59_ENABLE_PRIVATE_WEB:-}" == YES ]] ||
  die 'requires explicit owner opt-in on the authorized Mac'
command -v gh >/dev/null && command -v ssh >/dev/null && command -v curl >/dev/null ||
  die 'requires GitHub CLI, strict SSH and curl on the Mac'
repo="$(git rev-parse --show-toplevel)" || die 'must run inside reviewed IPAT Git'
cd "$repo"
[[ "$(git branch --show-current)" == main && -z "$(git status --porcelain)" ]] ||
  die 'canonical Mac main must be clean and reviewed'
sha="$(git rev-parse HEAD)"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die 'invalid local commit'
[[ "$(gh api repos/mr-ipat/ipat/commits/main --jq .sha)" == "$sha" ]] ||
  die 'private GitHub main does not match local source'
[[ "$(/usr/bin/fdesetup status)" == 'FileVault is On.' ]] ||
  die 'local source storage FileVault must be enabled'

# Host alias ipat-lab already pins the expected host key. Never offer password
# login; both connection and tunnel fail if the identity/forward cannot verify.
ssh_args=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes
          -o ControlMaster=no -T)
ssh "${ssh_args[@]}" ipat-lab bash -s -- "$sha" <<'REMOTE'
set -Eeuo pipefail
umask 077
expected="$1"
[[ "$expected" =~ ^[0-9a-f]{40}$ ]] || exit 4
repo="$HOME/workspaces/ipat"
[[ -d "$repo/.git" && "$(git -C "$repo" branch --show-current)" == main &&
   -z "$(git -C "$repo" status --porcelain)" &&
   "$(git -C "$repo" rev-parse HEAD)" == "$expected" ]] || {
  echo 'IPAT_R59_BLOCKED: live source does not match clean reviewed main' >&2
  exit 4
}
[[ ! -e /run/ipat-ssh-stage2.active ]] || {
  echo 'IPAT_R59_BLOCKED: SSH rollback is pending' >&2; exit 4
}
command -v curl >/dev/null || { echo 'IPAT_R59_BLOCKED: curl unavailable' >&2; exit 4; }
state="$HOME/.cache/ipat-private-web"
mkdir -p -m 0700 "$state"
chmod 0700 "$state"
binary="$repo/target/release/control-api"
pidfile="$state/service.pid"
shafile="$state/source.sha"
if [[ -s "$pidfile" ]]; then
  read -r pid < "$pidfile"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null &&
      [[ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || :)" == "$binary" ]] &&
      [[ "$(cat "$shafile" 2>/dev/null || :)" == "$expected" ]]; then
    echo 'IPAT_R59_EXISTING_MATCHED_LOOPBACK_PROCESS'
  else
    echo 'IPAT_R59_BLOCKED: old PID state; manual review required' >&2
    exit 4
  fi
else
  [[ -z "$(ss -H -lnt '( sport = :3000 )')" ]] || {
    echo 'IPAT_R59_BLOCKED: preview port occupied' >&2; exit 4;
  }
  # Only the unprivileged original Rust control-api, compiled from exact Git SHA.
  cd "$repo"
  "$HOME/.cargo/bin/cargo" build -p control-api --release --locked --offline --quiet
  [[ -x "$binary" ]] || exit 4
  IPAT_LAB_WEB=1 nohup "$binary" </dev/null >>"$state/service.log" 2>&1 &
  pid=$!
  printf '%s\n' "$pid" > "$pidfile"
  printf '%s\n' "$expected" > "$shafile"
  sleep 1
fi
# Enforce exact loopback binding. No service, nftables, root or port 80/443 change.
listeners="$(ss -H -lnt '( sport = :3000 )')"
[[ "$listeners" == *'127.0.0.1:3000'* ]] &&
  ! grep -Eq '0[.]0[.]0[.]0:3000|\\[::\\]:3000|[[:space:]]\\*:3000' <<<"$listeners" ||
  { echo 'IPAT_R59_BLOCKED: non-private listener' >&2; exit 4; }
curl --silent --show-error --fail --noproxy '*' \
  http://127.0.0.1:3000/lab/status | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["mode"]=="ssh-loopback-only"
assert d["production_access"] is False
assert d["authentication_enabled"] is False
assert d["device_operations_enabled"] is False
'
echo 'IPAT_R59_VERIFIED_VPS_UNPRIVILEGED_LOOPBACK_ONLY=PASS'
REMOTE

state="$HOME/.cache/ipat-private-web"
mkdir -p -m 0700 "$state"
chmod 0700 "$state"
socket="$state/ssh-control.sock"
if [[ -e "$socket" || -S "$socket" ]]; then
  if ! ssh -S "$socket" -O check ipat-lab >/dev/null 2>&1; then
    die 'stale SSH control socket; verify process manually before cleanup'
  fi
else
  # Unix-socket controlled forward can be explicitly closed without killing
  # any unrelated SSH session. Bind localhost, NEVER external 0.0.0.0.
  ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes \
    -o ExitOnForwardFailure=yes -o ControlMaster=yes -S "$socket" \
    -f -N -L 127.0.0.1:48765:127.0.0.1:3000 ipat-lab
fi
curl --silent --show-error --fail --noproxy '*' \
  http://127.0.0.1:48765/lab/status | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["mode"]=="ssh-loopback-only"
assert d["production_access"] is False
'
curl --silent --show-error --fail --noproxy '*' \
  http://127.0.0.1:48765/lab | grep -Fq 'IPAT LAB CONSOLE'
echo 'IPAT_R59_MAC_BROWSER_TUNNEL_END_TO_END=PASS'
echo 'OPEN_ONLY_ON_AUTHORIZED_MAC: http://127.0.0.1:48765/lab'
echo 'PUBLIC_PRODUCTION_WEB: NOT_READY'
