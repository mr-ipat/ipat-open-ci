#!/usr/bin/env bash
# Mr. iPat: stop ONLY the R5.9 lab tunnel and precisely tracked non-root process.
set -Eeuo pipefail
umask 077
[[ "$(uname -s)" == Darwin && "${IPAT_R59_STOP_PRIVATE_WEB:-}" == YES ]] || {
  echo 'R59_STOP_DENIED: explicit authorized Mac opt-in required' >&2; exit 4;
}
state="$HOME/.cache/ipat-private-web"
socket="$state/ssh-control.sock"
if [[ -S "$socket" ]]; then
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -S "$socket" -O exit ipat-lab
fi
ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes \
    -o ControlMaster=no -T ipat-lab bash -s <<'REMOTE'
set -Eeuo pipefail
state="$HOME/.cache/ipat-private-web"
pidfile="$state/service.pid"
binary="$HOME/workspaces/ipat/target/release/control-api"
if [[ -f "$pidfile" ]]; then
  read -r pid < "$pidfile"
  [[ "$pid" =~ ^[0-9]+$ ]] || exit 4
  if kill -0 "$pid" 2>/dev/null; then
    [[ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || :)" == "$binary" ]] ||
      { echo 'R59_STOP_DENIED: PID mismatch' >&2; exit 4; }
    kill -TERM "$pid"
  fi
  rm -f -- "$state/service.pid" "$state/source.sha"
fi
echo 'R59_NONROOT_PREVIEW_STOP_REQUESTED'
REMOTE
echo 'R59_MAC_LOCAL_TUNNEL_STOP_REQUESTED'
