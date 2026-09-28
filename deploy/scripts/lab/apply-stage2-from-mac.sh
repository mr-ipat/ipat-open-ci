#!/usr/bin/env bash
# Run ONLY in the project owner's interactive Mac Terminal with VPS console open.
# A timer automatically restores the previous SSH config unless confirmed.
set -Eeuo pipefail
umask 077
repo="$HOME/Projects/ipat-current"
server_repo=/home/openai/workspaces/ipat
remote_stage="$server_repo/deploy/scripts/lab/stage2-ssh-key-only.sh"
root_stage=/root/ipat-bootstrap/stage2-ssh.sh
reviewed_stage_sha=800f1d228e7b19578569122d5a9ff4c4966b8d5520d4a9ac713b892edf9b3425
reviewed_partial_backup_sha=2d74782d0e418262701107be01e91c0ea87d3b7406803ca58acdb91a57338a77
fatal() { echo "ABORT: $*" >&2; exit 1; }
[[ -t 0 && -d "$repo/.git" ]] || fatal "interactive authorized Mac Terminal required"
[[ "$(git -C "$repo" branch --show-current)" == main ]] || fatal "switch to main first"
[[ -z "$(git -C "$repo" status --porcelain)" ]] || fatal "uncommitted changes on Mac"
[[ "$(git -C "$repo" rev-parse HEAD)" == \
   "$(gh api repos/mr-ipat/ipat/commits/main --jq .sha)" ]] ||
    fatal "local main differs from private GitHub; review and sync before proceeding"
[[ "$(shasum -a 256 "$repo/deploy/scripts/lab/stage2-ssh-key-only.sh" | awk '{print $1}')" == \
   "$reviewed_stage_sha" ]] || fatal "privileged script hash does not match reviewed source"
bash -n "$repo/deploy/scripts/lab/stage2-ssh-key-only.sh"
backup="$HOME/IPAT-secure-backups/readonly-config-20260925T073601Z/READABLE-CONFIG-PARTIAL.tar.gz"
[[ -s "$backup" ]] || fatal "off-host partial backup missing"
[[ "$(shasum -a 256 "$backup" | awk '{print $1}')" == "$reviewed_partial_backup_sha" ]] ||
    fatal "off-host partial backup digest mismatch"
tar -tzf "$backup" >/dev/null
echo "REVIEWED_SCRIPT_AND_OFFHOST_PARTIAL_BACKUP_DIGESTS_PASS"
echo "WARNING: NO VPS SNAPSHOT OR FULL OFFSITE RECOVERY COPY EXISTS"

ssh_common=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ControlMaster=no -o ConnectTimeout=8)
ssh -T "${ssh_common[@]}" ipat-lab 'test "$(id -un)" = openai &&
  test -s "$HOME/.ssh/authorized_keys" && systemctl is-active --quiet ssh' ||
    fatal "fresh key-only SSH baseline failed"
echo "INDEPENDENT_KEY_ONLY_SSH_BASELINE_PASS"

# Transfer only verified source, not GitHub tokens or Mac private SSH keys.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/ipat-stage2.XXXXXXXX")"
trap 'rm -rf "$tmp"' EXIT
git -C "$repo" bundle create "$tmp/main.bundle" main
git -C "$repo" bundle verify "$tmp/main.bundle" >/dev/null
scp -q "${ssh_common[@]}" "$tmp/main.bundle" ipat-lab:.cache/ipat/ipat-stage2.bundle
ssh -T "${ssh_common[@]}" ipat-lab '
set -eu
repo="$HOME/workspaces/ipat"
test -z "$(git -C "$repo" status --porcelain)"
git -C "$repo" fetch -q "$HOME/.cache/ipat/ipat-stage2.bundle" main
git -C "$repo" merge --ff-only -q FETCH_HEAD
rm -f "$HOME/.cache/ipat/ipat-stage2.bundle"
'
actual="$(ssh -T "${ssh_common[@]}" ipat-lab 'git -C "$HOME/workspaces/ipat" rev-parse HEAD')"
expected="$(git -C "$repo" rev-parse HEAD)"
[[ "$actual" == "$expected" ]] || fatal "remote Git commit mismatch"
ssh -T "${ssh_common[@]}" ipat-lab "bash -n '$remote_stage' && bash '$remote_stage' --check" ||
    fatal "Ubuntu read-only root-script preflight failed"
echo "UBUNTU_STAGE2_READ_ONLY_PREFLIGHT_PASS"

cat <<'WARNING'
STAGE-2 PROPOSED CHANGES (SSH ONLY):
- Set PermitRootLogin=no (remote root SSH denied; provider VPS console unaffected).
- Set PasswordAuthentication=no globally for SSH (other password-only SSH
  users will also lose SSH access).
- Keep SSH port 22, existing user keys, firewall and routing unchanged.
- Install ONLY /etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf.
- Arm systemd automatic rollback BEFORE changing SSH config.
- You must re-authenticate as openai from a fresh connection and disarm the
  rollback timer within SIX MINUTES.
- Existing root config is copied locally on the VPS; off-host Mac archive is
  PARTIAL and NOT a full VPS snapshot.
Have a WORKING provider console session open throughout this procedure.
WARNING
read -r -p 'Type CONSOLE_READY only after testing console access: ' console
[[ "$console" == CONSOLE_READY ]] || fatal "console recovery not confirmed"
read -r -p 'Type DISABLE_PASSWORD_SSH to authorize changes to all SSH accounts: ' approval
[[ "$approval" == DISABLE_PASSWORD_SSH ]] || fatal "SSH hardening not authorized"

echo "Password prompt below is the Linux openai sudo password on YOUR Mac."
# Root-owned script is verified again AFTER root copies it, before execution.
ssh -tt "${ssh_common[@]}" ipat-lab \
  "sudo -k -v && sudo install -d -o root -g root -m 0700 /root/ipat-bootstrap && \
   sudo install -o root -g root -m 0700 '$remote_stage' '$root_stage' && \
   printf '%s  %s\\n' '$reviewed_stage_sha' '$root_stage' | sudo sha256sum --check - && \
   sudo env IPAT_STAGE2_APPROVED=yes IPAT_STAGE2_CONSOLE_READY=yes \
     /bin/bash '$root_stage' --apply" ||
   fatal "apply failed; wait for timed rollback if policy changed; use provider console"

echo "Immediately validating a NEW key-only session (not the sudo session)."
ssh -T "${ssh_common[@]}" -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no ipat-lab \
  'test "$(id -un)" = openai && systemctl is-active --quiet ssh &&
   test -s "$HOME/.ssh/authorized_keys" && echo NEW_INDEPENDENT_KEY_ONLY_SESSION_PASS' ||
  fatal "new key-only login failed; DO NOT confirm; wait for rollback/use console"

echo "Key-only connection succeeded. Confirm promptly before six-minute timer."
read -r -p 'Type CONFIRM to disarm automatic rollback: ' confirm
[[ "$confirm" == CONFIRM ]] ||
  fatal "not confirmed; automatic rollback remains armed"
ssh -tt "${ssh_common[@]}" ipat-lab \
  "sudo -v && sudo /bin/bash '$root_stage' --confirm" ||
  fatal "sudo confirmation failed; allow timed rollback/use console"

ssh -T "${ssh_common[@]}" -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no ipat-lab \
  'test "$(id -un)" = openai && systemctl is-active --quiet ssh &&
   test ! -e /run/ipat-ssh-stage2.active && echo FINAL_FRESH_KEY_ONLY_LOGIN_PASS' ||
  fatal "post-confirm check failed; use provider console"
echo "STAGE2_VERIFIED: root/password SSH disabled; firewall still unchanged"
