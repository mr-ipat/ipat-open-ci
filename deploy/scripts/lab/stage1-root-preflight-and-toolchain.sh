#!/usr/bin/env bash
# IPAT stage 1: restricted lab bootstrap. No firewall, SSH or network changes.
set -Eeuo pipefail
umask 077

if [[ "$#" -ne 1 ]] || [[ "$1" != "--check" && "$1" != "--apply" ]]; then
  echo "Usage: $0 --check|--apply" >&2
  exit 2
fi
mode="$1"
user_home="/home/openai"

assert_target() {
  # shellcheck source=/dev/null
  . /etc/os-release
  if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "26.04" ]]; then
    echo "ABORT: server is not approved Ubuntu 26.04" >&2
    exit 3
  fi
  if ! id openai >/dev/null 2>&1 || [[ ! -s "$user_home/.ssh/authorized_keys" ]]; then
    echo "ABORT: designated openai account/public-key access missing" >&2
    exit 4
  fi
  if ! command -v apt-get >/dev/null || ! command -v dpkg-query >/dev/null; then
    echo "ABORT: expected Ubuntu package management absent" >&2
    exit 5
  fi
  local free_kib
  free_kib="$(df -Pk / | awk 'NR==2 { print $4 }')"
  if [[ ! "$free_kib" =~ ^[0-9]+$ ]] || (( free_kib < 5 * 1024 * 1024 )); then
    echo "ABORT: less than 5 GiB filesystem headroom" >&2
    exit 6
  fi
  echo "OS_PASS=$PRETTY_NAME"
  echo "FREE_ROOT_KIB=$free_kib"
}

assert_target
if [[ "$mode" == "--check" ]]; then
  echo "READ_ONLY: current compiler/apt candidate"
  command -v cc || echo "cc missing"
  apt-cache policy build-essential | head -12
  echo "CHECK_ONLY_PASS: NO ROOT OR SERVER CHANGES"
  exit 0
fi

if (( EUID != 0 )); then
  echo "ABORT: apply requires interactive sudo on the owner's Mac" >&2
  exit 7
fi
if [[ "${IPAT_STAGE1_APPROVED:-}" != "yes" ||
      "${IPAT_EXTERNAL_PARTIAL_BACKUP_VERIFIED:-}" != "yes" ]]; then
  echo "ABORT: owner approval and previously verified off-host partial backup required" >&2
  exit 8
fi

echo "ROOT_PREFLIGHT: validate existing SSH without changing it"
if ! /usr/sbin/sshd -t; then
  echo "ABORT: existing sshd configuration failed validation" >&2
  exit 9
fi
if ! systemctl is-active --quiet ssh; then
  echo "ABORT: existing ssh daemon is not active" >&2
  exit 10
fi
printf 'EXISTING_EFFECTIVE_SSH_POLICY_FOR_OPENAI:\n'
/usr/sbin/sshd -T -C user=openai,host=hub.example.invalid,addr=127.0.0.1 |
  grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication) ' || true

# Root-readable config baseline is for same-disk rollback, NOT disaster recovery.
install -d -o root -g root -m 0700 /var/backups/ipat-lab
backup="$(mktemp -d /var/backups/ipat-lab/stage1-XXXXXXXX)"
chmod 0700 "$backup"
tar -C / -czf "$backup/root-config.tar.gz"   etc/ssh/sshd_config etc/ssh/sshd_config.d   etc/apt/apt.conf.d etc/apt/sources.list.d
chmod 0600 "$backup/root-config.tar.gz"
dpkg-query -W > "$backup/packages-before.tsv"
chmod 0600 "$backup/packages-before.tsv"
sha256sum "$backup/root-config.tar.gz" > "$backup/config.sha256"
{
  for account in openai root; do
    echo "ACCOUNT=$account; context=synthetic-127.0.0.1 (not real source IP)"
    /usr/sbin/sshd -T -C "user=$account,host=hub.example.invalid,addr=127.0.0.1" |
      grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|allowtcpforwarding|maxauthtries) ' || true
  done
} > "$backup/effective-sshd-policy.txt"
chmod 0600 "$backup/effective-sshd-policy.txt"
install -d -o openai -g openai -m 0700 "$user_home/.cache/ipat"
install -o openai -g openai -m 0600 "$backup/effective-sshd-policy.txt" "$user_home/.cache/ipat/stage1-sshd-policy.txt"
echo "ROOT_BACKUP_CREATED=$backup"
echo "SANITIZED_SSHD_POLICY_REPORT=$user_home/.cache/ipat/stage1-sshd-policy.txt"

echo "APT_STAGE: refresh signed existing Ubuntu sources only"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
apt-get update
apt-get -s install --no-install-recommends build-essential > "$backup/apt-plan.txt"
if grep -q '^Remv ' "$backup/apt-plan.txt" ||
   grep -Eq '^[1-9][0-9]* upgraded,' "$backup/apt-plan.txt"; then
  echo "ABORT: apt simulation requests removals or existing-package upgrades" >&2
  echo "Review root backup and dependency plan; no install attempted" >&2
  exit 11
fi
echo "APT_PLAN_NO_REMOVALS_OR_UPGRADES_PASS"
apt-get install -y --no-install-recommends build-essential

echo "VERIFY_STAGE1"
command -v cc
cc --version | head -1
dpkg-query -W build-essential
/usr/sbin/sshd -t
systemctl is-active --quiet ssh
dpkg-query -W > "$backup/packages-after.tsv"
chmod 0600 "$backup/packages-after.tsv"
echo "STAGE1_APPLY_PASS: SSH/firewall/routes unchanged; NO REBOOT REQUESTED"
echo "WARNING: VPS has no snapshot. Keep verified console rescue and off-host backup."
