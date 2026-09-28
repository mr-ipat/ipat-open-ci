#!/usr/bin/env bash
# K3s host readiness inventory ONLY. Explicitly not an install/approval gate.
# Requires no root, package installation, privileged network access or K3s.
set -Eeuo pipefail

if [[ "${1:-}" != "--report" || "$#" -ne 1 ]]; then
  printf 'Usage: %s --report\n' "$0" >&2
  exit 2
fi
[[ -r /etc/os-release ]] || { echo "OS_RELEASE_MISSING"; exit 3; }
# shellcheck source=/dev/null
. /etc/os-release
printf '%s\n' '=== IPAT K3S HOST READ-ONLY OBSERVATIONS ==='
printf 'OS=%s\n' "$PRETTY_NAME"
printf 'KERNEL=%s\n' "$(uname -r)"
printf 'ARCH=%s\n' "$(uname -m)"
printf 'CPU_LOGICAL=%s\n' "$(nproc)"
printf 'MEMORY_TOTAL_KIB=%s\n' "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
printf 'SWAP_TOTAL_KIB=%s\n' "$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
printf 'ROOT_FREE_KIB=%s\n' "$(df -Pk / | awk 'NR==2 {print $4}')"
printf 'ROOT_FSTYPE=%s\n' "$(findmnt -n -o FSTYPE /)"
printf 'VIRTUALIZATION=%s\n' "$(systemd-detect-virt 2>/dev/null || echo unverified)"
printf 'HOST_SHORT=%s\n' "$(hostname -s)"
printf 'CGROUP_FILESYSTEM=%s\n' "$(stat -fc %T /sys/fs/cgroup)"
if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
  printf 'CGROUP_CONTROLLERS=%s\n' "$(cat /sys/fs/cgroup/cgroup.controllers)"
else
  echo 'CGROUP_CONTROLLERS=UNVERIFIED'
fi

for feature in overlay br_netfilter vxlan nf_conntrack; do
  if [[ -d "/sys/module/$feature" ]]; then
    printf 'KERNEL_FEATURE_%s=loaded_or_builtin\n' "$feature"
  else
    printf 'KERNEL_FEATURE_%s=not_currently_visible; do not infer unsupported\n' "$feature"
  fi
done
for name in net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables; do
  value_path="/proc/sys/${name//./\/}"
  if [[ -r "$value_path" ]]; then
    printf 'SYSCTL_%s=%s\n' "$name" "$(cat "$value_path")"
  else
    printf 'SYSCTL_%s=NOT_READABLE\n' "$name"
  fi
done
printf 'TIME_NTP_SYNC=%s\n' "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unverified)"
printf 'SSH_SERVICE=%s\n' "$(systemctl is-active ssh 2>/dev/null || echo unverified)"
printf 'SSH_OWNED_SNIPPET='
ssh_snippet=/etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf
if [[ -f "$ssh_snippet" ]] &&
   grep -Fxq 'PermitRootLogin no' "$ssh_snippet" &&
   grep -Fxq 'PasswordAuthentication no' "$ssh_snippet" &&
   grep -Fxq 'PubkeyAuthentication yes' "$ssh_snippet"; then
  echo 'observed_key_only_directives; actual Match contexts still require verification'
else
  echo 'NOT_CONFIRMED'
fi
if [[ -e /run/ipat-ssh-stage2.active ]]; then
  echo 'STAGE2_ROLLBACK=MARKER_PRESENT'
else
  echo 'STAGE2_ROLLBACK=NO_MARKER'
fi

echo 'TCP_K3S_PORTS_LISTENING (empty is expected before install)'
if command -v ss >/dev/null 2>&1; then
  ss -H -lnt |
    awk '$4 ~ /:(6443|6444|10250|2379|2380)$/ {print $4}' |
    sort -u || true
else
  echo 'UNVERIFIED_NO_SS'
fi
echo 'UDP_K3S_OVERLAY_LISTENING (empty is expected before install)'
if command -v ss >/dev/null 2>&1; then
  ss -H -lnu |
    awk '$4 ~ /:(8472|51820|51821)$/ {print $4}' |
    sort -u || true
else
  echo 'UNVERIFIED_NO_SS'
fi
printf 'DEFAULT_IPV4_ROUTE=%s\n' "$(ip -4 route show default | head -1)"
printf 'CURRENT_IPV4_INTERFACES\n'
ip -brief -4 address
for tool in k3s kubectl iptables nft ufw; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'TOOL_%s=present_on_PATH\n' "$tool"
  else
    printf 'TOOL_%s=absent_on_PATH\n' "$tool"
  fi
done
printf '%s\n' \
  'PROVIDER_PUBLIC_FIREWALL=UNVERIFIED_BY_GUEST' \
  'OUT_OF_BAND_RESCUE=REQUIRES_OPERATOR_VERIFICATION' \
  'COMPLETE_ENCRYPTED_INDEPENDENT_BACKUP_AND_RESTORE=NOT_VERIFIED' \
  'K3S_CNI_MULTI_NODE_PRIVATE_NETWORK=ADR_017_OPEN' \
  'K3S_DATASTORE_BACKUP_STRATEGY=ADR_017_OPEN' \
  'K3S_INSTALL_GATE=BLOCKED_UNTIL_RECOVERY_NETWORK_AND_ADR_REVIEW' \
  'READ_ONLY_PREFLIGHT_COMPLETE_NO_CONFIG_CHANGE'
