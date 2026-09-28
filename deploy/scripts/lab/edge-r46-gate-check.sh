#!/usr/bin/env bash
# R4.6 read-only evidence; no provider access, host firewall writes, or sudo.
set -Eeuo pipefail
[[ "$#" == 1 && "$1" == --report ]] ||
  { echo "Usage: $0 --report" >&2; exit 2; }
[[ "$(uname -s)" == Darwin ]] ||
  { echo "Run on the authorized Mac, not on the VPS" >&2; exit 3; }
for c in fdesetup curl ssh python3; do
  command -v "$c" >/dev/null || { echo "Tool unavailable: $c" >&2; exit 4; }
done
echo "R46_EDGE_FILEVAULT_EXTERNAL_EVIDENCE_ONLY"
if fdesetup status | grep -Fxq "FileVault is On."; then
  echo FILEVAULT=ON
else
  echo FILEVAULT=NOT_VERIFIED
fi
mac4="$(curl -fsS4 --noproxy '*' --max-time 7 https://api.ipify.org)"
python3 - "$mac4" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
assert ip.version==4 and ip.is_global, "Mac public IPv4 is not verified as globally routable"
print("MAC_PUBLIC_IPV4_CURRENT="+str(ip))
print("PROPOSED_SOURCE_CIDR="+str(ip)+"/32")
print("CAUTION_IP_STABILITY=NOT_ESTABLISHED")
PY
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ControlMaster=no -o ControlPath=none \
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no ipat-lab '
set -eu
test "$(id -un)" = openai
systemctl is-active --quiet ssh
test ! -e /run/ipat-ssh-stage2.active
echo "VPS_GLOBAL_IPV6_GUEST:"
ip -brief -6 address show scope global
echo "VPS_IPV6_DEFAULT_ROUTE:"
ip -6 route show default | head -1
echo "SSH_IPV4_IPV6_LISTENERS:"
ss -H -lnt | grep -E ":22[[:space:]]" || true
test -r /etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf
grep -Fxq "PasswordAuthentication no" /etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf
grep -Fxq "PermitRootLogin no" /etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf
echo SSH_MANAGED_KEY_ONLY_DIRECTIVES=OBSERVED
'
echo "OWNER_SCREENSHOT_EDGE_SG_IPV4_INBOUND=ALLOW_ALL_0.0.0.0/0"
echo "OWNER_SCREENSHOT_EDGE_SG_IPV6_INBOUND=ALLOW_ALL_::/0"
echo "SECURITY_GROUP_OTHER_VM_ATTACHMENTS=UNVERIFIED"
echo "VNC_REAL_LOGIN=REQUIRES_OWNER_CONFIRMATION"
echo "RESTIC_PASSWORD_INDEPENDENT_ESCROW=REQUIRES_OWNER_CONFIRMATION"
echo "EDGE_PROVIDER_FIREWALL_CHANGE=NOT_PERFORMED"
echo "GUEST_HOST_FIREWALL_CHANGE=NOT_PERFORMED"
