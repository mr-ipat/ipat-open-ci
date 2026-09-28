#!/usr/bin/env bash
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo R57_NFT_BLOCKED_NOT_ROOT >&2; exit 4; }
[[ "$(cat /etc/ipat-disposable-vm 2>/dev/null || true)" == R57_QEMU_UBUNTU26_DISPOSABLE_ONLY ]] || { echo R57_NFT_BLOCKED_NOT_DISPOSABLE >&2; exit 4; }
[[ "$(hostname)" == ipat-r57-b ]] || { echo R57_NFT_BLOCKED_WRONG_HOST >&2; exit 4; }
[[ "$(systemd-detect-virt 2>/dev/null || true)" == qemu ]] || { echo R57_NFT_BLOCKED_NOT_QEMU >&2; exit 4; }
. /etc/os-release
[[ "$ID:$VERSION_ID" == ubuntu:26.04 ]] || { echo R57_NFT_BLOCKED_WRONG_OS >&2; exit 4; }
[[ "${IPAT_R57_INTENTIONAL_SSH_ROLLBACK_DRILL:-}" == YES ]] || { echo R57_NFT_BLOCKED_EXPLICIT_OPT_IN_REQUIRED >&2; exit 4; }
systemctl is-active --quiet k3s || { echo R57_NFT_BLOCKED_K3S_INACTIVE >&2; exit 4; }
cat > /tmp/r57-fw-rollback.sh <<'ROLLBACK'
#!/usr/bin/env bash
set -eu
/usr/sbin/nft delete table inet ipat_r57_lab 2>/dev/null || true
ROLLBACK
install -m 0700 /tmp/r57-fw-rollback.sh /usr/local/sbin/ipat-r57-fw-rollback
systemctl stop ipat-r57-fw-rollback.timer ipat-r57-fw-rollback.service >/dev/null 2>&1 || true
systemd-run   --unit=ipat-r57-fw-rollback   --on-active=10s   --timer-property=AccuracySec=1s   --timer-property=RandomizedDelaySec=0   /usr/local/sbin/ipat-r57-fw-rollback >/dev/null
cat > /tmp/r57-firewall-block-new-ssh.nft <<'NFT'
table inet ipat_r57_lab {
  chain input {
    type filter hook input priority -50; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip saddr 10.0.2.0/24 tcp dport 16443 accept
    ip saddr 10.42.0.0/16 accept
    ip protocol icmp accept
    meta l4proto ipv6-icmp accept
    udp sport 67 udp dport 68 accept
  }
}
NFT
nft delete table inet ipat_r57_lab >/dev/null 2>&1 || true
nft -c -f /tmp/r57-firewall-block-new-ssh.nft
nft -f /tmp/r57-firewall-block-new-ssh.nft
test "$(systemctl show ipat-r57-fw-rollback.timer -p AccuracyUSec --value)" = 1s
echo R57_PRECISE_ROLLBACK_TIMER_ARMED_10S_ACCURACY_1S=PASS
