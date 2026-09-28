#!/usr/bin/env bash
# Mr. iPat / IPAT R5.7. Real K3s source-cluster drill for the dedicated
# disposable QEMU Ubuntu 26.04 VM only. NEVER run on the IPAT VPS.
set -Eeuo pipefail
umask 077

PINNED_TAG='v1.36.4+k3s1'
PINNED_ARM64_SHA256='c920706346d5ad4e5cd3c7bf1bb09ce71ebe07fec829e513e40f1caf98aed8bb'
LAB_MARKER='R57_QEMU_UBUNTU26_DISPOSABLE_ONLY'
EXPECTED_HOST='ipat-r57-a'

die(){ printf 'R57_SOURCE_BLOCKED: %s\n' "$*" >&2; exit 4; }
[[ $(id -u) -eq 0 ]] || die 'root required inside disposable VM'
[[ "$(cat /etc/ipat-disposable-vm 2>/dev/null || true)" == "$LAB_MARKER" ]] ||
  die 'missing exact disposable VM marker'
[[ "$(hostname)" == "$EXPECTED_HOST" ]] || die 'wrong disposable source hostname'
[[ "$(systemd-detect-virt 2>/dev/null || true)" == qemu ]] || die 'QEMU VM required'
. /etc/os-release
[[ "$ID:$VERSION_ID" == ubuntu:26.04 ]] || die 'Ubuntu 26.04 required'
[[ "$(uname -m)" == aarch64 ]] || die 'arm64 disposable VM required'
[[ ! -e /usr/local/bin/k3s && ! -e /var/lib/rancher/k3s ]] ||
  die 'existing K3s state is refused'

node_ip="$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')"
python3 - "$node_ip" <<'PY' || die 'node IP must be RFC1918'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
assert any(ip in net for net in (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
))
PY

work="$(mktemp -d /var/tmp/ipat-r57-source.XXXXXX)"
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT
curl --proto '=https' --tlsv1.2 --fail --location --retry 3   --connect-timeout 10 --max-time 120   "https://github.com/k3s-io/k3s/releases/download/${PINNED_TAG}/k3s-arm64"   -o "$work/k3s"
printf '%s  %s\n' "$PINNED_ARM64_SHA256" "$work/k3s" |
  sha256sum --check --status || die 'K3s checksum mismatch'
install -m 0755 "$work/k3s" /usr/local/bin/k3s
install -d -m 0700 /etc/rancher/k3s /var/lib/ipat-r57/export

cat > /etc/rancher/k3s/config.yaml <<CFG
cluster-init: true
write-kubeconfig-mode: "0600"
bind-address: "$node_ip"
advertise-address: "$node_ip"
node-ip: "$node_ip"
https-listen-port: 16443
disable:
  - traefik
  - servicelb
  - metrics-server
CFG
chmod 0600 /etc/rancher/k3s/config.yaml

cat > /etc/systemd/system/k3s.service <<'UNIT'
[Unit]
Description=IPAT R5.7 disposable K3s source laboratory
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/k3s server
KillMode=process
Delegate=yes
TasksMax=infinity
LimitNOFILE=1048576
Restart=on-failure
RestartSec=5s
UMask=0022
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now k3s >/dev/null

ready=0
for _ in $(seq 1 90); do
  if /usr/local/bin/k3s kubectl get nodes --no-headers 2>/dev/null |
     grep -E "^${EXPECTED_HOST}[[:space:]]+Ready" >/dev/null; then
    ready=1; break
  fi
  sleep 3
done
[[ "$ready" == 1 ]] || die 'source node did not become Ready'
/usr/local/bin/k3s kubectl -n kube-system rollout status deploy/coredns   --timeout=150s >/dev/null

/usr/local/bin/k3s kubectl create namespace ipat-r57-restore >/dev/null 2>&1 || true
/usr/local/bin/k3s kubectl -n ipat-r57-restore create configmap restore-marker   --from-literal=marker=MR_IPAT_R57_RESTORE_PROOF   --dry-run=client -o yaml | /usr/local/bin/k3s kubectl apply -f - >/dev/null

/usr/local/bin/k3s kubectl create namespace ipat-r57-smoke >/dev/null 2>&1 || true
/usr/local/bin/k3s kubectl -n ipat-r57-smoke run dns-smoke   --image=busybox:1.37.0 --restart=Never --command -- sh -c 'sleep 600' >/dev/null
/usr/local/bin/k3s kubectl -n ipat-r57-smoke wait --for=condition=Ready   pod/dns-smoke --timeout=180s >/dev/null
/usr/local/bin/k3s kubectl -n ipat-r57-smoke exec dns-smoke --   nslookup kubernetes.default.svc.cluster.local >/dev/null

listeners="$(ss -H -lnt '( sport = :16443 )')"
grep -Fq "$node_ip:16443" <<<"$listeners" || die 'private API listener missing'
if grep -Eq '0[.]0[.]0[.]0:16443|\[::\]:16443|[[:space:]]\*:16443' <<<"$listeners"; then
  die 'wildcard API listener forbidden'
fi

/usr/local/bin/k3s etcd-snapshot save   --etcd-server "https://$node_ip:16443"   --data-dir /var/lib/rancher/k3s   --name r57-cross-host >/dev/null
snapshot="$(find /var/lib/rancher/k3s/server/db/snapshots -maxdepth 1   -type f -name 'r57-cross-host*' -print -quit)"
[[ -n "$snapshot" && -s "$snapshot" ]] || die 'snapshot missing'
install -m 0600 "$snapshot" /var/lib/ipat-r57/export/r57-cross-host.snapshot
install -m 0600 /var/lib/rancher/k3s/server/token   /var/lib/ipat-r57/export/server-token
sha256sum /var/lib/ipat-r57/export/r57-cross-host.snapshot   > /var/lib/ipat-r57/export/r57-cross-host.snapshot.sha256
chmod 0600 /var/lib/ipat-r57/export/*

systemctl restart k3s
for _ in $(seq 1 60); do
  /usr/local/bin/k3s kubectl get nodes --no-headers 2>/dev/null |
    grep -E "^${EXPECTED_HOST}[[:space:]]+Ready" >/dev/null && break
  sleep 3
done
/usr/local/bin/k3s kubectl -n kube-system rollout status deploy/coredns   --timeout=120s >/dev/null

echo "R57_SOURCE_K3S_VERSION=$(/usr/local/bin/k3s --version | head -1)"
echo "R57_SOURCE_NODE_IP=$node_ip"
echo "R57_SOURCE_SNAPSHOT_SHA256=$(awk '{print $1}' /var/lib/ipat-r57/export/r57-cross-host.snapshot.sha256)"
echo "R57_SOURCE_TOKEN_BYTES=$(stat -c %s /var/lib/ipat-r57/export/server-token)"
echo 'R57_SOURCE_SYSTEMD_K3S_READY=PASS'
echo 'R57_SOURCE_POD_DNS=PASS'
echo 'R57_SOURCE_API_PRIVATE_ONLY=PASS'
echo 'R57_SOURCE_SNAPSHOT_AND_TOKEN_EXPORT_READY=PASS'
echo 'R57_SOURCE_SYSTEMD_RESTART=PASS'
