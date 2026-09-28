#!/usr/bin/env bash
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo REFUSED_NOT_ROOT >&2; exit 4; }
[[ "$(cat /etc/ipat-disposable-vm 2>/dev/null || true)" == R57_QEMU_UBUNTU26_DISPOSABLE_ONLY ]] || { echo REFUSED_NOT_R57_VM >&2; exit 4; }
[[ "$(hostname)" == ipat-r57-b ]] || { echo REFUSED_WRONG_HOST >&2; exit 4; }
[[ "$(systemd-detect-virt 2>/dev/null || true)" == qemu ]] || { echo REFUSED_NOT_QEMU >&2; exit 4; }
. /etc/os-release
[[ "$ID:$VERSION_ID" == ubuntu:26.04 ]] || { echo REFUSED_WRONG_OS >&2; exit 4; }
[[ "$(uname -m)" == aarch64 ]] || { echo REFUSED_WRONG_ARCH >&2; exit 4; }
[[ ! -e /usr/local/bin/k3s && ! -e /var/lib/rancher/k3s ]] || { echo REFUSED_EXISTING_K3S >&2; exit 4; }
IMPORT_DIR=/var/lib/ipat-r57/import
[[ -s "$IMPORT_DIR/r57-cross-host.snapshot" && -s "$IMPORT_DIR/server-token" ]] || { echo REFUSED_MISSING_RESTORE_INPUT >&2; exit 4; }
[[ "${IPAT_R57_SNAPSHOT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || { echo REFUSED_EXPECTED_SNAPSHOT_SHA256_REQUIRED >&2; exit 4; }
printf '%s  %s\n' "$IPAT_R57_SNAPSHOT_SHA256" "$IMPORT_DIR/r57-cross-host.snapshot" | sha256sum -c --status
node_ip="$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')"
python3 - "$node_ip" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1]); assert ip in ipaddress.ip_network("10.0.0.0/8")
PY
work="$(mktemp -d /var/tmp/ipat-r57-restore.XXXXXX)"
cleanup(){ rm -rf -- "$work"; }
trap cleanup EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 120  'https://github.com/k3s-io/k3s/releases/download/v1.36.4%2Bk3s1/k3s-arm64' -o "$work/k3s"
printf '%s  %s\n' 'c920706346d5ad4e5cd3c7bf1bb09ce71ebe07fec829e513e40f1caf98aed8bb' "$work/k3s" | sha256sum -c -
install -m 0755 "$work/k3s" /usr/local/bin/k3s
install -d -m 0700 /etc/rancher/k3s /var/lib/rancher/k3s/server/db/snapshots
install -m 0600 "$IMPORT_DIR/server-token" /etc/rancher/k3s/server-token
# New-host restore requires the ORIGINAL server token at K3s' standard path.
install -m 0600 "$IMPORT_DIR/server-token" /var/lib/rancher/k3s/server/token
install -m 0600 "$IMPORT_DIR/r57-cross-host.snapshot" /var/lib/rancher/k3s/server/db/snapshots/r57-cross-host.snapshot
cat > /etc/rancher/k3s/config.yaml <<CFG
write-kubeconfig-mode: "0600"
bind-address: "$node_ip"
advertise-address: "$node_ip"
node-ip: "$node_ip"
https-listen-port: 16443
token-file: /etc/rancher/k3s/server-token
disable:
  - traefik
  - servicelb
  - metrics-server
CFG
chmod 0600 /etc/rancher/k3s/config.yaml
cat > /etc/systemd/system/k3s.service <<'UNIT'
[Unit]
Description=IPAT R5.7 disposable restored K3s laboratory
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

# Official new-host restore: use original token to decrypt bootstrap state.
# Keep restore output private; only classify the success marker.
set +e
umask 022
/usr/local/bin/k3s server   --cluster-reset   --cluster-reset-restore-path=/var/lib/rancher/k3s/server/db/snapshots/r57-cross-host.snapshot   --data-dir=/var/lib/rancher/k3s   --bind-address="$node_ip"   --advertise-address="$node_ip"   --node-ip="$node_ip"   --https-listen-port=16443   --disable=traefik --disable=servicelb --disable=metrics-server   > /root/r57-restore.log 2>&1
restore_rc=$?
set -e
if [[ $restore_rc -ne 0 ]]; then
  echo R57_VM_B_RESTORE_COMMAND_FAILED_LOG_REMAINS_ROOT_ONLY >&2
  exit 1
fi
grep -Fq 'Managed etcd cluster membership has been reset' /root/r57-restore.log || {
  echo R57_VM_B_RESTORE_SUCCESS_MARKER_MISSING >&2
  exit 1
}

systemctl enable --now k3s >/dev/null
ready=0
for i in $(seq 1 90); do
  if /usr/local/bin/k3s kubectl get nodes --no-headers 2>/dev/null | grep -E '^ipat-r57-b[[:space:]]+Ready' >/dev/null; then
    ready=1; break
  fi
  sleep 3
done
[[ $ready -eq 1 ]] || { echo R57_VM_B_NODE_NOT_READY >&2; exit 1; }

# Prove the snapshot contents survived onto this different VM before cleanup.
marker="$(/usr/local/bin/k3s kubectl -n ipat-r57-restore get configmap restore-marker -o jsonpath='{.data.marker}')"
[[ "$marker" == MR_IPAT_R57_RESTORE_PROOF ]] || { echo R57_VM_B_RESTORE_MARKER_MISMATCH >&2; exit 1; }

# Old node resources are expected in an etcd restore to new hosts.
if /usr/local/bin/k3s kubectl get node ipat-r57-a >/dev/null 2>&1; then
  /usr/local/bin/k3s kubectl delete node ipat-r57-a --wait=false >/dev/null
fi
for i in $(seq 1 90); do
  ! /usr/local/bin/k3s kubectl get node ipat-r57-a >/dev/null 2>&1 && break
  sleep 1
done
! /usr/local/bin/k3s kubectl get node ipat-r57-a >/dev/null 2>&1 || { echo R57_STALE_NODE_REMAINS >&2; exit 1; }
# Pods restored from etcd can still reference the deleted source Node. Remove
# only those stale pod objects, then let their controllers recreate them on B.
/usr/local/bin/k3s kubectl get pods -A --field-selector spec.nodeName=ipat-r57-a \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' | \
while IFS=$'\t' read -r ns pod; do
  [[ -n "$ns" && -n "$pod" ]] || continue
  /usr/local/bin/k3s kubectl -n "$ns" delete pod "$pod" \
    --force --grace-period=0 >/dev/null 2>&1 || true
done
/usr/local/bin/k3s kubectl -n kube-system rollout status deploy/coredns --timeout=180s >/dev/null
# Prove workloads can execute on VM B.
/usr/local/bin/k3s kubectl -n ipat-r57-smoke delete pod dns-smoke-b --ignore-not-found --force --grace-period=0 >/dev/null 2>&1 || true
/usr/local/bin/k3s kubectl -n ipat-r57-smoke run dns-smoke-b --image=busybox:1.37.0 --restart=Never   --command -- sh -c 'sleep 600' >/dev/null
/usr/local/bin/k3s kubectl -n ipat-r57-smoke wait --for=condition=Ready pod/dns-smoke-b --timeout=180s >/dev/null
/usr/local/bin/k3s kubectl -n ipat-r57-smoke exec dns-smoke-b -- nslookup kubernetes.default.svc.cluster.local >/dev/null
listeners="$(ss -H -lnt '( sport = :16443 )')"
grep -Fq "$node_ip:16443" <<<"$listeners"
! grep -Eq '0[.]0[.]0[.]0:16443|\[::\]:16443|[[:space:]]\*:16443' <<<"$listeners"
printf 'R57_VM_B_OS=%s:%s\n' "$ID" "$VERSION_ID"
printf 'R57_VM_B_K3S_VERSION='; /usr/local/bin/k3s --version | head -1
printf 'R57_VM_B_NODE_IP=%s\n' "$node_ip"
echo R57_CROSS_HOST_ETCD_RESTORE_MARKER=PASS
echo R57_VM_B_NEW_NODE_READY=PASS
echo R57_VM_B_POST_RESTORE_POD_DNS=PASS
echo R57_VM_B_API_PRIVATE_BIND_ONLY=PASS
systemctl restart k3s
for i in $(seq 1 60); do
  /usr/local/bin/k3s kubectl get nodes --no-headers 2>/dev/null | grep -E '^ipat-r57-b[[:space:]]+Ready' >/dev/null && break
  sleep 3
done
/usr/local/bin/k3s kubectl -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null
# A pod Ready condition can be stale for a short window after a K3s restart.
# Prove container runtime recovery with a NEW pod created after restart.
/usr/local/bin/k3s kubectl -n ipat-r57-smoke delete pod dns-after-restart --ignore-not-found --force --grace-period=0 >/dev/null 2>&1 || true
/usr/local/bin/k3s kubectl -n ipat-r57-smoke run dns-after-restart --image=busybox:1.37.0 --restart=Never --command -- sh -c 'sleep 600' >/dev/null
/usr/local/bin/k3s kubectl -n ipat-r57-smoke wait --for=condition=Ready pod/dns-after-restart --timeout=180s >/dev/null
/usr/local/bin/k3s kubectl -n ipat-r57-smoke exec dns-after-restart -- nslookup kubernetes.default.svc.cluster.local >/dev/null
/usr/local/bin/k3s etcd-snapshot save --etcd-server "https://$node_ip:16443" --data-dir /var/lib/rancher/k3s --name r57-post-restore >/dev/null
find /var/lib/rancher/k3s/server/db/snapshots -maxdepth 1 -type f -name 'r57-post-restore*' -size +1k | grep -q .
echo R57_VM_B_SYSTEMD_SERVICE=PASS
echo R57_VM_B_RESTART_AND_POST_RESTORE_SNAPSHOT=PASS
