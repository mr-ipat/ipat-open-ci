#!/usr/bin/env bash
# Mr. iPat / IPAT R5.6. REAL K3s installation is ONLY permitted on a
# disposable, GitHub-hosted Ubuntu 26.04 runner; NEVER on the live IPAT VPS.
set -Eeuo pipefail
umask 077

PINNED_TAG='v1.36.4+k3s1'
PINNED_K3S_SHA256='835873f37245fc615f547a2fe2af9402a347875f13fa64a1f136de644955ea3f'

die() { printf 'R56_K3S_LAB_BLOCKED: %s\n' "$*" >&2; exit 4; }
[[ "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${RUNNER_OS:-}" == Linux &&
   "${RUNNER_ARCH:-}" == X64 &&
   "${IPAT_K3S_DISPOSABLE_LAB:-}" == 1 ]] ||
   die 'requires an explicitly opted-in GitHub-hosted ephemeral Linux x64 runner'
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 26.04 ]] ||
   die 'requires the separately provisioned disposable Ubuntu 26.04 runner'
[[ "$(id -u)" != 0 ]] || die 'orchestration must use the non-root CI user'
[[ ! -e /var/lib/rancher/k3s &&
   ! -e /etc/rancher/k3s/k3s.yaml ]] ||
   die 'refusing a runner with existing K3s state'
[[ ! -e /usr/local/bin/k3s ]] || die 'refusing an existing K3s binary'
command -v sudo >/dev/null || die 'sudo is required only on ephemeral runner'
command -v curl >/dev/null || die 'curl required for pinned release'

# Discover actual disposable CI node IPv4, never use a user-supplied interface
# or public address; this smoke profile is not an ADR-017 production CNI.
node_ip="$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
python3 - "$node_ip" <<'PY' || die 'CI node route is not RFC1918 private'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
assert any(ip in n for n in (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")))
PY

# Keep containerd overlay/runc executable layers on an explicitly executable
# root filesystem, NOT under GitHub's workspace/_temp mount. Only a disposable
# GitHub Ubuntu 26.04 VM may execute the gated root operations above.
lab_dir="$(sudo mktemp -d /var/lib/ipat-k3s-ci.XXXXXXXX)"
sudo chown "$(id -u):$(id -g)" "$lab_dir"
mount_options="$(findmnt -n -o OPTIONS -T "$lab_dir")"
case ",$mount_options," in *,noexec,*) die 'isolated container runtime data mount is noexec' ;; esac
echo 'R56_CI_CONTAINER_RUNTIME_DATA_ON_EXECUTABLE_ROOTFS=PASS'
server_pid=''
cleanup() {
  rc=$?
  if [[ -n "$server_pid" ]]; then
    sudo kill -TERM "$server_pid" >/dev/null 2>&1 || true
  fi
  # Runner is disposable; no process or secret-bearing test bundle is uploaded.
  # Never recursively delete arbitrary directories or change host-global rules.
  if [[ "$lab_dir" == /var/lib/ipat-k3s-ci.* ]]; then
    sudo rm -rf -- "$lab_dir"
  fi
  exit "$rc"
}
trap cleanup EXIT

echo "R56_EPHEMERAL_RUNNER_OS=${ID}:${VERSION_ID}"
echo "R56_PINNED_STABLE_K3S=$PINNED_TAG"
download_url="https://github.com/k3s-io/k3s/releases/download/${PINNED_TAG}/k3s"
curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
  --connect-timeout 10 --max-time 120 \
  "$download_url" --output "$lab_dir/k3s"
printf '%s  %s\n' "$PINNED_K3S_SHA256" "$lab_dir/k3s" | sha256sum --check --status ||
   die 'downloaded K3s binary differs from pinned upstream release checksum'
chmod 0700 "$lab_dir/k3s"
"$lab_dir/k3s" --version
echo 'R56_PINNED_K3S_BINARY_SHA256_VERIFIED=PASS'

# Run embedded etcd on a temporary, separate GitHub VM. No host systemd
# installation, external SSH route, provider security-group API, or ingress.
# Bind the supervisor/API ONLY to the ephemeral runner's RFC1918 address.
# Secret-bearing wrapper/files retain the shell's umask 077, but containerd
# needs standard service umask 022 for correctly traversable OCI layer dirs.
# Test this only on the disposable GitHub VM; K3s itself explicitly protects
# its Kubeconfig (0600) and stateful token paths.
sudo bash -c 'umask 022; exec "$@"' ipat-ephemeral "$lab_dir/k3s" server \
  --cluster-init \
  --data-dir "$lab_dir/data" \
  --write-kubeconfig "$lab_dir/kubeconfig" \
  --write-kubeconfig-mode 0600 \
  --bind-address "$node_ip" \
  --advertise-address "$node_ip" \
  --node-ip "$node_ip" \
  --https-listen-port 16443 \
  --disable traefik --disable servicelb --disable metrics-server \
  >"$lab_dir/server.log" 2>&1 &
server_pid=$!

k() { sudo "$lab_dir/k3s" kubectl --kubeconfig "$lab_dir/kubeconfig" "$@"; }
ready=0
for attempt in $(seq 1 90); do
  if ! sudo kill -0 "$server_pid" 2>/dev/null; then
    die 'ephemeral K3s process exited before API became ready (logs intentionally private)'
  fi
  if k get nodes --no-headers 2>/dev/null | grep -Eq '[[:space:]]Ready[[:space:]]'; then
    ready=1
    break
  fi
  sleep 4
done
[[ "$ready" == 1 ]] || die 'ephemeral K3s node not Ready within bounded time'
k get nodes -o wide
echo 'R56_UBUNTU26_REAL_K3S_NODE_READY=PASS'

# Confirm the API never binds a public wildcard IPv4/IPv6 listener.
listeners="$(ss -H -lnt '( sport = :16443 )')"
[[ -n "$listeners" ]] || die 'K3s API listener was not found'
if grep -Eq '0[.]0[.]0[.]0:16443|\\[::\\]:16443|[[:space:]]\\*:16443' <<<"$listeners"; then
  die 'K3s API unexpectedly listens on wildcard/public IPv4/IPv6'
fi
grep -Fq "$node_ip:16443" <<<"$listeners" ||
  die 'API listener is not bound to the disposable RFC1918 node IPv4'
echo 'R56_EPHEMERAL_API_RFC1918_ONLY=PASS'

# Node Ready can precede packaged chart/deployment creation on fast CI VMs.
# Wait for the deployment to EXIST before judging its rollout readiness.
coredns_deployment_found=0
for attempt in $(seq 1 45); do
  if k -n kube-system get deployment coredns >/dev/null 2>&1; then
    coredns_deployment_found=1
    break
  fi
  sleep 2
done
[[ "$coredns_deployment_found" == 1 ]] || die 'packaged CoreDNS deployment not created within 90 seconds'
if ! k -n kube-system rollout status deploy/coredns --timeout=100s >/dev/null 2>&1; then
  # Emit ONLY controlled pod-state and event *reason* keys, never messages,
  # kubeconfigs, startup logs, server tokens or credential-bearing spec fields.
  k get pods -A -o json | python3 -c '
import json,sys
for x in json.load(sys.stdin).get("items",[]):
 s=x.get("status",{}); reasons=[]
 for cs in s.get("containerStatuses",[]):
  waiting=cs.get("state",{}).get("waiting",{})
  last_exit=cs.get("lastState",{}).get("terminated",{})
  if waiting: reasons.append(waiting.get("reason","Unknown"))
  if last_exit: reasons.append("lastExitCode="+str(last_exit.get("exitCode","unknown")))
 print("CI_POD_STATUS",x["metadata"]["namespace"],x["metadata"]["name"],
       s.get("phase","Unknown"), ",".join(reasons) or "none")
' || true
  k get events -A -o json | python3 -c '
import json,sys,collections
reasons=collections.Counter(x.get("reason","Unknown") for x in
 json.load(sys.stdin).get("items",[]))
for reason,count in sorted(reasons.items()):
 print("CI_EVENT_REASON",reason,count)
' || true
  # Classify *known* CoreDNS log/event errors without printing arbitrary
  # potentially sensitive logs, addresses, Kubeconfig, tokens or messages.
  k -n kube-system logs deploy/coredns --previous --tail=60 2>/dev/null | python3 -c '
import sys
text=sys.stdin.read().lower()
checks={
 "COREDNS_PLUGIN_LOOP": ("plugin/loop" in text or "loop detected" in text),
 "COREDNS_API_REFUSED": ("connection refused" in text),
 "COREDNS_PERMISSION": ("permission denied" in text),
 "COREDNS_NO_ROUTE": ("no route to host" in text),
 "COREDNS_TIMEOUT": ("timeout" in text),
 "COREDNS_PANIC": ("panic:" in text),
 "COREDNS_FORWARD_ERROR": ("plugin/errors" in text),
}
for category,present in checks.items():
 if present: print("CI_LOG_ERROR_CLASS",category)
if not any(checks.values()): print("CI_LOG_ERROR_CLASS","UNCLASSIFIED")
' || true
  k get events -A -o json | python3 -c '
import json,sys
for event in json.load(sys.stdin).get("items",[]):
 if event.get("reason") not in ("Failed","FailedCreatePodSandBox","BackOff"):
  continue
 message=event.get("message","").lower()
 matches={
  "CNI_PLUGIN": ("cni" in message or "flannel" in message),
  "RUNTIME_PERMISSION": ("permission denied" in message or "operation not permitted" in message),
  "NET_CONNECTION": ("connection refused" in message or "no route to host" in message),
  "IMAGE_ERROR": ("image" in message or "pull" in message),
  "APPARMOR": ("apparmor" in message),
  "SECCOMP": ("seccomp" in message),
  "RUNC": ("runc" in message),
  "EXEC_ENTRY": ("executable file not found" in message or "exec:" in message),
  "MOUNT": ("mount" in message),
  "NOEXEC": ("noexec" in message),
 }
 for category,present in matches.items():
  if present: print("CI_EVENT_ERROR_CLASS",category)
' || true
  die 'CoreDNS not Ready within the disposable test deadline'
fi
echo 'R56_EPHEMERAL_COREDNS_READY=PASS'

# A disposable nonprivileged BusyBox pod checks the REAL CNI and cluster DNS.
k create namespace ipat-ci-smoke >/dev/null
k -n ipat-ci-smoke run dns-smoke --image=busybox:1.37.0 --restart=Never \
   --command -- sh -c 'sleep 300' >/dev/null
k -n ipat-ci-smoke wait --for=condition=Ready pod/dns-smoke --timeout=180s
k -n ipat-ci-smoke exec dns-smoke -- nslookup kubernetes.default.svc.cluster.local \
   >/dev/null
echo 'R56_EPHEMERAL_POD_AND_CLUSTER_DNS=PASS'

# Embedded-etcd snapshot is ephemeral evidence, not independent production DR.
# Snapshot client defaults to 127.0.0.1:6443; our CI-only supervisor is
# intentionally bound to a distinct private address and port 16443. The
# verified upstream v1.36.4 command's --etcd-server flag selects that endpoint.
# The root-only token is discovered from --data-dir; never pass it in argv/logs.
sudo "$lab_dir/k3s" etcd-snapshot save \
  --etcd-server "https://$node_ip:16443" \
  --data-dir "$lab_dir/data" \
  --name ipat-ephemeral-smoke >/dev/null
sudo find "$lab_dir/data/server/db/snapshots" -maxdepth 1 -type f \
  -name 'ipat-ephemeral-smoke*' -size +1k | grep -q .
echo 'R56_EPHEMERAL_ETCD_SNAPSHOT_CREATED=PASS'
if [[ "${IPAT_R58_SMOKE:-0}" == 1 ]]; then
  # R5.8 only: same disposable CI runner, after actual Node/DNS/snapshot passed.
  bash deploy/scripts/lab/r58/app-smoke.sh "$lab_dir" "$node_ip"
fi
echo 'R56_LIMITATION=ONE_DISPOSABLE_RUNNER_NOT_MULTI_NODE_HA_OR_OFFHOST_RESTORE'
