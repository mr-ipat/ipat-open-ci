#!/usr/bin/env bash
# Mr. iPat / IPAT R5.8: only sourced by the exact disposable Ubuntu26 CI K3s runner.
# NO live infrastructure/ISP network changes; app health and deny routes only.
set -Eeuo pipefail
[[ "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${RUNNER_OS:-}" == Linux &&
   "${RUNNER_ARCH:-}" == X64 &&
   "${IPAT_K3S_DISPOSABLE_LAB:-}" == 1 &&
   "${IPAT_R58_SMOKE:-}" == 1 ]] || {
  echo 'R58_DENIED: exact disposable CI opt-in required' >&2; exit 4;
}
. /etc/os-release
[[ "$ID:$VERSION_ID" == ubuntu:26.04 ]] || {
  echo 'R58_DENIED: Ubuntu 26.04 disposable runner required' >&2; exit 4;
}
[[ $# -eq 2 && "$1" == /var/lib/ipat-k3s-ci.* ]] || {
  echo 'R58_DENIED: R5.6 temporary K3s data-dir required' >&2; exit 4;
}
lab_dir="$1"
node_ip="$2"
# K3s data is intentionally root-only; probe the real Unix socket via
# narrowly scoped noninteractive privilege without relaxing its permissions.
[[ -f "$lab_dir/kubeconfig" && -x "$lab_dir/k3s" ]] &&
  sudo -n test -S /run/k3s/containerd/containerd.sock || {
  echo 'R58_DENIED: require pre-existing temporary validated cluster' >&2; exit 4;
}
python3 - "$node_ip" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
assert any(ip in ipaddress.ip_network(n) for n in
  ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
PY
[[ -x "${HOME}/.cargo/bin/cargo" ]] || {
  echo 'R58_DENIED: pinned Rust must already be installed by CI' >&2; exit 4;
}
command -v docker >/dev/null && docker info >/dev/null 2>&1 || {
  echo 'R58_DENIED: disposable runner Docker image builder required' >&2; exit 4;
}
command -v helm >/dev/null || {
  echo 'R58_DENIED: Helm must already be available on disposable runner' >&2; exit 4;
}
k(){ sudo "$lab_dir/k3s" kubectl --kubeconfig "$lab_dir/kubeconfig" "$@"; }
echo 'R58_DISPOSABLE_K3S_APPLICATION_BUILD_BEGIN'
# Fully static musl userland binaries with no shared host libc requirement.
"$HOME/.cargo/bin/cargo" build --locked --release \
  --target x86_64-unknown-linux-musl -p control-api -p usp-controller
docker build -q -f deploy/container/control-api.Dockerfile \
  -t ipat/control-api:r58-lab . >/dev/null
docker build -q -f deploy/container/usp-controller.Dockerfile \
  -t ipat/usp-controller:r58-lab . >/dev/null
# Import images directly into the temporary embedded containerd; no push,
# external registry, live VPS, developer secret, NodePort or external ingress.
docker save ipat/control-api:r58-lab ipat/usp-controller:r58-lab \
  -o "$lab_dir/ipat-r58-images.tar"
# The bundled k3s ctr is configured for the actual runtime socket in
# /run/k3s; --data-dir changes persistent storage, NOT that socket path.
sudo "$lab_dir/k3s" ctr -n k8s.io images import \
  "$lab_dir/ipat-r58-images.tar" >/dev/null
rm -f "$lab_dir/ipat-r58-images.tar"
echo 'R58_LOCAL_CONTAINERD_IMAGES_IMPORTED=PASS'
# Inspect only normalized synthetic image references, never registry credentials.
images="$(sudo "$lab_dir/k3s" ctr -n k8s.io images list -q)"
for app in control-api usp-controller; do
  if ! grep -Eq "(^|/)ipat/${app}:r58-lab$" <<< "$images"; then
    echo "R58_IMAGE_REF_MISMATCH_${app}" >&2; exit 4
  fi
done
echo 'R58_BOTH_NORMALIZED_LOCAL_IMAGES_PRESENT=PASS'
# Helm chart forbids externally published services; validate before install.
helm lint deploy/helm/ipat-lab >/dev/null
helm template ipat-r58 deploy/helm/ipat-lab -n ipat-r58 \
  > "$lab_dir/ipat-r58-rendered.yaml"
python3 deploy/scripts/lab/r58/verify-rendered.py "$lab_dir/ipat-r58-rendered.yaml"
k create namespace ipat-r58 >/dev/null
if ! sudo helm install ipat-r58 deploy/helm/ipat-lab -n ipat-r58 \
  --kubeconfig "$lab_dir/kubeconfig" --wait --timeout 105s >/dev/null; then
  # Deliberately never print pod env/spec/images, event messages or logs.
  k -n ipat-r58 get deployments -o json 2>/dev/null | \
    python3 deploy/scripts/lab/r58/ci-safe-status.py deployments || :
  k -n ipat-r58 get pods -o json 2>/dev/null | \
    python3 deploy/scripts/lab/r58/ci-safe-status.py pods || :
  k -n ipat-r58 get events -o json 2>/dev/null | \
    python3 deploy/scripts/lab/r58/ci-safe-status.py events || :
  echo 'R58_HELM_ROLLOUT_FAILED_WITH_SAFE_STATUS_ONLY' >&2
  exit 1
fi
k -n ipat-r58 rollout status deployment/ipat-control-api --timeout=180s >/dev/null
k -n ipat-r58 rollout status deployment/ipat-usp-controller --timeout=180s >/dev/null
echo 'R58_BOTH_ACTUAL_K3S_APP_PODS_READY=PASS'
# Same-namespace smoke pod only. The network policy grants this fixed role;
# note that image/pod reachability does not prove every ingress denial works
# unless the chosen CNI actually enforces network policy.
k -n ipat-r58 run ipat-smoke --image=busybox:1.37.0 --restart=Never \
  --labels=ipat-role=smoke --command -- sh -c 'sleep 350' >/dev/null
k -n ipat-r58 wait --for=condition=Ready pod/ipat-smoke --timeout=150s >/dev/null
k -n ipat-r58 exec ipat-smoke -- sh -c \
  'wget -qO- http://ipat-control-api:3000/healthz | grep -qx ok'
k -n ipat-r58 exec ipat-smoke -- sh -c \
  'wget -qO- http://ipat-usp-controller:3100/healthz | grep -qx synthetic-usp-lab-only'
k -n ipat-r58 exec ipat-smoke -- sh -c \
  "wget -S -O /dev/null http://ipat-control-api:3000/v1/devices/synthetic \
    2>&1 | grep -Fq '401 Unauthorized'"
echo 'R58_HEALTH_AND_DENY_BY_DEFAULT_IN_REAL_K3S_PODS=PASS'
# Verify that the actual bundled network-policy controller rejects a pod
# without the approved smoke label, after proving its DNS is functional.
k -n ipat-r58 run ipat-unapproved --image=busybox:1.37.0 --restart=Never \
  --labels=ipat-role=unapproved --command -- sh -c 'sleep 350' >/dev/null
k -n ipat-r58 wait --for=condition=Ready pod/ipat-unapproved --timeout=150s >/dev/null
k -n ipat-r58 exec ipat-unapproved -- \
  nslookup ipat-control-api.ipat-r58.svc.cluster.local >/dev/null
k -n ipat-r58 exec ipat-unapproved -- sh -c \
  'if wget -T 4 -qO- http://ipat-control-api:3000/healthz >/dev/null 2>&1; then exit 53; else exit 0; fi'
echo 'R58_ACTUAL_UNAPPROVED_SAME_NAMESPACE_POD_INGRESS_DENIED=PASS'
echo 'R58_LIMITATION=HEALTH_ONLY_NO_REAL_OIDC_USP_TRANSPORT_OR_EXTERNAL_EXPOSURE'
