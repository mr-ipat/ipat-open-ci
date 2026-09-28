"""Mr. iPat: fail-closed static safety contract for Ubuntu 26.04 K3s lab."""
from pathlib import Path
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/scripts/lab/k3s-ubuntu26-ephemeral-ci.sh"
SOURCE = SCRIPT.read_text()
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text()


class K3sUbuntu26DisposableSafety(unittest.TestCase):
    def test_refuses_local_machine_and_untrusted_runner(self):
        env = os.environ.copy()
        for name in (
            "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS",
            "RUNNER_ARCH", "IPAT_K3S_DISPOSABLE_LAB",
        ):
            env.pop(name, None)
        result = subprocess.run(
            ["bash", str(SCRIPT)], env=env, capture_output=True, text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 4)
        self.assertIn("R56_K3S_LAB_BLOCKED", result.stderr)

    def test_runner_and_release_are_explicitly_pinned(self):
        for expected in (
            "GITHUB_ACTIONS:-", "RUNNER_ENVIRONMENT:-", "github-hosted",
            "IPAT_K3S_DISPOSABLE_LAB:-", "VERSION_ID", "26.04",
            "v1.36.4+k3s1",
            "835873f37245fc615f547a2fe2af9402a347875f13fa64a1f136de644955ea3f",
            "sha256sum --check --status",
        ):
            self.assertIn(expected, SOURCE)

    def test_disposable_private_only_and_no_external_control(self):
        for expected in (
            "--bind-address \"$node_ip\"", "--advertise-address \"$node_ip\"",
            "--https-listen-port 16443",
            "ipaddress.ip_network", "0[.]0[.]0[.]0:16443",
            "--disable traefik", "--disable servicelb",
            "mktemp -d /var/lib/ipat-k3s-ci.", "findmnt -n -o OPTIONS",
            "isolated container runtime data mount is noexec",
            "umask 022; exec", "--write-kubeconfig-mode 0600", "trap cleanup EXIT",
        ):
            self.assertIn(expected, SOURCE)
        for banned in (
            "ssh ipat-lab", "get.k3s.io |", "systemctl enable",
            "nft -f", "iptables -A", "gh api repos/mr-ipat/ipat",
            "/home/openai/workspaces/ipat", "/var/lib/rancher/k3s/server/token",
        ):
            self.assertNotIn(banned, SOURCE)

    def test_actual_pods_dns_and_ephemeral_etcd_snapshot_required(self):
        for expected in (
            "Ready", "get deployment coredns", "coredns_deployment_found=0",
            "rollout status deploy/coredns", "wait --for=condition=Ready",
            "nslookup kubernetes.default.svc.cluster.local",
            "etcd-snapshot save", "--etcd-server", "https://$node_ip:16443",
            "R56_EPHEMERAL_ETCD_SNAPSHOT_CREATED=PASS",
            "R56_LIMITATION=ONE_DISPOSABLE_RUNNER_NOT_MULTI_NODE_HA_OR_OFFHOST_RESTORE",
        ):
            self.assertIn(expected, SOURCE)

    def test_separate_ubuntu26_ci_job_and_no_live_runner(self):
        self.assertIn("k3s-ubuntu26-disposable:", WORKFLOW)
        self.assertIn("runs-on: ubuntu-26.04", WORKFLOW)
        self.assertIn("IPAT_K3S_DISPOSABLE_LAB: \"1\"", WORKFLOW)
        self.assertIn("k3s-ubuntu26-ephemeral-ci.sh", WORKFLOW)
        self.assertIn("test_k3s_ubuntu26_ephemeral_review.py", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
