"""Static fail-closed contracts for Mr. iPat's R5.7 disposable K3s recovery lab."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[4]
SOURCE = (ROOT / "deploy/scripts/lab/r57/source-systemd-k3s.sh").read_text()
RESTORE = (ROOT / "deploy/scripts/lab/r57/restore-systemd-k3s.sh").read_text()
NFT = (ROOT / "deploy/scripts/lab/r57/nft-rollback-drill.sh").read_text()
ALL = SOURCE + RESTORE + NFT

class R57RecoverySafety(unittest.TestCase):
    def test_exact_disposable_qemu_guards_exist(self):
        for text, host in ((SOURCE, "ipat-r57-a"), (RESTORE, "ipat-r57-b"),
                           (NFT, "ipat-r57-b")):
            self.assertIn("R57_QEMU_UBUNTU26_DISPOSABLE_ONLY", text)
            self.assertIn(host, text)
            self.assertIn("ubuntu:26.04", text)
            self.assertIn("systemd-detect-virt", text)
            self.assertIn("qemu", text)
        self.assertIn("aarch64", SOURCE)
        self.assertIn("aarch64", RESTORE)

    def test_pinned_k3s_and_private_api_boundary(self):
        for text in (SOURCE, RESTORE):
            self.assertTrue("v1.36.4+k3s1" in text or "v1.36.4%2Bk3s1" in text)
            self.assertIn("c920706346d5ad4e5cd3c7bf1bb09ce71ebe07fec829e513e40f1caf98aed8bb", text)
            self.assertIn("https-listen-port: 16443", text)
            self.assertIn("0[.]0[.]0[.]0:16443", text)
            self.assertIn("sha256sum", text)
        self.assertNotIn("get.k3s.io", ALL)

    def test_restore_requires_original_token_and_stale_node_reconciliation(self):
        self.assertIn("/var/lib/rancher/k3s/server/token", RESTORE)
        self.assertIn("--cluster-reset", RESTORE)
        self.assertIn("--cluster-reset-restore-path=", RESTORE)
        self.assertIn("IPAT_R57_SNAPSHOT_SHA256", RESTORE)
        self.assertIn("delete node ipat-r57-a", RESTORE)
        self.assertIn("spec.nodeName=ipat-r57-a", RESTORE)
        self.assertIn("restore-marker", RESTORE)
        self.assertIn("r57-post-restore", RESTORE)
        self.assertIn("dns-after-restart", RESTORE)
        self.assertNotIn("cat /var/lib/rancher/k3s/server/token", RESTORE)
        self.assertNotIn("echo $IPAT_R57", RESTORE)

    def test_source_exports_token_without_printing_secret(self):
        self.assertIn("/var/lib/ipat-r57/export/server-token", SOURCE)
        self.assertIn("install -m 0600 /var/lib/rancher/k3s/server/token", SOURCE)
        self.assertIn("R57_SOURCE_TOKEN_BYTES=", SOURCE)
        self.assertNotIn("cat /var/lib/rancher/k3s/server/token", SOURCE)

    def test_nft_drill_has_precise_timed_rollback_and_opt_in(self):
        for marker in ("IPAT_R57_INTENTIONAL_SSH_ROLLBACK_DRILL",
                       "nft -c -f", "policy drop", "AccuracySec=1s",
                       "RandomizedDelaySec=0", "ipat_r57_lab",
                       "--on-active=10s"):
            self.assertIn(marker, NFT)
        self.assertIn("nft delete table inet ipat_r57_lab", NFT)
        self.assertNotIn("flush ruleset", NFT)
        self.assertNotIn("iptables -F", NFT)

    def test_no_live_vps_or_external_provider_integration(self):
        for forbidden in ("ipat-lab", "/home/openai",
                          "security group", "provider api", "ufw enable"):
            self.assertNotIn(forbidden.lower(), ALL.lower())

if __name__ == "__main__":
    unittest.main()
