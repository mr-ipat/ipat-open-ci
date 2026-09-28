"""Static checks: external provider external probe is observation, not firewall validation."""
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("external-readonly-network-check.sh")
SOURCE = SCRIPT.read_text()


class ExternalNetworkReviewTests(unittest.TestCase):
    def test_bash_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_refuses_unrecognized_mode(self):
        run = subprocess.run(["bash", str(SCRIPT), "--apply"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)

    def test_no_mutating_commands(self):
        for forbidden in ("ufw enable", "nft add", "iptables -A", "ssh -tt", "sudo ", "reset-firewall"):
            self.assertNotIn(forbidden, SOURCE)

    def test_external_probe_cannot_claim_provider_rule_validation(self):
        self.assertIn("EDGE_PROVIDER_MANAGED_FIREWALL=NOT_VISIBLE", SOURCE)
        self.assertIn("UDP_8472=NOT_SCANNED", SOURCE)
        self.assertIn("cannot distinguish provider filtering from absent service", SOURCE)


if __name__ == "__main__":
    unittest.main()
