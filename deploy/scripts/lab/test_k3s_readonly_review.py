"""Source-only test. Host/CNI/backup security requires separate real execution."""

from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).with_name("k3s-readonly-preflight.sh")
SOURCE = SCRIPT.read_text()


class K3sReadOnlyReviewTests(unittest.TestCase):
    def test_bash_parse(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_only_report_arg_is_permitted(self):
        proc = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--report", proc.stderr)

    def test_no_package_install_network_mutation_or_executed_remote_code(self):
        # This is a limited source contract, not a bash interpreter/sandbox.
        for disallowed in (
            "apt-get install", "apt install", "curl | sh", "curl -sfL",
            "modprobe ", "sysctl -w", "systemctl start ", "ufw enable",
            "iptables -A", "nft add", "k3s server", "kubectl apply",
        ):
            with self.subTest(disallowed=disallowed):
                self.assertNotIn(disallowed, SOURCE)

    def test_recovery_and_provider_gates_are_explicitly_unknown(self):
        self.assertIn("PROVIDER_PUBLIC_FIREWALL=UNVERIFIED_BY_GUEST", SOURCE)
        self.assertIn("OUT_OF_BAND_RESCUE=REQUIRES_OPERATOR_VERIFICATION", SOURCE)
        self.assertIn("COMPLETE_ENCRYPTED_INDEPENDENT_BACKUP_AND_RESTORE=NOT_VERIFIED", SOURCE)
        self.assertIn("K3S_INSTALL_GATE=BLOCKED_UNTIL_RECOVERY_NETWORK_AND_ADR_REVIEW", SOURCE)


if __name__ == "__main__":
    unittest.main()
