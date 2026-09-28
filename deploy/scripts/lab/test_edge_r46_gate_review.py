"""Static checks: source-only external provider+FileVault gate, NOT provider rule verification."""
from pathlib import Path
import subprocess
import unittest

SCRIPT = Path(__file__).with_name("edge-r46-gate-check.sh")
SOURCE = SCRIPT.read_text()


class EdgeR46GateReviewTests(unittest.TestCase):
    def test_bash_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_only_report_flag_allowed(self):
        p = subprocess.run(["bash", str(SCRIPT), "--apply"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)

    def test_no_mutation_or_credential_dumps(self):
        for forbidden in (
            "sudo ", "ufw enable", "nft add", "iptables -A",
            "systemctl reload", "RESTIC_PASSWORD=", "security find-generic-password",
            "Reset Rules", "ssh -tt",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, SOURCE)

    def test_global_ipv6_and_provider_unknown_explicit(self):
        for required in (
            "FILEVAULT=ON",
            "PROPOSED_SOURCE_CIDR=",
            "CAUTION_IP_STABILITY=NOT_ESTABLISHED",
            "VPS_GLOBAL_IPV6_GUEST",
            "OWNER_SCREENSHOT_EDGE_SG_IPV4_INBOUND=ALLOW_ALL",
            "OWNER_SCREENSHOT_EDGE_SG_IPV6_INBOUND=ALLOW_ALL",
            "SECURITY_GROUP_OTHER_VM_ATTACHMENTS=UNVERIFIED",
            "VNC_REAL_LOGIN=REQUIRES_OWNER_CONFIRMATION",
            "RESTIC_PASSWORD_INDEPENDENT_ESCROW=REQUIRES_OWNER_CONFIRMATION",
            "EDGE_PROVIDER_FIREWALL_CHANGE=NOT_PERFORMED",
        ):
            with self.subTest(required=required):
                self.assertIn(required, SOURCE)


if __name__ == "__main__":
    unittest.main()
