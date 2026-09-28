"""Static safety-contract checks; NOT a substitute for a real rollback drill."""

from pathlib import Path
import hashlib
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE / "stage2-ssh-key-only.sh"
HELPER = HERE / "apply-stage2-from-mac.sh"
EXPECTED_SHA = "800f1d228e7b19578569122d5a9ff4c4966b8d5520d4a9ac713b892edf9b3425"


class Stage2ReviewTests(unittest.TestCase):
    def test_bash_syntax(self):
        for script in (ROOT, HELPER):
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)

    def test_fixed_root_digest_and_helper_pin(self):
        digest = hashlib.sha256(ROOT.read_bytes()).hexdigest()
        self.assertEqual(digest, EXPECTED_SHA)
        self.assertIn(f"reviewed_stage_sha={digest}", HELPER.read_text())

    def test_revert_scheduled_before_ssh_policy_is_installed(self):
        root = ROOT.read_text()
        self.assertLess(
            root.index('systemd-run --quiet --collect'),
            root.index('install -o root -g root -m 0644 "$temp" "$managed"'),
        )
        self.assertIn('systemctl reload ssh', root)
        self.assertIn('systemctl stop "$unit.timer"', root)
        self.assertIn('--on-active=6m', root)
        self.assertIn('PermitRootLogin no', root)
        self.assertIn('PasswordAuthentication no', root)

    def test_explicit_human_and_fresh_connection_gates(self):
        helper = HELPER.read_text()
        for required in (
            'CONSOLE_READY',
            'DISABLE_PASSWORD_SSH',
            'PreferredAuthentications=publickey',
            'ControlMaster=no',
            'read -r -p \'Type CONFIRM',
            '--confirm',
            'NO VPS SNAPSHOT',
        ):
            self.assertIn(required, helper)

    def test_no_firewall_or_ssh_port_mutations(self):
        root = ROOT.read_text()
        for forbidden in ('ufw enable', 'iptables ', 'nft add', 'Port 2222'):
            self.assertNotIn(forbidden, root)


if __name__ == "__main__":
    unittest.main()
