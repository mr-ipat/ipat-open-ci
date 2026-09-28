"""Static/contract checks for Mac-only encrypted backup; not a root restore drill."""
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("backup-mac-restic.sh")
SOURCE = SCRIPT.read_text()


class MacResticReviewTests(unittest.TestCase):
    def test_bash_parse(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_keychain_secret_is_not_materialized_as_environment_value(self):
        self.assertIn("RESTIC_PASSWORD_COMMAND=", SOURCE)
        self.assertIn("/usr/bin/security find-generic-password", SOURCE)
        for bad in ("RESTIC_PASSWORD=", "restic init", "curl | sh", "openssl rand", "chmod 777"):
            self.assertNotIn(bad, SOURCE)

    def test_checks_are_real_restore_not_snapshot_listing(self):
        self.assertIn("check --read-data", SOURCE)
        self.assertIn('restore "$snap_source"', SOURCE)
        self.assertIn('restore "$snap_partial"', SOURCE)
        self.assertIn('git -C "$source" archive --format=tar main', SOURCE)
        self.assertIn('expected_partial_sha=', SOURCE)
        self.assertIn('trap \'rm -rf "$testdir"\' EXIT', SOURCE)

    def test_source_stream_fails_if_git_archive_exits_nonzero(self):
        self.assertIn("--stdin-from-command -- git", SOURCE)
        self.assertNotIn("backup --stdin ", SOURCE)

    def test_explicit_scope_warning(self):
        self.assertIn("VERIFIED_SCOPE: this mode validates Git source and historical readable-config ONLY", SOURCE)
        self.assertIn("whole-host, PostgreSQL and K3s datastore recovery remain unverified", SOURCE)


if __name__ == "__main__":
    unittest.main()
