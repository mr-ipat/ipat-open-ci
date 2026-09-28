"""Read-only static contract tests. Does NOT prove privileged root backup ran."""
from pathlib import Path
import ast
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
PRODUCER = HERE / "root-config-stream.py"
RUNNER = HERE / "mac-root-config-backup.sh"
P = PRODUCER.read_text()
R = RUNNER.read_text()


def bash_root_payload():
    tree = ast.parse(P)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "ROOT_TAR" for t in node.targets):
                return ast.literal_eval(node.value)
    raise AssertionError("Missing literal root tar command")


class RootEncryptedStreamContractTests(unittest.TestCase):
    def test_syntax(self):
        subprocess.run(["python3", "-m", "py_compile", str(PRODUCER)], check=True)
        subprocess.run(["bash", "-n", str(RUNNER)], check=True)

    def test_root_stream_scoped_no_persistent_plaintext(self):
        payload = bash_root_payload()
        for needed in (
            "set -Eeuo pipefail", 'test "$(id -u)" = 0',
            "etc/ssh/sshd_config.d", "etc/sudoers",
            "home/openai/.ssh/authorized_keys",
            "tar -C / --one-file-system --numeric-owner",
            "-czf -",
        ):
            self.assertIn(needed, payload)
        for banned in ("ssh_host_", "passwd -", "ufw ", "systemctl restart",
                       "apt-get ", "mktemp", "/tmp/", "sudoers.d/*"):
            self.assertNotIn(banned, payload)

    def test_exact_safe_ssh_stream_and_local_tty_sudo(self):
        for needed in (
            '"-T"', '"StrictHostKeyChecking=yes"', '"ControlMaster=no"',
            '"PasswordAuthentication=no"', 'getpass.getpass(',
            '"sudo -S -k -p \'\' /bin/bash -c "',
            'first != b"\\x1f\\x8b"',
            'rc = proc.wait(', '"--smoke"', '"--fail-smoke"',
        ):
            self.assertIn(needed, P)
        self.assertNotIn("os.environ['SUDO", P)

    def test_encrypted_backup_and_failure_aware_producer(self):
        for expected in (
            "RESTIC_PASSWORD_COMMAND=",
            "--stdin-from-command --",
            "python3 \"$producer\" --root",
            "check --read-data", 'trap cleanup EXIT',
            "ESCROW_CONFIRMED_AND_BACKUP_ROOT",
            "FileVault is On.",
            "git -C \"$source\" branch --show-current",
            "tar -tzf \"$archive\"",
            "etc/sudoers",
            "HOST_SSH_PRIVATE_KEYS_AND_ALL_APPLICATION_STATE=NOT_INCLUDED",
        ):
            self.assertIn(expected, R)
        self.assertNotIn("RESTIC_PASSWORD=", R)

    def test_sudo_prompt_is_explicit_tty_and_restic_progress_is_quiet(self):
        self.assertIn('with open("/dev/tty", "w"', P)
        self.assertIn("BUKAN password/passphrase SSH", P)
        self.assertIn("password SUDO akun Linux openai", R)
        self.assertIn('restic -r "$repo" --quiet backup --tag ipat-lab,root-config', R)
        self.assertNotIn("sudo -i", R)

    def test_helper_refuses_unrecognized_mode(self):
        proc = subprocess.run(["bash", str(RUNNER), "--install-k3s"],
                              text=True, capture_output=True)
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
