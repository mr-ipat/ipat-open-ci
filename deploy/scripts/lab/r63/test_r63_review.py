"""R6.3 SSH HOST IDENTITY - no credentials, no automatic trust rewrite."""
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "deploy/scripts/lab/r63/ssh-host-trust-check.py"
SPEC = importlib.util.spec_from_file_location("ipat_r63", SCRIPT)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
OLD = "SHA256:" + "a" * 43
NEW = "SHA256:" + "b" * 43

class SSHHostKeyGates(unittest.TestCase):
    def test_exact_single_global_ipv4_port_never_scan_network_range(self):
        for address in ["127.0.0.1", "10.0.0.1", "192.168.1.1",
                        "224.0.0.1", "router.lab", "198.51.100.153/24",
                        "0.0.0.0", "::1"]:
            with self.subTest(address=address), self.assertRaises(M.Rejected):
                M.explicit_public_ipv4(address, 11122)
        self.assertEqual(M.explicit_public_ipv4("8.8.8.8", 11122), "8.8.8.8")
        for port in [0, 65536, -1]:
            with self.assertRaises(M.Rejected):
                M.explicit_public_ipv4("8.8.8.8", port)

    def test_changed_key_must_block_without_independent_verification(self):
        self.assertEqual(M.assess(NEW, OLD), ("HOST_KEY_CHANGED_UNVERIFIED", False))
        self.assertEqual(M.assess(NEW, None), ("NO_HISTORICAL_HOST_KEY", False))
        self.assertEqual(M.assess(NEW, OLD, OLD),
                         ("INDEPENDENT_FINGERPRINT_MISMATCH", False))
        self.assertEqual(M.assess(NEW, OLD, NEW),
                         ("INDEPENDENT_MATCH_REPIN_SEPARATELY", True))
        self.assertEqual(M.assess(OLD, OLD),
                         ("HISTORICAL_HOST_KEY_MATCH", True))
        self.assertEqual(M.assess(OLD, OLD, NEW),
                         ("INDEPENDENT_FINGERPRINT_CONFLICT", False))

    def test_rejects_ambiguous_and_malformed_fingerprints(self):
        for data in ["", "SHA256:short", OLD + "\n" + NEW]:
            with self.assertRaises(M.Rejected):
                M.single_fingerprint(data)
        self.assertEqual(M.single_fingerprint("RSA " + NEW), NEW)

    def test_no_auth_ssh_client_and_no_knownhosts_mutation_in_source(self):
        source = SCRIPT.read_text()
        self.assertIn('"ssh-keyscan"', source)
        self.assertIn('"ssh-keygen"', source)
        self.assertNotIn('sshpass', source)
        self.assertNotIn('StrictHostKeyChecking=no', source)
        self.assertNotIn('ssh-keygen -R', source)
        self.assertNotIn('known_hosts").write', source)
        self.assertNotIn('subprocess.Popen', source)
        self.assertNotIn('"ssh",', source)

    def test_single_keyscan_only_and_no_ssh_password(self):
        fake_scan = "[8.8.8.8]:11122 ssh-rsa FAKE_RSA_PUBLIC_KEY\n"
        seen = []
        def runner(args, stdin=None):
            seen.append((args, stdin))
            if args[0] == "ssh-keyscan":
                return fake_scan
            if args[0] == "ssh-keygen":
                return "2048 " + NEW + " test (RSA)"
            raise AssertionError("unexpected program")
        with patch.object(M, "run_command", side_effect=runner):
            self.assertEqual(M.observed_rsa_fingerprint("8.8.8.8", 11122), NEW)
        self.assertEqual(seen[0][0][:3], ["ssh-keyscan", "-T", "5"])
        self.assertEqual(seen[1][0], ["ssh-keygen", "-lf", "-", "-E", "sha256"])
        self.assertIn(b"ssh-rsa FAKE_RSA_PUBLIC_KEY", seen[1][1])

    def test_unambiguous_historical_key_only(self):
        with patch.object(M, "run_command",
                          return_value="# Host found\n[test]:11122 RSA " + OLD):
            self.assertEqual(M.historical_rsa_fingerprint("8.8.8.8", 11122), OLD)
        with patch.object(M, "run_command", side_effect=M.Rejected("no known host")):
            self.assertIsNone(M.historical_rsa_fingerprint("8.8.8.8", 11122))

    def test_only_owner_mode_0600_private_external_fingerprint_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            file = root / "trusted-lan-fingerprint.txt"
            file.write_text(NEW + "\n", encoding="ascii")
            file.chmod(0o600)
            self.assertEqual(M.independently_verified_private_fingerprint(str(file)), NEW)
            file.chmod(0o644)
            with self.assertRaises(M.Rejected):
                M.independently_verified_private_fingerprint(str(file))
            file.chmod(0o600)
            alias = root / "alias"
            alias.symlink_to(file)
            with self.assertRaises(M.Rejected):
                M.independently_verified_private_fingerprint(str(alias))
            file.write_text(OLD + "\n" + NEW)
            with self.assertRaises(M.Rejected):
                M.independently_verified_private_fingerprint(str(file))

    def test_no_owner_confirmation_means_no_network_scan_even_if_file_exists(self):
        with patch.object(M, "observed_rsa_fingerprint",
                          side_effect=AssertionError("NETWORK_MUST_NOT_OPEN")):
            with patch.object(sys, "argv", [
                "ssh-host-trust-check.py", "--target-ipv4", "8.8.8.8",
                "--port", "11122", "--independent-fingerprint-file",
                "/definitely/no/file",
            ]):
                with patch.dict(os.environ,
                                {"IPAT_R63_VERIFIED_FROM_TRUSTED_LAN": ""}):
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(M.main(), 4)

    def test_independent_private_proof_only_labels_match_never_logs_in(self):
        with patch.object(M, "observed_rsa_fingerprint", return_value=NEW), \
             patch.object(M, "historical_rsa_fingerprint", return_value=OLD), \
             patch.object(M, "independently_verified_private_fingerprint", return_value=NEW), \
             patch.object(sys, "argv", [
                 "ssh-host-trust-check.py", "--target-ipv4", "8.8.8.8",
                 "--port", "11122", "--independent-fingerprint-file",
                 "/test/ONLY_STUBBED_BY_MOCK",
             ]), \
             patch.dict(os.environ, {"IPAT_R63_VERIFIED_FROM_TRUSTED_LAN": "YES"}):
            result = io.StringIO()
            with redirect_stdout(result):
                self.assertEqual(M.main(), 0)
            self.assertIn("INDEPENDENT_MATCH_REPIN_SEPARATELY", result.getvalue())
            self.assertIn("PASSWORD_SENT=NO", result.getvalue())
            self.assertIn("no account authentication", result.getvalue())

    def test_real_main_changed_key_fixture_fails_closed_without_password(self):
        with patch.object(M, "observed_rsa_fingerprint", return_value=NEW), \
             patch.object(M, "historical_rsa_fingerprint", return_value=OLD), \
             patch.object(sys, "argv", [
                 "ssh-host-trust-check.py", "--target-ipv4", "8.8.8.8",
                 "--port", "11122",
             ]):
            result = io.StringIO()
            with redirect_stdout(result):
                self.assertEqual(M.main(), 4)
            text = result.getvalue()
            self.assertIn("HOST_KEY_CHANGED_UNVERIFIED", text)
            self.assertIn("PASSWORD_SENT=NO", text)

if __name__ == "__main__":
    unittest.main()
