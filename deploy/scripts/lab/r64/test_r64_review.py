"""R6.4 no-real-router tests for key-only strict SSH read of DEV-08."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "deploy/scripts/lab/r64/ssh-first-read.py"
SPEC = importlib.util.spec_from_file_location("ipat_r64", SCRIPT)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
GOOD_FP = "SHA256:" + "a" * 43
OLD_FP = "SHA256:" + "b" * 43

def example(temp):
    folder = Path(temp)
    folder.chmod(0o700)
    key = folder / "dedicated-test-key"
    key.write_text("FAKE_TEST_ONLY_PRIVATE_KEY_NOT_USABLE", encoding="ascii")
    key.chmod(0o600)
    trust = folder / "direct-lan-fingerprint.verified"
    trust.write_text(GOOD_FP + "\n", encoding="ascii")
    trust.chmod(0o600)
    cfg = {
        "target_id": "DEV-08",
        "expected_model": "RB951Ui-2HnD",
        "expected_routeros": "7.23.7",
        "public_ipv4": "8.8.8.8",
        "ssh_port": 2222,
        "dedicated_username": "lab_readonly",
        "dedicated_private_key": str(key),
        "trusted_lan_fingerprint_file": str(trust),
        "owner_permission": "confirmed_by_operator",
        "trusted_lan_independently_checked": True,
        "customer_backup_recovery_confirmed": True,
    }
    config = folder / "private-probe.json"
    config.write_text(json.dumps(cfg), encoding="ascii")
    config.chmod(0o600)
    return cfg, config, key, trust

class RouterOSSSHFirstRead(unittest.TestCase):
    def test_offline_requirements_never_scan_or_load_secrets(self):
        with patch.object(M, "load_private_config",
                          side_effect=AssertionError("NO_FILE_ACCESS")), \
             patch.object(M, "scan_single_rsa",
                          side_effect=AssertionError("NO_NETWORK")), \
             patch.object(sys, "argv", ["ssh-first-read.py", "--requirements"]):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(M.main(), 0)
            self.assertIn("NO_PUBLIC_ENDPOINT_LOGIN_OR_NETWORK_TRAFFIC", out.getvalue())

    def test_private_exact_config_is_local_0600_outside_git(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, path, key, trust = example(temp)
            loaded, identity, trusted = M.load_private_config(str(path))
            self.assertEqual(loaded["target_id"], "DEV-08")
            self.assertEqual(identity, key.resolve(strict=True))
            self.assertEqual(trusted, GOOD_FP)
            for change in [
                {"expected_routeros": "7.23.8"},
                {"target_id": "DEV-06"},
                {"owner_permission": "not_confirmed"},
                {"customer_backup_recovery_confirmed": False},
                {"trusted_lan_independently_checked": False},
                {"ssh_port": 0},
                {"ssh_port": True},
                {"public_ipv4": "127.0.0.1"},
                {"dedicated_username": "-oProxyCommand"},
                {"password": "FAKE_NEVER_STORE"},
            ]:
                with self.subTest(change=change):
                    path.write_text(json.dumps(dict(cfg, **change)), encoding="ascii")
                    with self.assertRaises((M.Rejected, M.TRUST.Rejected)):
                        M.load_private_config(str(path))
            path.write_text(json.dumps(cfg), encoding="ascii")
            key.chmod(0o644)
            with self.assertRaises(M.Rejected):
                M.load_private_config(str(path))
            key.chmod(0o600)
            path.chmod(0o644)
            with self.assertRaises(M.Rejected):
                M.load_private_config(str(path))
            path.chmod(0o600)
            dup = json.dumps(cfg).replace(
                '"target_id": "DEV-08"',
                '"target_id": "DEV-08", "target_id": "DEV-08"'
            )
            path.write_text(dup, encoding="ascii")
            with self.assertRaises(M.Rejected):
                M.load_private_config(str(path))
            path.write_text(json.dumps(cfg), encoding="ascii")
            trust.unlink()
            with self.assertRaises((M.Rejected, M.TRUST.Rejected, OSError)):
                M.load_private_config(str(path))

    def test_offline_preflight_performs_no_socket_or_subprocess(self):
        with tempfile.TemporaryDirectory() as temp:
            _, path, _, _ = example(temp)
            with patch.object(M, "scan_single_rsa",
                              side_effect=AssertionError("NO_HOST_KEY_SCAN")), \
                 patch.object(M.subprocess, "run",
                              side_effect=AssertionError("NO_SSH")), \
                 patch.object(sys, "argv",
                              ["ssh-first-read.py", "--config", str(path), "--preflight"]):
                out = io.StringIO()
                with redirect_stdout(out):
                    self.assertEqual(M.main(), 0)
                self.assertIn("SSH_LOGIN=NOT_ATTEMPTED", out.getvalue())

    def test_without_all_owner_opt_ins_no_network_or_login_even_with_valid_files(self):
        with tempfile.TemporaryDirectory() as temp:
            _, path, _, _ = example(temp)
            with patch.object(M, "scan_single_rsa",
                              side_effect=AssertionError("MUST_NOT_SCAN")), \
                 patch.object(M, "pin_and_read",
                              side_effect=AssertionError("MUST_NOT_LOGIN")), \
                 patch.object(M.sys, "platform", "darwin"), \
                 patch.dict(os.environ, {
                     "IPAT_R64_OWNER_APPROVES_SINGLE_SSH_READ": "YES",
                     "IPAT_R63_VERIFIED_FROM_TRUSTED_LAN": "",
                     "IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED": "YES",
                 }), \
                 patch.object(sys, "argv", [
                     "ssh-first-read.py", "--config", str(path), "--read",
                     "--output", str(Path(temp) / "unapproved.json"),
                 ]):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(M.main(), 4)
                self.assertFalse((Path(temp) / "unapproved.json").exists())

    def test_strict_only_3_expected_identity_lines_and_redacted_result(self):
        for text in [
            b"RB951Ui-2HnD\nmipsbe\n7.23.7\n",
            b"RB951Ui-2HnD\nmipsbe\n7.23.7 (stable)\n",
            b"RB951Ui-2HnD\nmipsbe\n7.23.7 (long-term)\n",
        ]:
            result = M.sanitize_ssh_read(text)
            self.assertEqual(result["model"], "RB951Ui-2HnD")
            self.assertFalse(result["physical_device_enrolled"])
            self.assertFalse(result["tenant_binding_verified"])
            self.assertFalse(result["compatibility_verified"])
            self.assertFalse(result["configuration_modified"])
            self.assertEqual(result["method"], "SSH_EXEC")
        for malformed in [
            b"CCR2004\nmipsbe\n7.23.7\n",
            b"RB951Ui-2HnD\narm\n7.23.7\n",
            b"RB951Ui-2HnD\nmipsbe\n7.23.8\n",
            b"RB951Ui-2HnD\nmipsbe\n7.23.7 (testing)\n",
            b"welcome\nRB951Ui-2HnD\nmipsbe\n7.23.7\n",
            b"RB951Ui-2HnD\nmipsbe\n7.23.7\nLEAK\n",
            b"RB951Ui-2HnD\nmipsbe\n7.23.7\n" + b"x" * 5000,
            b"RB951Ui-2HnD\nmipsbe\ninvalid\x1b",
        ]:
            with self.subTest(raw=malformed[:20]):
                with self.assertRaises(M.Rejected):
                    M.sanitize_ssh_read(malformed)

    def test_mismatched_independent_fingerprint_never_invokes_ssh(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, _, key, _ = example(temp)
            output = Path(temp) / "evidence.json"
            with (patch.object(M.TRUST, "historical_rsa_fingerprint",
                               side_effect=AssertionError("NO_FURTHER_TRUST")),
                  self.assertRaises(M.Rejected)):
                M.pin_and_read(
                    cfg, key, GOOD_FP, output,
                    scan=lambda *_: ("SYNTHETIC", OLD_FP),
                    launcher=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        AssertionError("NO_SSH_BEFORE_TRUST")
                    ),
                )
            self.assertFalse(output.exists())

    def test_output_destination_fails_before_any_server_key_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            _, path, _, _ = example(temp)
            with (patch.object(M, "pin_and_read",
                               side_effect=AssertionError("NETWORK_MUST_NOT_START")),
                  patch.object(M.sys, "platform", "darwin"),
                  patch.dict(os.environ, {
                      "IPAT_R64_OWNER_APPROVES_SINGLE_SSH_READ": "YES",
                      "IPAT_R63_VERIFIED_FROM_TRUSTED_LAN": "YES",
                      "IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED": "YES",
                  }),
                  patch.object(sys, "argv", [
                      "ssh-first-read.py", "--config", str(path), "--read",
                      "--output", str(ROOT / "UNSAFE_EVIDENCE.json"),
                  ])):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(M.main(), 4)

    def test_mocked_independent_match_creates_ephemeral_strict_single_key_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, _, key, _ = example(temp)
            output = Path(temp) / "evidence.json"
            calls = []
            line = "[8.8.8.8]:2222 ssh-rsa SYNTHETIC_PUBLIC_KEY_FIXTURE"
            def fake_ssh(args, **kwargs):
                calls.append(args)
                self.assertEqual(args[0], "ssh")
                self.assertEqual(args[-1], M.REMOTE_COMMAND)
                self.assertIn("BatchMode=yes", args)
                self.assertIn("PasswordAuthentication=no", args)
                self.assertIn("StrictHostKeyChecking=yes", args)
                self.assertIn("IdentityAgent=none", args)
                self.assertIn("HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256", args)
                self.assertIn("GlobalKnownHostsFile=/dev/null", args)
                self.assertIn("ClearAllForwardings=yes", args)
                self.assertEqual(args[-2], "lab_readonly@8.8.8.8")
                pinflag = next(item for item in args if item.startswith(
                    "UserKnownHostsFile="))
                pin = Path(pinflag.split("=", 1)[1])
                self.assertEqual(pin.read_text().strip(), line)
                self.assertEqual(stat.S_IMODE(pin.stat().st_mode), 0o600)
                kwargs["stdout"].write(b"RB951Ui-2HnD\nmipsbe\n7.23.7\n")
                return SimpleNamespace(returncode=0)
            with patch.object(M.TRUST, "historical_rsa_fingerprint",
                              return_value=OLD_FP), \
                 patch.dict(os.environ,
                            {"IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED": "YES"}):
                result = M.pin_and_read(
                    cfg, key, GOOD_FP, output,
                    scan=lambda *_: (line, GOOD_FP), launcher=fake_ssh,
                )
            self.assertEqual(len(calls), 1)
            self.assertFalse(result["physical_device_enrolled"])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text())["method"], "SSH_EXEC")
            self.assertNotIn("FAKE_PASSWORD", output.read_text())

    def test_historical_conflict_requires_explicit_additional_acknowledgment(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, _, key, _ = example(temp)
            out = Path(temp) / "evidence.json"
            with patch.object(M.TRUST, "historical_rsa_fingerprint",
                              return_value=OLD_FP), \
                 patch.dict(os.environ,
                            {"IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED": ""}), \
                 self.assertRaises(M.Rejected):
                M.pin_and_read(cfg, key, GOOD_FP, out,
                               scan=lambda *_: ("SYNTHETIC", GOOD_FP),
                               launcher=lambda *_a, **_k: (
                                   _ for _ in ()).throw(AssertionError("NO_LOGIN")))
            self.assertFalse(out.exists())

    def test_single_rsa_scan_refuses_ambiguous_untrusted_public_keys(self):
        rows = (
            "[8.8.8.8]:2222 ssh-rsa FAKE_FIRST\n"
            "[8.8.8.8]:2222 ssh-rsa FAKE_SECOND\n"
        )
        with patch.object(M.TRUST, "run_command", return_value=rows):
            with self.assertRaises(M.Rejected):
                M.scan_single_rsa("8.8.8.8", 2222)

    def test_dashboard_reports_security_block_not_connected_device(self):
        repo = ROOT
        catalog = json.loads((repo / "web/lab/device-targets.json").read_text())
        self.assertEqual(catalog["physical_devices_enrolled"], 0)
        self.assertEqual(catalog["physical_interoperability_verified"], 0)
        self.assertFalse(catalog["network_discovery_enabled"])
        device = catalog["targets"][7]
        self.assertEqual(device["id"], "DEV-08")
        self.assertEqual(device["status"], "operator_reported_pending_verification")
        self.assertEqual(device["access_gate"], "ssh_host_key_changed_unverified")
        markup = (repo / "web/lab/index.html").read_text()
        script = (repo / "web/lab/app.js").read_text()
        self.assertIn('id="router-security-alert"', markup)
        self.assertIn('ssh_host_key_changed_unverified', script)
        self.assertIn('status laboratorium terakhir', script)
        self.assertNotIn('innerHTML', script)
        self.assertNotIn('127.0.0.1:11122', script)

    def test_security_defaults_and_no_password_mode(self):
        source = SCRIPT.read_text()
        self.assertIn("StrictHostKeyChecking=yes", source)
        self.assertIn("PreferredAuthentications=publickey", source)
        self.assertIn("PasswordAuthentication=no", source)
        self.assertIn("IPAT_R63_VERIFIED_FROM_TRUSTED_LAN", source)
        self.assertIn("GlobalKnownHostsFile=/dev/null", source)
        self.assertNotIn("StrictHostKeyChecking=no", source)
        self.assertNotIn("sshpass", source)
        self.assertNotIn("password =", source)

if __name__ == "__main__":
    unittest.main()
