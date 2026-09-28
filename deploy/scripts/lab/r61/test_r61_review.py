"""Mr. iPat: R6.1 secure device-specific read-only RouterOS acceptance tests."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "deploy/scripts/lab/r61/readonly-rest-probe.py"
SPEC = importlib.util.spec_from_file_location("ipat_r61", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
TARGETS = json.loads((ROOT / "web/lab/device-targets.json").read_text())

def sample(ip="192.168.88.42"):
    return {
        "target_id": "DEV-08",
        "expected_model": "RB951Ui-2HnD",
        "expected_routeros": "7.23.7",
        "management_ipv4": ip,
        "tls_name": "rb951.lab.internal",
        "ca_cert_path": "",
        "netrc_path": "",
        "owner_permission": "confirmed_by_operator",
        "isolated_lab_route_confirmed": True,
    }

class ReadOnlyCustomerRouterReview(unittest.TestCase):
    def test_only_dev08_user_reported_never_claim_real_support(self):
        targets = TARGETS["targets"]
        self.assertEqual(len(targets), 8)
        self.assertEqual(targets[-1]["id"], "DEV-08")
        self.assertEqual(targets[-1]["family"], "RB951Ui-2HnD")
        self.assertIn("7.23.7", targets[-1]["firmware"])
        self.assertEqual(targets[-1]["status"],
                         "operator_reported_pending_verification")
        self.assertEqual(TARGETS["physical_devices_enrolled"], 0)
        self.assertEqual(TARGETS["physical_interoperability_verified"], 0)
        self.assertFalse(TARGETS["network_discovery_enabled"])
        self.assertFalse(TARGETS["compatibility_claim"])

    def test_sanitizer_drops_serial_secrets_tenant_and_address(self):
        payload = [{
            "board-name": "RB951Ui-2HnD", "architecture-name": "mipsbe",
            "version": "7.23.7", "serial-number": "NEVER_PRINT_SERIAL",
            "ip-address": "NEVER_PRINT_IP", "password": "NEVER_PRINT_SECRET",
            "user": "NEVER_PRINT_USER", "uptime": "5d"
        }]
        result = MOD.sanitize_resource(payload, "RB951Ui-2HnD", "7.23.7")
        serialized = json.dumps(result)
        for secret in ("NEVER_PRINT_SERIAL", "NEVER_PRINT_IP",
                       "NEVER_PRINT_SECRET", "NEVER_PRINT_USER"):
            self.assertNotIn(secret, serialized)
        self.assertFalse(result["physical_device_enrolled"])
        self.assertFalse(result["tenant_binding_verified"])
        self.assertFalse(result["compatibility_verified"])
        self.assertFalse(result["operator_review_complete"])
        self.assertFalse(result["configuration_modified"])
        self.assertEqual(result["hardware_revision"], "NOT_OBSERVED")

    def test_documented_version_suffix_only_without_accidental_upgrade(self):
        base = {"board-name": "RB951Ui-2HnD", "architecture-name": "mipsbe"}
        for version in ["7.23.7", "7.23.7 (stable)", "7.23.7 (long-term)"]:
            value = MOD.sanitize_resource([dict(base, version=version)],
                                          "RB951Ui-2HnD", "7.23.7")
            self.assertEqual(value["routeros"], version)
            self.assertFalse(value["compatibility_verified"])
        for version in ["7.23.70", "7.23.6", "7.23.7 (development)",
                        "7.23.7 (testing)", "7.23.7 (stable)\nInjected"]:
            with self.assertRaises(MOD.Rejected):
                MOD.sanitize_resource([dict(base, version=version)],
                                      "RB951Ui-2HnD", "7.23.7")

    def test_mismatch_duplicate_or_unexpected_shape_rejected(self):
        base = {"board-name": "RB951Ui-2HnD",
                "architecture-name": "mipsbe", "version": "7.23.7"}
        for altered in [{"version": "7.24.2"},
                        {"architecture-name": "arm"},
                        {"board-name": "CCR2004"},
                        {"board-name": "bad\nleak"}]:
            payload = dict(base, **altered)
            with self.subTest(altered=altered):
                with self.assertRaises(MOD.Rejected):
                    MOD.sanitize_resource([payload], "RB951Ui-2HnD", "7.23.7")
        for payload in ([], [base, base], {"foo": "bar"}, "raw"):
            with self.assertRaises(MOD.Rejected):
                MOD.sanitize_resource(payload, "RB951Ui-2HnD", "7.23.7")

    def local_config(self, directory: Path):
        ca = directory / "lab-ca.pem"
        ca.write_text("SYNTHETIC_CERT_TEST_ONLY", encoding="utf-8")
        netrc = directory / "credentials.netrc"
        netrc.write_text(
            "machine rb951.lab.internal login READ_ONLY_TEST_USER"
            " password PLACEHOLDER_NOT_REAL\n", encoding="utf-8"
        )
        netrc.chmod(0o600)
        config = directory / "config.json"
        value = sample()
        value["ca_cert_path"] = str(ca)
        value["netrc_path"] = str(netrc)
        config.write_text(json.dumps(value), encoding="utf-8")
        config.chmod(0o600)
        return config, netrc, value

    def test_offline_preflight_never_opens_a_socket(self):
        with tempfile.TemporaryDirectory() as temp:
            config, _, _ = self.local_config(Path(temp))
            with patch.object(MOD.socket, "create_connection",
                              side_effect=AssertionError("NETWORK_IS_FORBIDDEN")):
                validated = MOD.validated(str(config))
                self.assertEqual(validated[0]["expected_routeros"], "7.23.7")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(config), "--preflight"],
                text=True, capture_output=True, timeout=6,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("REAL_CONNECTION=NOT_ATTEMPTED", result.stdout)
            self.assertNotIn("192.168.88.42", result.stdout)

    def test_preflight_refuses_permissions_routing_bad_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cfg, cred, value = self.local_config(root)
            forbidden = [
                {"management_ipv4": "8.8.8.8"},
                {"management_ipv4": "127.0.0.1"},
                {"management_ipv4": "198.51.100.1"},
                {"expected_routeros": "7.24.2"},
                {"expected_model": "OtherModel"},
                {"owner_permission": "not-approved"},
                {"isolated_lab_route_confirmed": False},
                {"tls_name": "invalid_name"},
                {"extra_secret": "NOT_ACCEPTED"},
            ]
            for change in forbidden:
                cfg.write_text(json.dumps(dict(value, **change)), encoding="utf-8")
                with self.subTest(change=change):
                    with self.assertRaises((MOD.Rejected, ValueError)):
                        MOD.validated(str(cfg))
            cfg.write_text(json.dumps(value), encoding="utf-8")
            cred.chmod(0o644)
            with self.assertRaises(MOD.Rejected):
                MOD.validated(str(cfg))
            cred.chmod(0o600)
            cfg.chmod(0o644)
            with self.assertRaises(MOD.Rejected):
                MOD.validated(str(cfg))
            cfg.chmod(0o600)
            duplicated = json.dumps(value).replace(
                '"target_id": "DEV-08"', '"target_id": "DEV-08", "target_id": "DEV-08"')
            cfg.write_text(duplicated, encoding="utf-8")
            with self.assertRaises(MOD.Rejected):
                MOD.validated(str(cfg))

    def test_real_read_requires_two_distinct_mac_opt_ins(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, _, _ = self.local_config(Path(temp))
            output = str(Path(temp) / "no-unapproved-output.json")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(cfg),
                 "--read", "--output", output],
                text=True, capture_output=True, timeout=6,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
            self.assertEqual(proc.returncode, 4)
            self.assertFalse(Path(output).exists())
            self.assertNotIn("192.168.88.42", proc.stderr)
            self.assertNotIn("PLACEHOLDER_NOT_REAL", proc.stderr)

    def test_invalid_output_path_fails_before_any_real_network(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg, _, _ = self.local_config(Path(temp))
            with patch.object(MOD.sys, "platform", "darwin"), \
                 patch.dict(os.environ, {
                     "IPAT_R61_REAL_READ": "YES",
                     "IPAT_R61_OWNER_CONFIRMS_SINGLE_GET": "YES",
                 }), \
                 patch.object(MOD.sys, "argv", [
                     "readonly-rest-probe.py", "--config", str(cfg),
                     "--read", "--output", str(ROOT / "FORBIDDEN_PROBE.json"),
                 ]), \
                 patch.object(MOD, "read_one",
                              side_effect=AssertionError("DEVICE_MUST_NOT_BE_CONTACTED")) as read:
                self.assertEqual(MOD.main(), 4)
                read.assert_not_called()

    def test_mocked_one_get_exact_path_no_write_or_redirect(self):
        class FakeResponse:
            status = 200
            def getheader(self, key, default=None):
                return default
            def read(self, _limit):
                return json.dumps([{
                    "board-name": "RB951Ui-2HnD",
                    "architecture-name": "mipsbe", "version": "7.23.7",
                    "serial-number": "SENSITIVE_TEST"
                }]).encode()
        calls = []
        class FakeConn:
            def __init__(self, ip, dns, ctx):
                self.args = (ip, dns)
            def request(self, method, path, headers=None):
                calls.append((method, path, headers))
            def getresponse(self):
                return FakeResponse()
            def close(self):
                calls.append(("close",))
        class FakeContext:
            minimum_version = None
        with patch.object(MOD.ssl, "create_default_context", return_value=FakeContext()):
            result = MOD.read_one(sample(), "/synthetic/not-a-real-cert",
                                  ("TEST_ONLY", "SYNTHETIC_NOT_REAL"), FakeConn)
        self.assertEqual(len([x for x in calls if x[0] == "GET"]), 1)
        self.assertEqual(calls[0][:2], ("GET", "/rest/system/resource"))
        self.assertEqual(calls[-1], ("close",))
        self.assertNotIn("SENSITIVE_TEST", json.dumps(result))
        self.assertFalse(result["compatibility_verified"])

    def test_only_new_owner_private_output_with_no_network_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            output = root / "redacted.json"
            result = MOD.sanitize_resource(
                [{"board-name":"RB951Ui-2HnD",
                  "architecture-name":"mipsbe","version":"7.23.7"}],
                "RB951Ui-2HnD", "7.23.7")
            MOD.private_output(str(output), result)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            data = output.read_text()
            self.assertNotIn("192.168", data)
            self.assertNotIn("password", data)
            with self.assertRaises(MOD.Rejected):
                MOD.private_output(str(output), result)

    def test_no_auto_enroll_no_tls_disable_no_secret_args(self):
        script = SCRIPT.read_text()
        for marker in ('IPAT_R61_REAL_READ', 'IPAT_R61_OWNER_CONFIRMS_SINGLE_GET',
                       'TLSVersion.TLSv1_2','create_default_context',
                       'server_hostname=self._expected_dns',
                       'socket.create_connection((self._private_ip, 443)',
                       'conn.request("GET", "/rest/system/resource"',
                       'os.O_EXCL'):
            self.assertIn(marker, script)
        for forbidden in ('verify=False', 'CERT_NONE', '"POST"', '"PATCH"',
                          '"DELETE"', 'subprocess.run(["curl"', 'nmap ',
                          'routeros_password', 'api_password'):
            self.assertNotIn(forbidden, script)
        self.assertFalse(MOD.sanitize_resource(
            [{"board-name": "RB951Ui-2HnD", "architecture-name": "mipsbe",
              "version": "7.23.7"}], "RB951Ui-2HnD", "7.23.7")["physical_device_enrolled"])

if __name__ == "__main__":
    unittest.main()
