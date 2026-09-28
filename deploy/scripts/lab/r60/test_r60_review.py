"""Mr. iPat: R6.0 planned hardware inventory; zero physical enrollment."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "deploy/scripts/lab/r60/prepare-device-intake.py"
SPEC = importlib.util.spec_from_file_location("ipat_r60", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CATALOG = json.loads((ROOT / "web/lab/device-targets.json").read_text())
RUST = (ROOT / "apps/control-api/src/main.rs").read_text()
HTML = (ROOT / "web/lab/index.html").read_text()
JS = (ROOT / "web/lab/app.js").read_text()

def sample():
    return {
        "target_id": "DEV-01",
        "exact_model": "C320",
        "hardware_revision": "GPFD Rev A",
        "firmware_build": "V2.1.0",
        "protocol_candidate": "snmpv3",
    }

class HardwareIntakeSafety(unittest.TestCase):
    def test_canonical_targets_are_exactly_planned_matrix_not_physical(self):
        self.assertEqual([f"DEV-{i:02d}" for i in range(1, 9)],
                         [t["id"] for t in CATALOG["targets"]])
        self.assertEqual(0, CATALOG["physical_devices_enrolled"])
        self.assertEqual(0, CATALOG["physical_interoperability_verified"])
        self.assertFalse(CATALOG["network_discovery_enabled"])
        self.assertFalse(CATALOG["compatibility_claim"])
        self.assertEqual(["awaiting_metadata"] * 7,
                         [t["status"] for t in CATALOG["targets"][:7]])
        self.assertEqual("operator_reported_pending_verification",
                         CATALOG["targets"][7]["status"])
        self.assertEqual("RB951Ui-2HnD", CATALOG["targets"][7]["family"])
        self.assertEqual(["ZTE", "C-DATA", "VSOL", "ZTE", "MikroTik",
                          "MikroTik", "MikroTik", "MikroTik"],
                         [t["vendor"] for t in CATALOG["targets"]])

    def test_valid_offline_metadata_is_still_not_approved_or_connected(self):
        value = MODULE.parse_intake(json.dumps(sample()).encode())
        self.assertEqual(value["target_id"], "DEV-01")
        self.assertEqual(value["status"], "awaiting_separate_authorization_and_physical_test")
        for field in ("physical_connection_performed", "compatibility_verified",
                      "tenant_binding_verified", "high_risk_writes_enabled"):
            self.assertIs(value[field], False)
        self.assertEqual(value["protocol_candidate"], "snmpv3")

    def test_rejects_secrets_addresses_spoofing_and_placeholders(self):
        invalid = []
        for key in ("password", "secret", "serial", "management_ip", "token"):
            row = sample()
            row[key] = "should-never-be-output"
            invalid.append(row)
        for field, value in (("target_id", "DEV-99"),
                             ("exact_model", "192.168.1.1"),
                             ("hardware_revision", "unknown"),
                             ("firmware_build", "password1"),
                             ("protocol_candidate", "telnet"),
                             ("protocol_candidate", "routeros-api-ssl"),
                             ("exact_model", "LAB-ONT\nInjected"),
                             ("exact_model", "<PLACEHOLDER>")):
            row = sample()
            row[field] = value
            invalid.append(row)
        for bad in invalid:
            with self.subTest(bad=bad):
                with self.assertRaises(MODULE.IntakeRejected):
                    MODULE.parse_intake(json.dumps(bad).encode())
        with self.assertRaises(MODULE.IntakeRejected):
            MODULE.parse_intake(b'{"target_id":"DEV-01","target_id":"DEV-02"}')
        with self.assertRaises(MODULE.IntakeRejected):
            MODULE.parse_intake(b"X" * 2049)

    def test_true_private_file_is_mode_0600_and_never_committed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            base.chmod(0o700)
            source = base / "operator-input.json"
            target = base / "validated-staging.json"
            source.write_text(json.dumps(sample()), encoding="utf-8")
            process = subprocess.run(
                [sys.executable, str(SCRIPT), "--input", str(source),
                 "--output", str(target)],
                cwd=ROOT, text=True, capture_output=True, timeout=7
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn("TEST=NOT_RUN", process.stdout)
            self.assertFalse("V2.1.0" in process.stdout)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertFalse(json.loads(target.read_text())["compatibility_verified"])
            duplicate = subprocess.run(
                [sys.executable, str(SCRIPT), "--input", str(source),
                 "--output", str(target)],
                cwd=ROOT, text=True, capture_output=True, timeout=7
            )
            self.assertEqual(duplicate.returncode, 4)
            self.assertIn("R60_INTAKE_DENIED", duplicate.stderr)
            assert base != ROOT

    def test_readonly_browser_and_k3s_negative_paths(self):
        for value in ('"/lab/device-targets"', "LAB_DEVICE_TARGETS",
                      "lab_device_targets", "StatusCode::METHOD_NOT_ALLOWED",
                      "private_catalog_rejects_mutation_without_fake_authentication"):
            self.assertIn(value, RUST)
        self.assertIn('awaiting_metadata', JS)
        self.assertIn('catalog.physical_devices_enrolled !== 0', JS)
        self.assertIn('catalog.network_discovery_enabled !== false', JS)
        self.assertIn("textContent", JS)
        self.assertNotIn("innerHTML", JS)
        self.assertIn('id="target-rows"', HTML)
        self.assertIn('0</span> perangkat fisik terdaftar', HTML)
        self.assertNotIn("/v1/devices", JS)

    def test_negative_missing_flag_excludes_lab_endpoint(self):
        self.assertIn('lab_web_enabled(k3s_lab, lab_requested)', RUST)
        self.assertIn('lab_requested && !k3s_lab', RUST)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn('test_r60_review.py', ci)

if __name__ == "__main__":
    unittest.main()
