"""R7.4 offline isolated C320 plan tests; all device values synthetic."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "lab-readiness.py"
SPEC = importlib.util.spec_from_file_location("ipat_r74", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
STAGE = {
    "schema": 1, "intake_type": "unverified_offline_metadata_only",
    "target_id": "DEV-01", "category": "OLT", "vendor": "ZTE",
    "family": "C320", "exact_model": "ZXA10 C320",
    "hardware_revision": "SYNTHETIC-BOARD", "firmware_build": "SYNTHETIC-1",
    "protocol_candidate": "vendor-cli-readonly",
    "physical_connection_performed": False,
    "compatibility_verified": False, "tenant_binding_verified": False,
    "high_risk_writes_enabled": False,
    "status": "awaiting_separate_authorization_and_physical_test",
}
PLAN = {
    **MODULE.EXPECTED,
    **{name: True for name in MODULE.GATES}
}

class LabReadinessContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ipat-r74-")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.folder.chmod(0o700)
        self.set_json("stage.json", STAGE)
        self.set_json("plan.json", PLAN)

    def set_json(self, name, obj):
        file = self.folder / name
        file.write_text(json.dumps(obj))
        file.chmod(0o600)

    def call(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            capture_output=True, text=True, timeout=6)

    def test_requirements_do_not_read_private_files_or_open_network(self):
        result = self.call("--requirements")
        self.assertEqual(result.returncode, 0)
        self.assertIn("NO_DEVICE_NETWORK_NO_CREDENTIALS_NO_FIRMWARE", result.stdout)

    def test_declared_lab_packet_never_grants_connection_or_upgrade(self):
        result = self.call("--check-packet", self.folder)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertTrue(data["declared_first_read_prerequisites_complete"])
        for field in ("physical_test_executed", "device_compatibility_verified",
                      "tenant_enrollment_authorized", "firmware_update_authorized",
                      "network_operations_performed"):
            self.assertIs(data[field], False)
        self.assertEqual(data["packet_review"], "HUMAN_REVIEW_REQUIRED")
        self.assertNotIn("SYNTHETIC-BOARD", result.stdout)

    def test_missing_any_operator_declaration_blocks(self):
        for gate in MODULE.GATES:
            with self.subTest(gate=gate):
                plan = dict(PLAN)
                plan[gate] = False
                self.set_json("plan.json", plan)
                result = self.call("--check-packet", self.folder)
                self.assertEqual(result.returncode, 4)
                data = json.loads(result.stdout)
                self.assertIn(gate, data["pending_owner_prerequisites"])
                self.assertEqual(data["packet_review"], "BLOCKED")
        self.set_json("plan.json", PLAN)

    def test_fails_closed_for_production_traffic_and_unknown_fields(self):
        self.set_json("plan.json", dict(PLAN, environment="production"))
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)
        self.set_json("plan.json", dict(PLAN, extra_ip="198.51.100.1"))
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)

    def test_rejects_stage_compatibility_spoofing_or_wrong_model(self):
        self.set_json("stage.json", dict(STAGE, compatibility_verified=True))
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)
        self.set_json("stage.json", dict(STAGE, exact_model="Other"))
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)

    def test_rejects_symlink_hardlink_and_public_access(self):
        target = self.folder / "stage.json"
        target.rename(self.folder / "original.json")
        target.symlink_to(self.folder / "original.json")
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)
        target.unlink()
        (self.folder / "original.json").rename(target)
        os.link(target, self.folder / "extra.json")
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)
        (self.folder / "extra.json").unlink()
        self.folder.chmod(0o755)
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)

    def test_rejects_duplicate_json_and_nonowner_file(self):
        path = self.folder / "plan.json"
        path.write_text('{"target_id":"DEV-01","target_id":"DEV-08"}')
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)
        self.set_json("plan.json", PLAN)
        path.chmod(0o644)
        self.assertEqual(self.call("--check-packet", self.folder).returncode, 4)

    def test_source_never_includes_network_transport_or_write(self):
        source = SCRIPT.read_text()
        for forbidden in ("paramiko", "ssh-keyscan", "socket.create_connection",
                          "download img", "update-boot", "subprocess.run",
                          "requests.get", "urllib.request"):
            self.assertNotIn(forbidden, source)

if __name__ == "__main__":
    unittest.main()
