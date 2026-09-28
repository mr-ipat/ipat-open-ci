"""R7.2 local-only C320 file integrity proofs, all images are fake bytes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "c320-firmware-check.py"
DUMMY_BYTES = b"IPAT SYNTHETIC TEST IMAGE, NOT ZTE FIRMWARE\n"
PLAN = {
    "target_id": "DEV-01", "vendor": "ZTE", "model": "ZXA10 C320",
    "card_type": "SYNTHETIC", "image_kind": "software",
    "target_version": "SYNTHETIC-ONLY",
    "release_reference": "SYNTHETIC-NOT-VENDOR"
}

class OfflineFirmwareSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ipat-r72-test-")
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.write("plan.json", json.dumps(PLAN).encode())
        self.write("image.bin", DUMMY_BYTES)
        self.write("vendor.sha256",
                   (hashlib.sha256(DUMMY_BYTES).hexdigest()+"  image.bin\n").encode())

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data):
        p = self.root / name
        p.write_bytes(data)
        p.chmod(0o600)

    def run_script(self, args, consent=True):
        env = os.environ.copy()
        env.pop("IPAT_R72_APPROVE_OFFLINE_HASH_ONLY", None)
        if consent:
            env["IPAT_R72_APPROVE_OFFLINE_HASH_ONLY"] = "YES"
        return subprocess.run([sys.executable,str(SCRIPT),*map(str,args)],
                              env=env, text=True, capture_output=True, timeout=6)

    def test_requirements_never_need_files_or_network(self):
        result = self.run_script(["--requirements"],consent=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn("NO_DEVICE_ACCESS_NO_FIRMWARE_EXECUTION", result.stdout)

    def test_explicit_consent_is_mandatory(self):
        result = self.run_script(["--check",self.root],consent=False)
        self.assertEqual(result.returncode,4)
        self.assertIn("EXPLICIT_HASH_ONLY_OPT_IN_REQUIRED",result.stderr)

    def test_fake_data_matches_claimed_hash_but_never_authorizes_upgrade(self):
        result = self.run_script(["--check",self.root])
        self.assertEqual(result.returncode,0,result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["target_id"],"DEV-01")
        self.assertTrue(data["local_sha256_equals_operator_supplied_checksum"])
        for key in ("firmware_upgrade_enabled",
                    "actual_c320_board_compatibility_verified",
                    "physical_recovery_and_approvals_verified",
                    "vendor_release_authenticity_independently_proven"):
            self.assertIs(data[key],False)
        self.assertNotIn(hashlib.sha256(DUMMY_BYTES).hexdigest(),result.stdout)

    def test_refuses_corrupted_and_wrong_vendor_hash(self):
        self.write("image.bin",DUMMY_BYTES+b"tampered")
        bad = self.run_script(["--check",self.root])
        self.assertEqual(bad.returncode,4)
        self.assertIn("IMAGE_DIGEST_MISMATCH",bad.stderr)
        self.write("vendor.sha256", b"bad checksum\n")
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)

    def test_refuses_symlink_and_nonprivate_file(self):
        original = self.root/"image.bin"
        original.rename(self.root/"real.bin")
        original.symlink_to(self.root/"real.bin")
        result = self.run_script(["--check",self.root])
        self.assertEqual(result.returncode,4)
        self.assertIn("UNTRUSTED_FILE",result.stderr)
        original.unlink()
        (self.root/"real.bin").rename(original)
        original.chmod(0o644)
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)

    def test_refuses_public_owner_directory_and_hardlinks(self):
        self.root.chmod(0o755)
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)
        self.root.chmod(0o700)
        (self.root/"link.bin").hardlink_to(self.root/"image.bin")
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)

    def test_refuses_forged_device_model_and_extra_keys(self):
        forged = dict(PLAN)
        forged["model"] = "ZXA10 C300"
        self.write("plan.json",json.dumps(forged).encode())
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)
        forged=dict(PLAN,actuate_firmware=True)
        self.write("plan.json",json.dumps(forged).encode())
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)

    def test_does_not_accept_traversal_or_unbounded_metadata(self):
        forged = dict(PLAN)
        forged["release_reference"]="../../etc/passwd"
        self.write("plan.json",json.dumps(forged).encode())
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)
        self.write("plan.json",b" " * 8193)
        self.assertEqual(self.run_script(["--check",self.root]).returncode,4)

    def test_does_not_include_any_network_or_firmware_write_actuator(self):
        src=SCRIPT.read_text()
        for disallowed in ("paramiko","pysnmp","telnetlib","subprocess.Popen",
                           "socket.create_connection","urllib.request",
                           "update-boot","download img","reset slotno"):
            self.assertNotIn(disallowed,src)
        self.assertIn('"firmware_upgrade_enabled": False',src)
        self.assertIn('VENDOR_HASH_SOURCE_INDEPENDENTLY_VERIFIED=NOT_ESTABLISHED_BY_THIS_TOOL',src)

if __name__=="__main__":
    unittest.main()
