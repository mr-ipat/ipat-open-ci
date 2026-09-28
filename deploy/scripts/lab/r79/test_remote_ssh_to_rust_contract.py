"""R7.9 actual offline Rust parser consumes only SYNTHETIC mock SSH outputs.
Never connect to OLT; real SSH+firmware interop still NOT RUN.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = Path(__file__).resolve().parent / "c320-ssh-readonly.py"
S = importlib.util.spec_from_file_location("ipat_r79_ssh_cross", SCRIPT)
M = importlib.util.module_from_spec(S)
S.loader.exec_module(M)
BIN = Path(os.getenv("CARGO_TARGET_DIR", str(ROOT / "target"))) / (
    "debug/c320-offline-review")
CARDS = ("Rack Shelf Slot CfgType RealType Port HardVer SoftVer Status\n"
         "1 1 1 GTGO GTGOG 8 120301 V2.0.0 INSERVICE\n"
         "1 1 3 SMXA SMXA 0 110702 V2.0.0 INSERVICE\n").encode()
VERSIONS = ("PhyLoc FileType VerType VerTag BuildTime VerLength\n"
            "1/1/1 GTGOG MVR V0.0.LAB 2026-01-01 01:02:03 100\n"
            "1/1/3 SMXA MVR V0.0.LAB 2026-01-01 01:02:03 100\n").encode()

class RealRustSyntheticTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert BIN.is_file(), "Build real locked offline Rust parser before test"
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ipat-r79-cross-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.private = root / "operator"
        self.private.mkdir(mode=0o700)
        self.capture = root / "protected-capture"
        self.capture.mkdir(mode=0o700)
        plan = {
            "target_id":"DEV-01", "environment":"isolated_lab",
            "transport":"ssh-strict-pinned-publickey",
            "profile":"zte-c320-exact-two-readonly-show-candidate",
            "private_ipv4":"10.72.4.10", "ssh_port":22,
            "ssh_user":"onlyread",
            **{key: True for key in M.GATES}
        }
        for name, content in (
            ("plan.json", json.dumps(plan)),
            ("known_hosts", "10.72.4.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA"),
            ("id_readonly", "SYNTHETIC NOT A REAL PRIVATE KEY")):
            file = self.private / name
            file.write_text(content)
            file.chmod(0o600)
    def parser(self):
        env = os.environ.copy()
        env["IPAT_R71_OWNER_CONFIRMS_REDACTED_OFFLINE_CAPTURE"] = "YES"
        return subprocess.run([str(BIN),"--parse",str(self.capture)],
            capture_output=True,text=True,timeout=6,env=env)
    def test_fixed_mock_remote_read_end_to_end_rust_counts_only(self):
        calls = []
        def fake(argv, **kwargs):
            calls.append(argv[-1])
            return types.SimpleNamespace(stdout=CARDS if len(calls)==1 else VERSIONS,
                                         returncode=0)
        with patch.dict(os.environ, {"IPAT_R79_OPERATOR_APPROVES_REMOTE_READ":"YES"}):
            with patch.object(M.subprocess,"run",side_effect=fake):
                result = M.collect(self.private,self.capture,M.packet(self.private)[0])
        self.assertEqual(calls,["show card","show version-running"])
        self.assertFalse(result["compatibility_verified"])
        self.assertFalse(result["firmware_enabled"])
        run = self.parser()
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn("CARDS=2 VERSION_ROWS=2",run.stdout)
        self.assertIn("PHYSICAL_DEVICE_IDENTITY=UNVERIFIED",run.stdout)
        self.assertNotIn("GTGOG",run.stdout)
        (self.capture/"versions.txt").write_bytes(VERSIONS.replace(b"GTGOG",b"BADBAD"))
        (self.capture/"versions.txt").chmod(0o600)
        failed = self.parser()
        self.assertEqual(failed.returncode,4)
        self.assertNotIn("BADBAD",failed.stderr)
if __name__=="__main__": unittest.main()
