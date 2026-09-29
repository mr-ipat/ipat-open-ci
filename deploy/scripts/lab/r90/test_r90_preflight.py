"""Strict local-only unit proofs for one-target public OLT transport preflight."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "olt-telnet-network-preflight.py"
SPEC = importlib.util.spec_from_file_location("ipat_r90_noauth", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class FakeConnection:
    def __init__(self, initial):
        self.initial = initial
        self.receives = 0
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def settimeout(self, timeout): assert timeout <= 2
    def recv(self, size):
        assert size <= 512
        self.receives += 1
        if isinstance(self.initial, BaseException): raise self.initial
        return self.initial
    def sendall(self, _): raise AssertionError("client must send ZERO data")

class R90Safety(unittest.TestCase):
    def test_one_exact_connect_receive_zero_outbound(self):
        called = []
        fake = FakeConnection(bytes([255,251,1,255,253,24]))
        def connect(endpoint, timeout):
            called.append((endpoint, timeout))
            return fake
        result = MODULE.probe("127.0.0.1",4321,"owner-mac",connector=connect)
        self.assertEqual(called, [(("127.0.0.1",4321),5)])
        self.assertEqual(fake.receives,1)
        self.assertTrue(result["tcp_reachable"])
        self.assertTrue(result["telnet_iac_observed"])
        self.assertEqual(result["credential_bytes_sent"],0)
        self.assertFalse(result["host_identity_verified"])
        self.assertEqual(result["physical_read_test"],"NOT_RUN")
    def test_silent_tcp_is_not_verified_olt(self):
        result = MODULE.probe("127.0.0.1",321,"owner-mac",
                              connector=lambda endpoint, timeout:
                              FakeConnection(socket.timeout()))
        self.assertTrue(result["tcp_reachable"])
        self.assertFalse(result["telnet_iac_observed"])
        self.assertFalse(result["device_adopted"])
        self.assertEqual(result["health"],"NOT_MEASURED")

    def test_no_liveness_is_a_blocked_path_not_a_device_failing_health(self):
        def denied(endpoint, timeout): raise TimeoutError()
        report = MODULE.probe("127.0.0.1",321,"ipat-vps",connector=denied)
        self.assertFalse(report["tcp_reachable"])
        self.assertEqual(report["failure_class"],"TIMEOUT")
        self.assertEqual(report["connectivity"],"UNKNOWN")
        self.assertEqual(report["physical_read_test"],"NOT_RUN")

    def test_private_evidence_no_ip_or_server_banner_and_no_repo_writes(self):
        fake = FakeConnection(b"\xff\xfb\x01ZTE SECRET 1234 PASSWORD")
        report = MODULE.probe("127.0.0.1",321,"owner-mac",
                              connector=lambda endpoint, timeout:fake)
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp)
            out = MODULE.store_redacted(private, report)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode),0o600)
            record = json.loads(out.read_text())
            self.assertTrue(record["telnet_iac_observed"])
            self.assertNotIn("ZTE",out.read_text())
            self.assertNotIn("PASSWORD",out.read_text())
            self.assertNotIn("127.0.0.1",out.read_text())
        with self.assertRaises(ValueError):
            MODULE.store_redacted(MODULE.ROOT,report)
    def test_no_network_without_explicit_approval_or_exact_port(self):
        env = os.environ.copy()
        env.pop(MODULE.OPT_IN,None)
        result = subprocess.run([sys.executable,str(SCRIPT),"--preflight",
             "--target-ipv4","198.51.100.1"],env=env,
             capture_output=True,text=True,timeout=3)
        self.assertNotEqual(result.returncode,0)
        env[MODULE.OPT_IN]="YES"
        for address,port in (("127.0.0.1","321"),
                             ("198.51.100.1","22"),
                             ("olt.example.invalid","321")):
            result = subprocess.run([sys.executable,str(SCRIPT),"--preflight",
                "--target-ipv4",address,"--port",port],env=env,
                capture_output=True,text=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
        info = subprocess.check_output([sys.executable,str(SCRIPT),
                      "--requirements"],text=True)
        self.assertFalse(json.loads(info)["safe_for_credentials"])

    def test_dashboard_displays_timestamped_network_evidence_without_online_claim(self):
        page=(MODULE.ROOT / "web/lab/device-workbench.html").read_text()
        self.assertIn("BUKTI HISTORIS, BUKAN TELEMETRI LIVE",page)
        self.assertIn("SSH terenkripsi serta Telnet sementara",page)
        self.assertIn("Restic terenkripsi",page)
        self.assertIn("BELUM ADOPSI OTOMATIS",page)
        self.assertIn("bukan monitoring aktif",page)
        self.assertNotIn("198.51.100.109",page)

    def test_source_no_network_writes_or_command_execution(self):
        tree=ast.parse(SCRIPT.read_text())
        calls = [n.func for n in ast.walk(tree) if isinstance(n,ast.Call)]
        self.assertFalse(any(isinstance(f,ast.Attribute) and
             f.attr in ("send","sendall","sendto","system","Popen")
             for f in calls))
        self.assertNotIn("telnetlib",SCRIPT.read_text())

def load_tests(loader, suite, pattern):
    # Include R9.11 private no-credential SSH and dashboard status checks
    # in the existing R9.0 safety CI step without modifying workflow auth.
    extra=Path(__file__).resolve().parents[1] / "r911" / "test_private_ssh_identity_probe.py"
    spec=importlib.util.spec_from_file_location("r911_private_ssh_tests",extra)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    # R9.12 fixed-enum, no-secrets WireGuard UI is purely lab.
    extra=Path(__file__).resolve().parents[1] / "r912" / "test_wg_wizard_static.py"
    spec=importlib.util.spec_from_file_location("r912_wg_wizard_tests",extra)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    path=Path(__file__).resolve().parents[1] / 'r915' / 'test_site_a_plan.py'
    spec=importlib.util.spec_from_file_location('r915_site_a_tests',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    extra=Path(__file__).resolve().parents[1] / "r916" / "test_site_a_keypair_static.py"
    spec=importlib.util.spec_from_file_location("r916_site_a_key_policy",extra)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    path=Path(__file__).resolve().parents[1]/'r917'/'test_direct_protocol.py'
    spec=importlib.util.spec_from_file_location('r917_direct_protocol_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r919'/'test_c320_action_policy_static.py'
    spec=importlib.util.spec_from_file_location('r919_c320_action_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r920'/'test_prepare_pin.py'
    spec=importlib.util.spec_from_file_location('r920_console_pin_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r921'/'test_show_ssh.py'
    spec=importlib.util.spec_from_file_location('r921_offline_show_ssh_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r923'/'test_plan_ssh_remediation.py'
    spec=importlib.util.spec_from_file_location('r923_onsite_change_review_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r924'/'test_auth_capability.py'
    spec=importlib.util.spec_from_file_location('r924_actual_auth_offer_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r926'/'test_assess_site_packet.py'
    spec=importlib.util.spec_from_file_location('r926_offline_physical_acceptance_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r928'/'test_private_telnet_323.py'
    spec=importlib.util.spec_from_file_location('r928_exact_private_telnet_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r930'/'test_real_lab_metadata_no_false_adoption.py'
    spec=importlib.util.spec_from_file_location('r930_authenticated_lab_read_report_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r931'/'test_private_backup.py'
    spec=importlib.util.spec_from_file_location('r931_protected_real_config_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r932'/'test_owner_mac_restic_c320_snapshot.py'
    spec=importlib.util.spec_from_file_location('r932_owner_operated_off_vps_backup_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r933'/'test_actual_recovery_status_static.py'
    spec=importlib.util.spec_from_file_location('r933_actual_backup_metadata_only_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    path=Path(__file__).resolve().parents[1]/'r934'/'test_one_manual_c320_ssh_read.py'
    spec=importlib.util.spec_from_file_location('r934_ephemeral_actual_c320_one_read_tests',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    suite.addTests(loader.loadTestsFromModule(mod))
    return suite

if __name__=="__main__":
    unittest.main()
