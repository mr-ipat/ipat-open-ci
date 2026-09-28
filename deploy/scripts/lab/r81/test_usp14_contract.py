"""R8.1 BBF 1.4 independent golden and private parser static gates.
Real prost and real HTTP acceptance is in Rust tests and HTTP smoke, not here.
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
HERE=Path(__file__).resolve().parent
GEN=HERE/"generate_golden_usp.py"
MODULE=importlib.util.spec_from_file_location("ipat_usp_goldens",GEN)
MANUAL=importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(MANUAL)
WIRE=(ROOT/"crates/usp-core/src/wire14.rs").read_text()
APP=(ROOT/"apps/usp-controller/src/main.rs").read_text()
SMOKE=(HERE/"usp14-private-http-smoke.sh").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()

class BBF14OfflineOnly(unittest.TestCase):
    def test_independent_hand_encoded_request_response_fixtures_unchanged(self):
        for name,is_response in [
            ("usp14_get_request.bin",False),("usp14_get_response.bin",True),
            ("usp14_get_response_correlated.bin",True)
        ]:
            raw=(ROOT/"crates/usp-core/tests/fixtures"/name).read_bytes()
            msg_id="r1" if name.endswith("_correlated.bin") else "r-example-1"
            self.assertEqual(raw,MANUAL.golden(is_response,msg_id))
            self.assertLess(len(raw),1024)
        result=subprocess.run([sys.executable,str(GEN)],capture_output=True,
                              text=True,check=False)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_wire_narrow_subset_rejects_unsupported_record_and_duplicate(self):
        for marker in (
            "MAX_RECORD_BYTES: usize = 64 * 1024",
            "UnsupportedRecord","UnknownOrDuplicateField",
            "fn fields<", "let mut seen = HashSet::new()",
            "inspect_no_session_get_response",
            "encode_offline_get", "record.version != \"1.4\"",
            "record.payload_security != 0",
            "!record.mac_signature.is_empty()",
            "msg_type != 2","body.request.is_some()"
        ):
            self.assertIn(marker,WIRE)

    def test_real_usp_and_k3s_bind_stay_disabled_and_never_claim_auth(self):
        for marker in (
            'if k3s_lab { health_only() } else { app() }',
            '.route("/lab/inspect-usp14", post(lab_inspect))',
            'inspect_no_session_get_response(&body)',
            '"peer_authenticated": false',
            '"tenant_bound": false',
            '"usp_session_established": false',
            '"device_operations_enabled": false',
            'StatusCode::SERVICE_UNAVAILABLE'
        ):
            self.assertIn(marker,APP)
        self.assertNotIn('"/v1/usp", post(',APP)
        self.assertIn('127.0.0.1:3100',APP)

    def test_real_synthetic_http_script_is_explicit_opt_in_and_ci_wired(self):
        for marker in (
            'IPAT_R81_SYNTHETIC_HTTP:-',
            'IPAT_RUN_OFFLINE_USP_LAB=1',
            '127.0.0.1:3100',
            'R81_NO_REAL_USP_MTP',
        ):
            self.assertIn(marker,SMOKE)
        self.assertIn('IPAT_R81_SYNTHETIC_HTTP=YES bash ',CI)
        self.assertIn('cargo test --locked -p usp-core --test usp14_wire',CI)
        # No binary or network must start with default unapproved invocation.
        proc=subprocess.run(["bash",str(HERE/"usp14-private-http-smoke.sh")],
            cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(proc.returncode,4)
if __name__=="__main__":unittest.main()
