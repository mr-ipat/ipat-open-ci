"""R8.2 code/CI contract: no real CPE, network/ACS escalation or writes."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
MAIN=(ROOT/"apps/cwmp-gateway/src/main.rs").read_text()
SMOKE=(ROOT/"deploy/scripts/lab/r82/virtual-cwmp-http-smoke.sh").read_text()
HTTP=(ROOT/"deploy/scripts/lab/r82/virtual_cwmp_http_smoke.py").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()

class VirtualCWMPContract(unittest.TestCase):
    def test_live_real_cwmp_unconditionally_denied(self):
        self.assertIn('.route("/cwmp", any(|| async { StatusCode::SERVICE_UNAVAILABLE }))',MAIN)
        self.assertIn('const LAB_BIND: &str = "127.0.0.1:3300"',MAIN)
        self.assertNotIn("0.0.0.0:3300",MAIN)
        self.assertIn('app_with_virtual_ont(false)',MAIN)
        self.assertIn('std::env::var("IPAT_RUN_K3S_LAB")',MAIN)
        self.assertIn('std::env::var("IPAT_R82_ENABLE_VIRTUAL_ONT")',MAIN)
        self.assertIn('std::env::var("IPAT_RUN_OFFLINE_CWMP_LAB")',MAIN)
    def test_fixed_one_read_and_no_dynamic_identity_privileges(self):
        for guard in (
            'inform.manufacturer == "SYNTHETIC"',
            'inform.oui == "001122"',
            'inform.product_class == "FAKE-ONT"',
            'inform.serial_number == "FAKE-NOT-PHYSICAL"',
            'inform.event_codes == ["0 BOOTSTRAP"]',
            'cwmp_protocol::inform_response(&inform)',
            'cwmp_protocol::rpc::read_request(',
            'cwmp_protocol::rpc::LAB_PARAMETER',
            'cwmp_protocol::rpc::parse_read_reply(',
            'DefaultBodyLimit::max(cwmp_protocol::MAX_XML_BYTES)',
            '"peer_authenticated":false',
            '"tenant_bound":false',
            '"session_established":false'
        ): self.assertIn(guard,MAIN)
        self.assertNotIn("SetParameterValues(",MAIN)
        self.assertNotIn("firmware_upgrade(",MAIN)
        self.assertNotIn("AuthenticatedPeer::",MAIN)
        self.assertNotIn("Authorization: Bearer",MAIN)
    def test_actual_local_smoke_enforces_opt_in_and_malicious_cases(self):
        for guard in (
            "IPAT_R82_SYNTHETIC_HTTP", "IPAT_R82_ENABLE_VIRTUAL_ONT=YES",
            "IPAT_RUN_OFFLINE_CWMP_LAB=1", "env -u IPAT_RUN_K3S_LAB",
            "rm -rf", "127.0.0.1", "ss -H -lnt"
        ): self.assertIn(guard,SMOKE)
        for guard in (
            "/lab/virtual-ont/inform", "/lab/virtual-ont/read-request",
            "/lab/virtual-ont/read-reply", "/cwmp",
            "FAKE-SENSITIVE-DEVICE-FIRMWARE",
            "application/xml", "b\"x\"*65537",
            "GetParameterValuesResponse", "SetParameterValues",
        ): self.assertIn(guard,HTTP)
    def test_ci_executes_real_compiled_axum_and_python_xml_roundtrip(self):
        self.assertIn("test_r82_contract.py",CI)
        self.assertIn("virtual-cwmp-http-smoke.sh",CI)
        self.assertIn("cargo test --locked -p cwmp-gateway",CI)
        self.assertIn("IPAT_R82_SYNTHETIC_HTTP=YES",CI)

if __name__=="__main__":unittest.main()
