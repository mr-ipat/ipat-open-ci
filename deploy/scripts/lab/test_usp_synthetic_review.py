"""R5 domain static gates retained alongside R8.1 independent protobuf/HTTP tests."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CORE = (ROOT / "crates/usp-core/src/lib.rs").read_text()
APP = (ROOT / "apps/usp-controller/src/main.rs").read_text()


class SyntheticUspBoundaryTests(unittest.TestCase):
    def test_transport_and_operator_proofs_have_no_public_constructors(self):
        for name in ("VerifiedAgent", "TrustedOperator"):
            self.assertIn("pub struct " + name, CORE)
            self.assertNotIn("impl " + name, CORE)
        self.assertIn("#[cfg(test)]", CORE)
        self.assertIn("fn peer(byte: u8) -> VerifiedAgent", CORE)
        self.assertIn("fn trusted_operator(label: &str) -> TrustedOperator", CORE)

    def test_synthetic_only_and_no_unauthorized_mutating_rpc(self):
        for label in ("Domain logic below NEVER trusts unverified wire input",
                      "pub fn plan_read(", "pub fn accept_reply(", "ReplayFull",
                      "WrongPeer", "WrongTenant", "MAX_REPLY"):
            self.assertIn(label, CORE)
        self.assertIn("pub mod wire14;", CORE)
        self.assertIn("actual_protobuf_wire_to_virtual_controller_domain_denies_cross_tenant_and_replay", CORE)
        for forbidden in ("pub fn set_parameter", "pub fn reboot", "pub fn apply_config",
                          "TcpListener", "mqtt", "axum"):
            self.assertNotIn(forbidden, CORE)

    def test_loopback_explicit_optin_and_denied_untrusted_route(self):
        self.assertIn('IPAT_RUN_OFFLINE_USP_LAB', APP)
        self.assertIn('127.0.0.1:3100', APP)
        self.assertIn('StatusCode::SERVICE_UNAVAILABLE', APP)
        # R5.8 permits pod-only wildcard bind ONLY when both separate explicit
        # synthetic+K3s lab flags are supplied; the default is still loopback.
        self.assertIn('IPAT_RUN_K3S_LAB', APP)
        self.assertIn('if k3s_lab {', APP)
        self.assertIn('bind_address(k3s_lab)', APP)
        self.assertIn('bind_address(false), "127.0.0.1:3100"', APP)
        self.assertIn('bind_address(true), "0.0.0.0:3100"', APP)
        # Historical 3 Axum and 12 domain tests MUST remain, while R8.1
        # adds new independent real-protobuf HTTP and virtual-domain tests.
        self.assertGreaterEqual(APP.count("#[tokio::test]"), 5)
        self.assertGreaterEqual(CORE.count("#[test]"), 13)
        self.assertIn("async fn no_usp_transport_route_accepts_untrusted_agent_messages", APP)
        self.assertIn("async fn malformed_or_wrong_content_type_rejected_and_k3s_parser_absent", APP)


if __name__ == "__main__":
    unittest.main()
