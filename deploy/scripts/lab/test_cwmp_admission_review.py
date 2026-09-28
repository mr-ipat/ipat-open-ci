"""Source guardrails for offline CWMP admission. NOT real TLS interoperability."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SRC = (ROOT / "crates/cwmp-admission/src/lib.rs").read_text()
MANIFEST = (ROOT / "crates/cwmp-admission/Cargo.toml").read_text()


class CwmpAdmissionReviewTests(unittest.TestCase):
    def test_trusted_peer_is_sealed_for_production(self):
        self.assertIn("pub struct AuthenticatedPeer", SRC)
        self.assertNotIn("pub fn new_peer", SRC)
        self.assertNotIn("impl AuthenticatedPeer", SRC)
        self.assertIn("fn peer(key: u8) -> AuthenticatedPeer", SRC)
        self.assertIn("#[cfg(test)]", SRC)

    def test_no_public_network_service_or_http_header_identity_fallback(self):
        for forbidden in ("axum", "TcpListener", "HeaderMap", "X-Client-Cert",
                          "reqwest", "std::process::Command", "unsafe {"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, MANIFEST)
        self.assertIn("pub fn begin(", SRC)
        self.assertIn("let inform = parse_inform(untrusted_xml)", SRC)
        self.assertIn("actual_tenant != trusted_tenant", SRC)
        self.assertIn("pinned_spki != peer.client_spki_sha256", SRC)

    def test_fail_closed_bounded_in_memory_semantics_explicit(self):
        for check in ("MAX_ENROLLMENTS", "MAX_ACTIVE", "MAX_REPLAY",
                      "SessionFull", "ReplayTableFull", "DuplicateDevice",
                      "ReusedCertificate", "MissingCorrelation", "InvalidLease"):
            with self.subTest(check=check):
                self.assertIn(check, SRC)
        self.assertIn("IN-MEMORY", SRC)
        self.assertEqual(SRC.count("#[test]"), 11)


if __name__ == "__main__":
    unittest.main()
