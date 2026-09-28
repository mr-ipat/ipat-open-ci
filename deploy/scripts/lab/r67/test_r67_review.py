"""IPAT R6.7 source guardrails for real TLS cryptographic laboratory.
All physical customer devices remain untested; offline-only inspection.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[4]
BINARY = ROOT / "apps/cwmp-gateway/src/bin/cwmp-mtls-lab.rs"
SCRIPT = ROOT / "deploy/scripts/lab/r67/mtls-loopback-contract.sh"
MANIFEST = ROOT / "apps/cwmp-gateway/Cargo.toml"

class RustlsLabBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = BINARY.read_text()
        cls.bash = SCRIPT.read_text()
        cls.cargo = MANIFEST.read_text()

    def test_real_tls13_requires_client_certificate_chain(self):
        self.assertIn("ServerConfig::builder_with_protocol_versions", self.src)
        self.assertIn("rustls::version::TLS13", self.src)
        self.assertIn("WebPkiClientVerifier::builder(Arc::new(roots))", self.src)
        self.assertIn(".with_client_cert_verifier(verifier)", self.src)
        for forbidden in ("allow_unauthenticated()", "with_no_client_auth()",
                          ".dangerous()", "tls_client_cert_header",
                          "StrictHostKeyChecking=no"):
            self.assertNotIn(forbidden, self.src)

    def test_only_explicit_nonroot_private_listener_and_no_flexible_bind(self):
        self.assertIn("Ipv4Addr::LOCALHOST, 3433", self.src)
        self.assertIn("IPAT_RUN_PRIVATE_CWMP_MTLS_LAB", self.src)
        self.assertIn("libc::geteuid()", self.src)
        self.assertNotIn("0.0.0.0", self.src)
        self.assertNotIn("SocketAddr::from_str", self.src)

    def test_no_customer_endpoint_or_tenant_privilege_promotion(self):
        self.assertIn('.route("/cwmp", any(|| async { StatusCode::SERVICE_UNAVAILABLE }))', self.src)
        self.assertIn('"device_enrolled":false', self.src)
        self.assertIn('"tenant_bound":false', self.src)
        self.assertIn('"cwmp_response_sent":false', self.src)
        self.assertIn('"production_acs":false', self.src)
        self.assertNotIn("register(", self.src)
        self.assertNotIn("AuthenticatedPeer {", self.src)
        self.assertNotIn("sudo ", self.src)

    def test_private_certificates_are_file_owner_bounded_and_nofollow(self):
        for expected in ("symlink_metadata(", "meta.uid()", "meta.nlink() != 1",
                         "meta.len() > MAX_PEM_BYTES", "libc::O_NOFOLLOW",
                         "0o700", "0o600", "RootCertStore::empty()"):
            self.assertIn(expected, self.src)
        self.assertIn("exactly_one_cert(private_file", self.src)
        self.assertIn("tls.max_early_data_size = 0", self.src)

    def test_real_client_and_server_negative_handshake_fixtures_are_exercised(self):
        for expected in ('--tlsv1.3', '--tls-max 1.3',
                         'MISSING_CLIENT_CERTIFICATE_WRONGLY_ADMITTED',
                         'UNTRUSTED_CLIENT_CA_WRONGLY_ADMITTED',
                         'WRONG_CLIENT_EKU_WRONGLY_ADMITTED',
                         'TLS_SERVER_HOSTNAME_BYPASS_DETECTED',
                         'TLS_CLIENT_TRUSTED_UNKNOWN_SERVER_CA',
                         'reject_candidate "$tmp/linked.key"',
                         'reject_candidate "$tmp/server.key"',
                         'R67_INVALID_PRIVATE_CERTIFICATE_DID_NOT_FAIL_CLOSED',
                         'R67_PRIVATE_LISTENER_TEARDOWN=PASS'):
            self.assertIn(expected, self.bash)
        self.assertNotIn('curl -k', self.bash)
        self.assertNotIn('--insecure', self.bash)

    def test_synthetic_lab_only_no_real_customer_credentials_in_repository(self):
        for text in (self.src, self.bash, self.cargo):
            self.assertNotRegex(text, r"\b110\.232\.82\.82\b")
            self.assertNotIn("F52qGGDX", text)
        self.assertIn('mktemp -d /tmp/ipat-r67-mtls.', self.bash)
        self.assertIn('trap cleanup EXIT', self.bash)
        self.assertIn('version = "=0.7.3"', self.cargo)
        self.assertIn('rustls = "=0.23.45"', self.cargo)

if __name__ == "__main__":
    unittest.main()
