"""R6.9 deny-by-default contract for verified JWT vs membership.
Static inspection alone is NOT a live IdP or MFA proof.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[4]
IDENTITY = (ROOT / "crates/identity-core/src/lib.rs").read_text()
PROBE = (ROOT / "apps/control-api/src/oidc_lab.rs").read_text()
GATEWAY = (ROOT / "apps/control-api/src/main.rs").read_text()
HTTP = (ROOT / "deploy/scripts/lab/r69/oidc-private-http-smoke.sh").read_text()

class R69SecurityGuardrails(unittest.TestCase):
    def test_only_fixed_pinned_rsa_key_and_no_untrusted_jwks_resolution(self):
        for expected in (
            "DecodingKey::from_rsa_pem", "Validation::new(Algorithm::RS256)",
            "header.kid.as_deref()", "header.jku.is_some()",
            "header.jwk.is_some()", "header.x5u.is_some()",
            "header.x5c.is_some()", "validation.set_issuer",
            "validation.set_audience", "validation.validate_nbf = true",
            "MAX_ACCESS_TOKEN_LIFETIME_SECS: u64 = 900",
        ):
            self.assertIn(expected, IDENTITY)
        self.assertNotIn(".dangerous()", IDENTITY)
        self.assertNotIn("from_secret(", IDENTITY)

    def test_verified_subject_cannot_infer_client_supplied_roles_or_tenant(self):
        self.assertIn("pub struct VerifiedSubject", IDENTITY)
        subject = IDENTITY.split("pub struct VerifiedSubject",1)[1].split("impl VerifiedSubject",1)[0]
        for forbidden in ("tenant", "role", "pop", "platform_owner"):
            self.assertNotIn(forbidden, subject.lower())
        self.assertIn('"tenant_membership_verified":false', PROBE)
        self.assertIn('"business_access_enabled":false', PROBE)
        self.assertIn('"roles_verified":false', PROBE)

    def test_probe_is_private_opt_in_and_never_unlocks_all_business_endpoints(self):
        self.assertIn("IPAT_LAB_OIDC_VERIFY", GATEWAY)
        self.assertIn("if lab_web_enabled", GATEWAY)
        self.assertIn("oidc_lab::from_owner_environment()", GATEWAY)
        self.assertIn('"/lab/auth/verify"', PROBE)
        for path in ("/v1/platform/{*path}", "/v1/tenant/{*path}",
                     "/v1/operations/{*path}"):
            self.assertIn(path, GATEWAY)
        self.assertIn("axum::routing::any(unauthenticated_business_api)", GATEWAY)
        self.assertIn("StatusCode::UNAUTHORIZED", GATEWAY)

    def test_pinned_key_cannot_come_from_browser_and_requires_owner_permissions(self):
        for expected in ("libc::O_NOFOLLOW", "0o700", "0o600",
                         "metadata.nlink() != 1", "IPAT_LAB_OIDC_PUBLIC_KEY_FILE",
                         "libc::geteuid()", "HeaderMap",
                         "header::AUTHORIZATION", "verify_access_token(token)"):
            self.assertIn(expected, PROBE)
        self.assertNotIn("X-Tenant-Id", PROBE)
        self.assertNotIn("X-Role", PROBE)
        self.assertNotIn("decode_header(token).unwrap()", PROBE)

    def test_actual_synthetic_http_script_denies_all_real_work_and_cleans_keys(self):
        for expected in ("IPAT_R69_RUN_SYNTHETIC_HTTP",
                         'mktemp -d /tmp/ipat-r69-jwt.', 'trap cleanup EXIT',
                         "issuer-test-only.key", 'Bearer ',
                         "/lab/auth/verify", "/v1/platform/tenants",
                         "/v1/tenant/members", "/v1/operations/alerts",
                         "R69_SIGNED_TOKEN_STILL_NO_TENANT_MEMBERSHIP_AND_BUSINESS_APIS_401"):
            self.assertIn(expected, HTTP)
        for forbidden in ("--insecure", "curl -k", "IPAT_RUN_K3S_LAB=1"):
            self.assertNotIn(forbidden, HTTP)

if __name__ == "__main__":
    unittest.main()
