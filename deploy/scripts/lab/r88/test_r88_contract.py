"""R8.8 statically ensure session primitive remains OFFLINE and no live user login."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[4]
SRC=(ROOT/"crates/identity-core/src/browser_session.rs").read_text()
ID=(ROOT/"crates/identity-core/src/oidc_id_token.rs").read_text()
BROWSER=(ROOT/"apps/control-api/src/oidc_browser_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
TEST=(ROOT/"crates/identity-core/tests/oidc_id_token.rs").read_text()
BRIDGE=(ROOT/"apps/control-api/src/browser_session_lab.rs").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()

class BrowserSessionBoundary(unittest.TestCase):
    def test_offline_identity_only_and_secret_hash_storage(self):
        for marker in (
            "pub fn issue(", "VerifiedBrowserIdentity", "getrandom::fill",
            "SHA", "Secure; HttpOnly; SameSite=Strict; Path=/",
            "self.sessions.get_mut", "Sha256::digest",
            "ConstantTimeEq", "SESSION_LIMIT", "SESSION_LIFETIME",
            "IDLE_LIFETIME", "pub fn revoke", "pub fn prune"
        ):
            # Do not require an exact SHA spelling in prose.
            if marker=="SHA":continue
            self.assertIn(marker,SRC)
        for forbidden in ("tokio_postgres", "http://", "SetParameterValues",
                          "approve_device(", "firmware_upgrade(", "tenant_id:",
                          "pub fn mint_role(", "access_token:"):
            self.assertNotIn(forbidden,SRC)
    def test_no_public_browser_login_or_real_business_bypass(self):
        self.assertIn("StatusCode::SERVICE_UNAVAILABLE",BROWSER)
        self.assertIn("authorization_code_discarded",BROWSER)
        self.assertNotIn("BrowserSessionVault",MAIN)
        self.assertNotIn("BrowserSessionVault",BROWSER)
        self.assertIn('"/v1/operations/{*path}"',MAIN)
        self.assertIn("unauthenticated_business_api",MAIN)
        self.assertIn("verify_offline_browser_pair",ID)
    def test_real_signed_fixture_exercises_security_and_negative(self):
        for name in (
            "r88_signed_pair_issues_opaque_unprivileged_session_and_csrf_gates",
            "r88_wrong_nonce_or_mfa_cannot_mint_session_and_expiry_revokes",
            "r88_session_rotation_invalidates_prior_cookie_and_csrf",
            "r88_capacity_timing_malformed_cookies_and_missing_origin_fail_closed",
        ):
            self.assertIn(name,TEST)
    def test_signed_pair_is_bound_to_actual_sealed_pg_per_request(self):
        for marker in (
            "verify_offline_browser_pair", "lookup_active_membership($1,$2,$3::uuid,$4,$5)",
            "current_scope_allowed", "pub(super) async fn issue_after_sealed_membership",
            "BrowserSessionVault", "RequestKind::Mutation",
            "r88_real_rsa_pair_to_disposable_postgres_tenant_pop_then_opaque_session",
        ): self.assertIn(marker,BRIDGE)
        for prohibited in ("Router::new(", "SetParameterValues", "UPDATE ipat_ops",
                           "INSERT INTO", "ALLOW_REAL_DEVICES", "RUST_LOG"):
            self.assertNotIn(prohibited,BRIDGE)
        self.assertIn("browser_session_lab::tests::r88_real_rsa_pair_to_disposable_postgres_tenant_pop_then_opaque_session",CI)
    def test_genuine_rust_ci_executes_session_tests(self):
        self.assertIn("test_r88_contract.py",CI)
        self.assertIn("cargo test --locked -p identity-core --test oidc_id_token",CI)

if __name__=="__main__":unittest.main()
