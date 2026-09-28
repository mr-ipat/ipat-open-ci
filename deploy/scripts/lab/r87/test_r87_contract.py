"""R8.7 offline OIDC two-token verifier code guards. No real session."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[4]
ID=(ROOT/"crates/identity-core/src/oidc_id_token.rs").read_text()
TEST=(ROOT/"crates/identity-core/tests/oidc_id_token.rs").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()
BROWSER=(ROOT/"apps/control-api/src/oidc_browser_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
class OidcPairContract(unittest.TestCase):
    def test_separate_verified_access_and_pinned_id_token(self):
        for g in ("verify_access_token(access_token)","Algorithm::RS256",
                  "header.kid.as_deref()","header.jku.is_some()",
                  "header.x5u.is_some()","validation.set_issuer",
                  "validation.set_audience","auth_time","MAX_AUTH_AGE",
                  "id.amr.iter().any","id.nonce","ct_eq",
                  "at_hash","Sha256::digest(access_token.as_bytes())"):
            self.assertIn(g,ID)
        self.assertNotIn("pub fn create_session(",ID)
        self.assertNotIn("HTTP",ID.split("use super::")[0])
    def test_never_mints_membership_or_routes_id_token_directly(self):
        for bad in ("tenant_id:","role:","pop_id:","SessionCookie",
                    "client_secret","std::process::Command","reqwest::"):
            self.assertNotIn(bad,ID)
        self.assertIn("StatusCode::SERVICE_UNAVAILABLE",BROWSER)
        self.assertIn('"/v1/tenant/{*path}"',MAIN)
        self.assertIn('"/v1/operations/{*path}"',MAIN)
    def test_real_independent_os_generated_rsa_negative_fixtures(self):
        for g in ('Command::new("openssl")','wrong_client',
                  'wrong-kid','at_hash','auth_time','only_password',
                  'other_token','"at+jwt"'):
            self.assertIn(g,TEST)
    def test_ci_runs_actual_real_rust_rsa_verification(self):
        self.assertIn("cargo test --locked -p identity-core --test oidc_id_token",CI)
        self.assertIn("test_r87_contract.py",CI)
if __name__=="__main__":unittest.main()
