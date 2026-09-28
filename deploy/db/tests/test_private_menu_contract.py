"""R7.8 hard-coded security contract; no real IdP/production DB required."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
BRIDGE=(ROOT/"apps/control-api/src/tenant_membership_lab.rs").read_text()
SQL=(ROOT/"deploy/db/migrations/0004_lab_scoped_identity_lookup.sql").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()
class PrivateMenuContract(unittest.TestCase):
    def test_explicit_nonroot_double_opt_in_and_unix_socket(self):
        for value in ("IPAT_LAB_SCOPED_MEMBERSHIP","IPAT_LAB_OIDC_VERIFY",
                      "IPAT_LAB_DB_CONNINFO_FILE",
                      "EXPECTED_DB_READER",
                      "Host::Unix(", "get_hostaddrs().is_empty()",
                      "get_options().is_none()", "libc::O_NOFOLLOW", "0o600"):
            self.assertIn(value,BRIDGE)
        self.assertIn("unsafe{libc::geteuid()}==0", "".join(BRIDGE.split()))
        self.assertIn("if scoped_requested && identity.is_none()",MAIN)
        self.assertIn('"127.0.0.1:3001"',MAIN)

    def test_verified_token_exact_sql_read_only_and_no_real_data(self):
        for value in ("verifier.verify_access_token(token)",
            "subject.issuer()","subject.subject()",
            "lookup_active_membership($1,$2,$3::uuid,$4,$5)",
            "visible_for_verified_candidate(",
            '"mfa_verified":false','"real_business_access_enabled":false',
            "if visible.is_empty()"):
            self.assertIn(value,BRIDGE)
        executable="\n".join(line for line in BRIDGE.splitlines()
                              if not line.lstrip().startswith("//"))
        for dangerous in ("SET ROLE ","SET LOCAL ipat.tenant_id",
                          "DELETE FROM ", "INSERT INTO ", "UPDATE ipat_"):
            self.assertNotIn(dangerous,executable)
        self.assertIn("RETURNS TABLE (approved_by text, expires_at timestamptz, tenant_slug text)",SQL)

    def test_existing_business_endpoints_continue_denial(self):
        self.assertIn("axum::routing::any(unauthenticated_business_api)",MAIN)
        self.assertIn('"/lab/auth/sections"',BRIDGE)
        self.assertIn("if let Some(store) = store",MAIN)
        self.assertIn("app_with_lab_identity_and_store(lab_web_enabled, identity, store)",MAIN)

    def test_ci_proves_live_disposable_pg_and_rust_signed_jwt(self):
        self.assertIn("seed_private_http_identity_ci.py",CI)
        self.assertIn("r78_end_to_end_real_signed_jwt_real_restricted_sql_real_axum_router",CI)
        self.assertIn("test_private_menu_contract.py",CI)

if __name__=="__main__": unittest.main()
