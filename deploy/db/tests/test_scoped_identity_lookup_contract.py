"""Static release guards for the strictly non-deployed R7.7 SQL lookup."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SQL = (ROOT / "deploy/db/migrations/0004_lab_scoped_identity_lookup.sql").read_text()
MAIN = (ROOT / "apps/control-api/src/main.rs").read_text()
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text()

class ScopedLookupSafety(unittest.TestCase):
    def test_identity_query_roles_are_non_login_non_bypass(self):
        for role in ("ipat_identity_lookup_owner", "ipat_identity_query"):
            self.assertIn(f"CREATE ROLE {role} NOLOGIN NOSUPERUSER NOCREATEDB", SQL)
        self.assertIn("NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT", SQL)

    def test_function_is_private_fixed_search_path_no_dynamic_sql(self):
        self.assertIn("LANGUAGE sql STABLE SECURITY DEFINER", SQL)
        self.assertIn("SET search_path = pg_catalog, ipat_platform", SQL)
        self.assertIn("REVOKE ALL ON FUNCTION ipat_platform.lookup_active_membership", SQL)
        self.assertIn("TO ipat_identity_query", SQL)
        self.assertNotIn("EXECUTE format(", SQL)
        self.assertNotIn("EXECUTE p_", SQL)
        self.assertNotIn("TO ipat_app_runtime", SQL)
        self.assertNotIn("CREATE USER ", SQL)

    def test_exact_tenant_role_pop_revocation_requirements(self):
        for requirement in (
            "m.issuer = p_issuer", "m.subject = p_subject",
            "m.tenant_id = p_tenant", "m.role = p_role",
            "m.revoked_at IS NULL",
            "m.expires_at > statement_timestamp()",
            "t.state = 'active'", "g.pop_id = p_pop",
            "FOR SELECT", "USING (true)",
        ):
            self.assertIn(requirement, SQL, requirement)

    def test_business_endpoints_still_deny_and_no_public_domain_bind(self):
        self.assertIn("unauthenticated_business_api", MAIN)
        self.assertIn('"/v1/tenant/{*path}"', MAIN)
        self.assertIn('"/v1/platform/{*path}"', MAIN)
        self.assertIn('"/v1/operations/{*path}"', MAIN)
        self.assertNotIn("lookup_active_membership", MAIN)
        self.assertIn('"127.0.0.1:3000"', MAIN)

    def test_ephemeral_ci_exercises_scoped_sql_after_existing_memberships(self):
        a=WORKFLOW.find("test_identity_memberships_integration.py")
        b=WORKFLOW.find("test_scoped_identity_lookup_integration.py")
        self.assertGreater(a,0)
        self.assertGreater(b,a)
        self.assertIn("test_scoped_identity_lookup_contract.py", WORKFLOW)

if __name__ == "__main__":
    unittest.main()
