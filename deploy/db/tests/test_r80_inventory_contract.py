"""Private R8.0 inventory route/fixed SQL acceptance smoke. No real DB."""
from pathlib import Path
import unittest

R=Path(__file__).resolve().parents[3]
SQL=(R/"deploy/db/migrations/0005_lab_verified_device_inventory.sql").read_text()
ROUTE=(R/"apps/control-api/src/tenant_membership_lab.rs").read_text()
MAIN=(R/"apps/control-api/src/main.rs").read_text()
CI=(R/".github/workflows/ci.yml").read_text()

class ReadOnlyInventoryContract(unittest.TestCase):
    def test_db_requires_exact_issuer_subject_tenant_pop_and_revocation(self):
        for guard in (
            "p_issuer","p_subject","p_tenant","p_role",
            "p_pop","m.revoked_at IS NULL","m.expires_at > statement_timestamp()",
            "t.state = 'active'","d.tenant_id = p_tenant",
            "d.pop_id = p_pop","g.pop_id = p_pop","LIMIT 100",
            "SECURITY DEFINER","SET search_path = pg_catalog",
            "REVOKE ALL ON FUNCTION",
        ):
            self.assertIn(guard,SQL)
        self.assertIn("p_role = 'noc_engineer'",SQL)
        self.assertNotIn("GRANT SELECT ON ipat_ops.devices TO ipat_identity_query",SQL)
        self.assertNotIn("GRANT SELECT ON ipat_ops.subscribers",SQL)
        self.assertIn("FOR SELECT TO ipat_identity_lookup_owner",SQL)

    def test_actual_route_rechecks_signed_token_and_db_same_snapshot(self):
        for value in (
            "verified_bearer(&store.verifier, &headers)",
            'query.role != "noc_engineer"',
            "WITH permit AS MATERIALIZED",
            "lookup_active_membership($1,$2,$3::uuid,$4,$5)",
            "list_authorized_lab_devices(",
            "visible_for_verified_candidate(",
            "&DashboardSection::OperationsInventory",
            '"real_business_access_enabled":false',
            '"mfa_verified":false',
            '"lab_only":true',
            '.route("/lab/auth/devices", get(devices))',
        ):
            self.assertIn(value,ROUTE)
        self.assertIn('if let Some(store) = store',MAIN)
        self.assertIn('axum::routing::any(unauthenticated_business_api)',MAIN)

    def test_no_http_parameter_sql_concatenation_or_table_direct_select(self):
        active=ROUTE.split("// R8.0: actual restricted PostgreSQL device inventory",1)[1]
        active=active.split("pub(super) fn router(",1)[0]
        for dangerous in ("format!(", "SET ROLE", "SET LOCAL", "INSERT INTO",
                          "UPDATE ipat_ops", "DELETE FROM", "FROM ipat_ops.devices"):
            # Disregard comments, which can explain prohibited SQL.
            executable="\n".join(line for line in active.splitlines()
                             if not line.lstrip().startswith("//"))
            self.assertNotIn(dangerous,executable)

    def test_explicit_disposable_postgres_ci_includes_full_rust_test(self):
        self.assertIn("test_verified_device_inventory_integration.py",CI)
        self.assertIn("r80_real_signed_jwt_to_postgres_tenant_pop_inventory",CI)
        self.assertIn("test_r80_inventory_contract.py",CI)

if __name__=="__main__":unittest.main()
