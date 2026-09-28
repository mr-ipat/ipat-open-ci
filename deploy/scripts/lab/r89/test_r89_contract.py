"""Unmounted authentic BFF session -> exact sealed PostgreSQL scoped device rows."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
BRIDGE=(ROOT/"apps/control-api/src/browser_session_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()
SQL=(ROOT/"deploy/db/migrations/0006_lab_device_candidates.sql").read_text()
class R89SessionInventory(unittest.TestCase):
    def test_remains_unmounted_until_real_confidential_idp_mfa(self):
        self.assertIn("mod browser_session_lab;",MAIN)
        self.assertNotIn("browser_session_lab::pending_devices_for_session(",MAIN)
        self.assertNotIn("browser_session_lab::issue_after_sealed_membership(",MAIN)
        self.assertIn('"/v1/operations/{*path}"',MAIN)
        self.assertIn("unauthenticated_business_api",MAIN)
    def test_per_request_sealed_scope_not_cookie_tenant(self):
        for clause in (
            "vault.authenticate(", "RequestKind::Read",
            "lookup_active_membership(", "list_lab_device_candidates(",
            "WITH permit AS MATERIALIZED", "LEFT JOIN LATERAL",
            "valid_scope(role, pop)", "approved_by.trim().is_empty()",
            "row_pop.as_str()) != pop", "rows.len() > 100"
        ): self.assertIn(clause,BRIDGE)
        self.assertNotIn("SET ROLE",BRIDGE.split("pub(super) async fn pending_devices_for_session(")[1].split("#[cfg(test)]")[0])
        self.assertIn("SECURITY DEFINER",SQL)
    def test_candidate_view_has_zero_network_or_secret_fields(self):
        view=BRIDGE.split("pub(super) struct PendingDevice {")[1].split("}",1)[0]
        for forbidden in ("management_ipv4","secret","password","private_key","auth_token","firmware","credential"):
            self.assertNotIn(forbidden,view)
        self.assertIn("connectivity",view)
        self.assertIn("health",view)
    def test_real_ci_must_call_exact_test_with_signed_two_isp_postgres(self):
        self.assertIn("r89_actual_signed_opaque_session_reads_real_sealed_pop_candidate_rows",CI)
        self.assertIn("cargo test --locked -p control-api",CI)
        self.assertIn("ipat_lab_device_registrar",BRIDGE)
        self.assertIn("LAB-R89-OLT-A",BRIDGE)
        self.assertIn("LAB-R89-ONT-B",BRIDGE)
if __name__=="__main__": unittest.main()
