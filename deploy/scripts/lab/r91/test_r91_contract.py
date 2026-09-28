"""R9.1 adoption-readiness source contract. No physical device network I/O."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
SQL=(ROOT/"deploy/db/migrations/0008_lab_device_adoption_readiness.sql").read_text()
BRIDGE=(ROOT/"apps/control-api/src/browser_session_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()

class R91ReadinessContract(unittest.TestCase):
    def test_four_explicit_gates_and_metadata_approval_do_not_probe(self):
        for gate in ("secure_management_path","device_identity",
                     "readonly_account","recovery_plan"):
            self.assertIn(gate,SQL)
        self.assertIn("read_probe_eligible",SQL)
        self.assertIn("adoption_state='approved'",SQL)
        self.assertIn("connectivity='unknown'",SQL)
        self.assertIn("health='not_measured'",SQL)
        self.assertIn("last_verified_at IS NULL",SQL)
        self.assertNotIn("firmware_upgrade",SQL)
        self.assertNotIn("SetParameterValues",SQL)
        self.assertNotIn("snmp",SQL.lower())

    def test_append_only_evidence_and_restricted_role_separation(self):
        for clause in (
            "ENABLE ROW LEVEL SECURITY","FORCE ROW LEVEL SECURITY",
            "CREATE ROLE ipat_device_readiness_owner NOLOGIN",
            "CREATE ROLE ipat_device_readiness_execute NOLOGIN",
            "GRANT SELECT,INSERT ON ipat_ops.device_adoption_attestations",
            "GRANT EXECUTE ON FUNCTION ipat_platform.attest_lab_device_adoption_gate",
            "TO ipat_device_readiness_execute",
            "GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_device_adoption_readiness",
            "TO ipat_identity_query",
        ):
            self.assertIn(clause,SQL)
        self.assertNotIn("GRANT UPDATE ON ipat_ops.device_adoption_attestations",SQL)
        self.assertNotIn("GRANT DELETE ON ipat_ops.device_adoption_attestations",SQL)
        self.assertIn("valid_until <= captured_at + interval '7 days'",SQL)

    def test_attester_must_be_original_independent_metadata_reviewer(self):
        for clause in (
            "r.reviewer_issuer=p_issuer",
            "r.reviewer_subject=p_subject",
            "m.role='security_admin'",
            "m.revoked_at IS NULL",
            "t.state='active'",
            "r.decision='approved'",
        ):
            self.assertIn(clause,SQL)

    def test_session_bridge_exposes_only_safe_boolean_readiness(self):
        self.assertIn("pub(super) async fn adoption_readiness_for_session(",BRIDGE)
        self.assertIn("vault.authenticate(",BRIDGE)
        self.assertIn("list_lab_device_adoption_readiness(",BRIDGE)
        section=BRIDGE.split("pub(super) struct AdoptionReadiness {",1)[1].split("}",1)[0]
        for forbidden in ("management_ipv4","evidence_sha256","note","subject",
                          "password","credential","private_key"):
            self.assertNotIn(forbidden,section)
        self.assertIn("read_probe_eligible",section)
        self.assertNotIn("browser_session_lab::adoption_readiness_for_session(",MAIN)

    def test_ci_runs_real_postgres_and_signed_session_readiness(self):
        self.assertIn("test_device_adoption_readiness_integration.py",CI)
        self.assertIn("r91_signed_session_reads_real_pg_adoption_gates_without_probe_execution",CI)
        self.assertIn("test_r91_contract.py",CI)

if __name__=="__main__":unittest.main()
