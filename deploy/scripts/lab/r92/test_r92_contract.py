"""R9.2 static no-device-execution contract; CI additionally runs real PG+Rust."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[4]
SQL=(ROOT/"deploy/db/migrations/0009_lab_read_probe_intent.sql").read_text()
RUST=(ROOT/"apps/control-api/src/browser_session_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()
SEED=(ROOT/"deploy/db/tests/seed_private_http_identity_ci.py").read_text()
class ReadIntentContract(unittest.TestCase):
    def test_immutable_nonexecutable_intent_and_private_audit(self):
        for x in ("device_read_probe_intents","device_read_probe_intent_audit",
                  "awaiting_separate_execution_review",
                  "must_revalidate_before_execution=true",
                  "nonexecutable_intent_recorded","published_at IS NULL",
                  "ENABLE ROW LEVEL SECURITY","FORCE ROW LEVEL SECURITY"):
            self.assertIn(x,SQL)
        for x in ("UPDATE ipat_ops.device_read_probe_intents",
                  "DELETE FROM ipat_ops.device_read_probe_intents",
                  "INSERT INTO ipat_ops.job_outbox",
                  "pg_notify","dblink","firmware_upgrade","TRIGGER","mqtt"):
            self.assertNotIn(x,SQL)
    def test_separate_exec_role_current_readiness_and_exact_noc_pop(self):
        for x in ("CREATE ROLE ipat_read_intent_owner NOLOGIN",
                  "CREATE ROLE ipat_read_intent_execute NOLOGIN",
                  "TO ipat_read_intent_execute",
                  "TO ipat_identity_query",
                  "list_lab_device_adoption_readiness(",
                  "'noc_engineer',p_pop","r.read_probe_eligible",
                  "r.secure_management_path","r.device_identity",
                  "r.readonly_account","r.recovery_plan"):
            self.assertIn(x,SQL)
        self.assertNotIn("GRANT UPDATE ON ipat_ops.device_read_probe_intents",SQL)
        self.assertNotIn("GRANT DELETE ON ipat_ops.device_read_probe_intents",SQL)
    def test_unmounted_signed_session_mutation_and_csrf(self):
        self.assertIn("pub(super) async fn submit_nonexecutable_read_intent_for_session(",RUST)
        self.assertIn("RequestKind::Mutation,",RUST)
        self.assertIn("trusted_host_origin,",RUST)
        self.assertIn("restricted_intent_writer",RUST)
        self.assertIn("request_lab_read_probe_intent(",RUST)
        self.assertNotIn("submit_nonexecutable_read_intent_for_session(",MAIN)
        self.assertIn("ipat_lab_read_intent_writer",SEED)
        self.assertIn("r91_signed_session_reads_real_pg_adoption_gates_without_probe_execution",RUST)
    def test_real_disposable_ci_is_a_required_gate(self):
        self.assertIn("test_r92_contract.py",CI)
        self.assertIn("test_read_probe_intent_integration.py",CI)
        self.assertIn("seed_private_http_identity_ci.py",CI)
if __name__=="__main__":unittest.main()
