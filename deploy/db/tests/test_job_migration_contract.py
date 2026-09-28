"""Static fail-closed contracts for Mr. iPat's lab-only R5.4 database slice."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SQL = (ROOT/"deploy/db/migrations/0002_lab_job_outbox.sql").read_text()
TEST = (ROOT/"deploy/db/tests/test_job_outbox_integration.py").read_text()
CI = (ROOT/".github/workflows/ci.yml").read_text()

class SyntheticJobMigrationContract(unittest.TestCase):
    def test_rls_forced_on_both_tenant_pop_scoped_tables(self):
        for table in ("provisioning_jobs","job_outbox"):
            self.assertIn(f"ALTER TABLE ipat_ops.{table} ENABLE ROW LEVEL SECURITY",SQL)
            self.assertIn(f"ALTER TABLE ipat_ops.{table} FORCE ROW LEVEL SECURITY",SQL)
        self.assertEqual(SQL.count("current_setting('ipat.tenant_id',true)"),2)
        self.assertEqual(SQL.count("current_setting('ipat.pop_id',true)"),2)

    def test_runtime_is_read_only_and_cross_tenant_routers_forbidden(self):
        self.assertIn("GRANT SELECT ON ipat_ops.provisioning_jobs,ipat_ops.job_outbox",SQL)
        self.assertNotIn("GRANT INSERT",SQL)
        self.assertNotIn("GRANT UPDATE",SQL)
        self.assertNotIn("GRANT DELETE",SQL)
        self.assertIn("FOREIGN KEY (tenant_id,router_id,pop_id)",SQL)
        self.assertIn("REFERENCES ipat_ops.devices(tenant_id,id,pop_id)",SQL)

    def test_router_quarantine_and_idempotent_key_constraints(self):
        self.assertIn("UNIQUE (tenant_id,idempotency_key)",SQL)
        self.assertIn("one_unresolved_job_per_router_uuid",SQL)
        self.assertIn("WHERE state IN ('leased','unknown')",SQL)
        self.assertIn("NEW.lease_epoch <> OLD.lease_epoch + 1",SQL)
        self.assertIn("immutable synthetic job payload changed",SQL)

    def test_outbox_trigger_is_atomic_and_definition_is_narrow(self):
        self.assertIn("AFTER INSERT OR UPDATE OF state",SQL)
        self.assertIn("FOR EACH ROW EXECUTE FUNCTION ipat_ops.emit_synthetic_job_event()",SQL)
        self.assertIn("LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''",SQL)
        self.assertIn("REVOKE ALL ON FUNCTION ipat_ops.emit_synthetic_job_event() FROM PUBLIC",SQL)
        self.assertNotIn("EXECUTE format(",SQL)
        self.assertTrue(SQL.strip().endswith("COMMIT;"))

    def test_ephemeral_integration_and_recovery_are_ci_gated(self):
        for evidence in ("IPAT_PG_EPHEMERAL_TEST","pg_dump","pg_restore",
                         "SYNTHETIC_JOB_OUTBOX_NEW_DATABASE_RESTORE_SHA256_MATCH"):
            self.assertIn(evidence,TEST)
        self.assertIn("test_job_migration_contract.py",CI)
        self.assertIn("test_job_outbox_integration.py",CI)
        self.assertIn("postgres:16.9",CI)

if __name__ == "__main__":
    unittest.main()
