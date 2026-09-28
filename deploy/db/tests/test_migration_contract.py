"""Static safety checks; real PostgreSQL behavior is tested in separate CI job."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (ROOT / "deploy/db/migrations/0001_lab_tenant_rls.sql").read_text()
CI = (ROOT / ".github/workflows/ci.yml").read_text()
INTEGRATION = (ROOT / "deploy/db/tests/test_postgres_rls_integration.py").read_text()

class MigrationContract(unittest.TestCase):
    def test_both_tenant_operational_tables_force_rls(self):
        for table in ("devices","subscribers"):
            self.assertIn(f"ALTER TABLE ipat_ops.{table} ENABLE ROW LEVEL SECURITY", MIGRATION)
            self.assertIn(f"ALTER TABLE ipat_ops.{table} FORCE ROW LEVEL SECURITY", MIGRATION)
            self.assertIn(f"ON ipat_ops.{table} FOR ALL TO ipat_app_runtime",MIGRATION)

    def test_scoped_composite_foreign_key(self):
        self.assertIn("FOREIGN KEY (tenant_id,device_id)",MIGRATION)
        self.assertIn("REFERENCES ipat_ops.devices(tenant_id,id)",MIGRATION)

    def test_no_runtime_schema_owner_or_bypass(self):
        self.assertIn("ipat_app_runtime LOGIN NOSUPERUSER",MIGRATION)
        self.assertIn("NOBYPASSRLS NOINHERIT",MIGRATION)
        self.assertIn("REVOKE ALL ON SCHEMA ipat_platform FROM PUBLIC",MIGRATION)
        self.assertNotIn("TRUNCATE ON",MIGRATION)
        self.assertNotIn("GRANT ALL",MIGRATION)

    def test_transaction_scoped_boundary_and_actual_restore_test(self):
        self.assertIn("current_setting('ipat.tenant_id',true)",MIGRATION)
        self.assertIn("SET LOCAL ipat.tenant_id",INTEGRATION)
        self.assertIn("pg_dump",INTEGRATION)
        self.assertIn("pg_restore",INTEGRATION)
        self.assertIn("createdb",INTEGRATION)
        self.assertIn("SYNTHETIC_POSTGRES_NEW_DATABASE_RESTORE_SHA256_MATCH",INTEGRATION)

    def test_ci_uses_ephemeral_isolated_only(self):
        self.assertIn("postgres-rls-restore:",CI)
        self.assertIn("postgres:16.9",CI)
        self.assertIn('IPAT_PG_EPHEMERAL_TEST: "1"',CI)
        self.assertIn('PGHOST: 127.0.0.1',CI)
        self.assertNotIn("hub.example.invalid",INTEGRATION)

if __name__=="__main__":unittest.main()
