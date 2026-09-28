"""R7.7 ephemeral PostgreSQL: isolated, least-privilege active membership lookup.
No actual user, device, DNS ownership, login, MFA or production database.
Run ONLY after 0001/0002/0003 tests in the same disposable CI database.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA, TB, run, sql

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "deploy/db/migrations/0004_lab_scoped_identity_lookup.sql"
ISSUER = "https://synthetic.r77.invalid/realms/demo"
SUBJECT = "signed-test-operator"
FN = "ipat_platform.lookup_active_membership"
SIGNATURE = "(text,text,uuid,text,text)"

def role_query(role, query, expect=True):
    # SET ROLE only in disposable DB as ephemeral test postgres superuser.
    return sql(f"SET ROLE {role}; {query}", expect=expect)

def match(tenant=TA, issuer=ISSUER, subject=SUBJECT,
          role="noc_engineer", pop="pop-a", sql_role="ipat_identity_query"):
    pop_sql = "NULL" if pop is None else "'" + pop.replace("'", "''") + "'"
    query = (
        "SELECT COALESCE(("
        f"SELECT approved_by FROM {FN}("
        f"'{issuer}','{subject}','{tenant}',"
        f"'{role}',{pop_sql}) LIMIT 1),'DENIED');"
    )
    result = role_query(sql_role, query)
    return result.stdout.strip().splitlines()[-1]

class ScopedIdentityLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("IPAT_PG_EPHEMERAL_TEST") != "1":
            raise unittest.SkipTest("Explicit ephemeral PostgreSQL test only")
        assert os.environ.get("PGDATABASE") == "ipat_synthetic"
        assert os.environ.get("PGHOST") == "127.0.0.1"
        assert os.environ.get("IPAT_PG_SYNTHETIC_PASSWORD") == "local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_platform.identity_memberships') IS NOT NULL").stdout.strip() == "t"
        assert sql("SELECT to_regclass('ipat_platform.lookup_active_membership') IS NULL").stdout.strip() == "t"
        run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", str(MIGRATION)])
        sql(f"""INSERT INTO ipat_platform.identity_memberships
          (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
          ('{TA}','{ISSUER}','{SUBJECT}','noc_engineer','R77-REVIEWER-A',
            statement_timestamp() + interval '1 day'),
          ('{TB}','{ISSUER}','{SUBJECT}','helpdesk','R77-REVIEWER-B',
            statement_timestamp() + interval '1 day')""")
        sql(f"""INSERT INTO ipat_platform.identity_pop_grants
          (tenant_id,issuer,subject,role,pop_id) VALUES
          ('{TA}','{ISSUER}','{SUBJECT}','noc_engineer','pop-a'),
          ('{TB}','{ISSUER}','{SUBJECT}','helpdesk','pop-b')""")

    def setUp(self):
        # Isolate each negative test; this test DB is disposable, not a real DB.
        sql(f"""UPDATE ipat_platform.tenants SET state='active'
          WHERE id IN ('{TA}','{TB}')""")
        sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=NULL, expires_at=statement_timestamp()+interval '1 day'
          WHERE issuer='{ISSUER}' AND subject='{SUBJECT}'""")

    def test_00_only_non_login_role_can_execute_function_not_runtime_or_public(self):
        q = f"""SELECT has_function_privilege(
          'ipat_identity_query','{FN}{SIGNATURE}','EXECUTE')::int,
          has_function_privilege(
          'ipat_app_runtime','{FN}{SIGNATURE}','EXECUTE')::int,
          has_function_privilege(
          'ipat_identity_lookup_owner','{FN}{SIGNATURE}','EXECUTE')::int"""
        # Function owner inherently has EXECUTE, application runtime has none.
        self.assertEqual(sql(q).stdout.strip(), "1|0|1")
        direct = f"SELECT * FROM {FN}('{ISSUER}','{SUBJECT}','{TA}','noc_engineer','pop-a')"
        self.assertNotEqual(role_query("ipat_app_runtime", direct, expect=False).returncode, 0)
        roles = sql("""SELECT rolname,rolcanlogin::int,rolsuper::int,
            rolbypassrls::int,rolcreaterole::int FROM pg_roles WHERE rolname IN
            ('ipat_identity_query','ipat_identity_lookup_owner')
            ORDER BY rolname""").stdout.strip().splitlines()
        self.assertEqual(roles, [
            "ipat_identity_lookup_owner|0|0|0|0",
            "ipat_identity_query|0|0|0|0",
        ])

    def test_01_exact_authorized_tenant_role_pop_positive(self):
        self.assertEqual(match(), "R77-REVIEWER-A")
        self.assertEqual(match(tenant=TB, role="helpdesk", pop="pop-b"), "R77-REVIEWER-B")
        # Tenant admin must be requested without POP; nobody was approved.
        self.assertEqual(match(role="tenant_admin", pop=None), "DENIED")

    def test_02_cross_tenant_and_wrong_issuer_or_subject_deny(self):
        self.assertEqual(match(tenant=TB), "DENIED")
        self.assertEqual(match(tenant=TA, role="helpdesk", pop="pop-b"), "DENIED")
        self.assertEqual(match(issuer="https://other.synthetic.invalid/realms/demo"), "DENIED")
        self.assertEqual(match(subject="forged-test-operator"), "DENIED")
        self.assertEqual(match(tenant=TB, role="noc_engineer", pop="pop-a"), "DENIED")

    def test_03_unknown_role_missing_wrong_or_injected_pop_deny(self):
        for role, pop in [
            ("platform_owner","pop-a"), ("noc_engineer",None),
            ("noc_engineer","pop-b"), ("noc_engineer","../pop-a"),
            ("tenant_admin","pop-a"), ("auditor","pop-a")
        ]:
            self.assertEqual(match(role=role, pop=pop), "DENIED")
        # Role+POP grants are not inferred across identities or companies.
        self.assertEqual(match(tenant=TB, role="helpdesk", pop="pop-a"), "DENIED")

    def test_04_revocation_expiry_and_tenant_suspension_deny(self):
        sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=statement_timestamp() WHERE tenant_id='{TA}'
          AND issuer='{ISSUER}' AND subject='{SUBJECT}'""")
        self.assertEqual(match(), "DENIED")
        self.assertEqual(match(tenant=TB, role="helpdesk", pop="pop-b"), "R77-REVIEWER-B")
        # Deterministic already-expired membership must still satisfy the
        # real schema CHECK (expires_at > created_at), independent of runner
        # scheduling and sub-second test timing.
        sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=NULL,
              created_at=statement_timestamp() - interval '2 days',
              expires_at=statement_timestamp() - interval '1 day'
          WHERE tenant_id='{TA}' AND issuer='{ISSUER}' AND subject='{SUBJECT}'""")
        self.assertEqual(match(), "DENIED")
        sql(f"""UPDATE ipat_platform.identity_memberships
          SET expires_at=statement_timestamp() + interval '1 day'
          WHERE tenant_id='{TA}' AND issuer='{ISSUER}' AND subject='{SUBJECT}'""")
        sql(f"UPDATE ipat_platform.tenants SET state='suspended' WHERE id='{TA}'")
        self.assertEqual(match(), "DENIED")
        self.assertEqual(match(tenant=TB, role="helpdesk", pop="pop-b"), "R77-REVIEWER-B")

    def test_05_direct_select_update_and_extra_function_privileges_denied(self):
        for relation in [
            "ipat_platform.identity_memberships",
            "ipat_platform.identity_pop_grants",
            "ipat_platform.platform_principals",
        ]:
            q = f"SELECT has_table_privilege('ipat_identity_query','{relation}','SELECT')::int"
            self.assertEqual(sql(q).stdout.strip(), "0")
            self.assertNotEqual(role_query(
                "ipat_identity_query", f"SELECT * FROM {relation}",
                expect=False).returncode, 0)
        self.assertEqual(sql("""SELECT has_schema_privilege(
          'ipat_identity_lookup_owner','ipat_platform','CREATE')::int""").stdout.strip(), "0")
        self.assertEqual(sql("""SELECT has_schema_privilege(
          'ipat_identity_query','ipat_platform','CREATE')::int""").stdout.strip(), "0")
        self.assertEqual(sql("""SELECT has_table_privilege(
          'ipat_identity_lookup_owner',
          'ipat_platform.platform_principals','SELECT')::int""").stdout.strip(), "0")

    def test_06_function_owner_rls_and_locked_search_path(self):
        rows = sql("""SELECT p.proname,r.rolname,p.prosecdef::int,
          p.proconfig::text FROM pg_proc p
          JOIN pg_namespace n ON n.oid=p.pronamespace
          JOIN pg_roles r ON r.oid=p.proowner
          WHERE n.nspname='ipat_platform'
          AND p.proname='lookup_active_membership'""").stdout.strip()
        self.assertIn("ipat_identity_lookup_owner|1|", rows)
        self.assertIn("search_path=pg_catalog, ipat_platform", rows)
        policies = sql("""SELECT tablename,policyname FROM pg_policies
          WHERE schemaname='ipat_platform' AND policyname LIKE
          'identity_lookup_%' ORDER BY tablename""").stdout.strip().splitlines()
        self.assertEqual(policies, [
            "identity_memberships|identity_lookup_membership_select",
            "identity_pop_grants|identity_lookup_pop_select"
        ])
        self.assertEqual(match(), "R77-REVIEWER-A")

if __name__ == "__main__":
    unittest.main()
