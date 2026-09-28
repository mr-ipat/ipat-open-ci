"""R7.0 independently approved identity membership schema LAB ONLY.
Run AFTER base RLS & job tests on one disposable PostgreSQL 16 CI service.
No DB runtime/HTTP OIDC account binding exists in this milestone.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA, TB, run, sql

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "deploy/db/migrations/0003_lab_identity_memberships.sql"
ISSUER = "https://id.synthetic.test.invalid/realms/ipat-lab"
SUBJECT = "synthetic-pilot-operator"
APP = "ipat_app_runtime"

class SyntheticIdentityMembershipIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST") != "1":
            raise unittest.SkipTest("Must explicitly opt into disposable PostgreSQL")
        assert os.getenv("PGHOST") == "127.0.0.1"
        assert os.getenv("PGDATABASE") == "ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD") == "local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.devices') IS NOT NULL").stdout.strip() == "t"
        assert sql("SELECT to_regclass('ipat_ops.provisioning_jobs') IS NOT NULL").stdout.strip() == "t"
        assert sql("SELECT to_regclass('ipat_platform.identity_memberships') IS NULL").stdout.strip() == "t"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIGRATION)])
        cls.m = "ipat_platform.identity_memberships"
        cls.p = "ipat_platform.identity_pop_grants"
        cls.o = "ipat_platform.platform_principals"
        sql(f"""INSERT INTO {cls.m}
            (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
            ('{TA}','{ISSUER}','{SUBJECT}','tenant_admin','lab-reviewer',
                clock_timestamp()+interval '1 day'),
            ('{TB}','{ISSUER}','{SUBJECT}','helpdesk','lab-reviewer',
                clock_timestamp()+interval '1 day')""")
        sql(f"""INSERT INTO {cls.p} (tenant_id,issuer,subject,role,pop_id)
            VALUES ('{TA}','{ISSUER}','{SUBJECT}','tenant_admin','pop-a'),
                   ('{TB}','{ISSUER}','{SUBJECT}','helpdesk','pop-b')""")
        sql(f"""INSERT INTO {cls.o}
            (issuer,subject,role,approved_by,expires_at)
            VALUES ('{ISSUER}','platform-only-synthetic',
            'platform_owner','lab-reviewer',clock_timestamp()+interval '1 day')""")

    def test_no_runtime_role_or_public_read_write_access(self):
        for name in (self.m,self.p,self.o):
            for statement in ("SELECT count(*)", "DELETE"):
                # Runtime has zero USAGE on the platform schema. Even if
                # a future developer accidentally adds schema USAGE, RLS
                # is FORCE and has NO runtime policy or grants here.
                query = f"{statement} FROM {name}"
                self.assertNotEqual(sql(query,user=APP,expect=False).returncode,0)
            self.assertNotEqual(sql(f"TRUNCATE {name}",user=APP,expect=False).returncode,0)

    def test_all_identity_tables_force_rls_and_runtime_role_is_unprivileged(self):
        q = """SELECT c.relname,c.relrowsecurity::int,c.relforcerowsecurity::int
               FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid
               WHERE n.nspname='ipat_platform' AND c.relname IN
               ('identity_memberships','identity_pop_grants','platform_principals')
               ORDER BY c.relname"""
        self.assertEqual(sql(q).stdout.strip().splitlines(),[
            "identity_memberships|1|1","identity_pop_grants|1|1",
            "platform_principals|1|1"])
        for relation in (self.m,self.p,self.o):
            grantee = sql(f"""SELECT has_table_privilege('{APP}','{relation}','SELECT')::int,
                has_table_privilege('{APP}','{relation}','INSERT')::int,
                has_table_privilege('{APP}','{relation}','UPDATE')::int,
                has_table_privilege('{APP}','{relation}','DELETE')::int""").stdout.strip()
            self.assertEqual(grantee,"0|0|0|0")

    def test_exact_tenant_subject_role_pop_composite_keys(self):
        q = f"""SELECT tenant_id||'/'||role FROM {self.m}
                WHERE issuer='{ISSUER}' AND subject='{SUBJECT}'
                ORDER BY tenant_id"""
        self.assertEqual(sql(q).stdout.strip().splitlines(),[
            f"{TA}/tenant_admin",f"{TB}/helpdesk"])
        self.assertNotEqual(sql(f"""INSERT INTO {self.p}
            (tenant_id,issuer,subject,role,pop_id) VALUES
            ('{TB}','{ISSUER}','{SUBJECT}','tenant_admin','pop-a')""",
            expect=False).returncode,0)
        self.assertNotEqual(sql(f"""INSERT INTO {self.m}
            (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
            ('{TA}','{ISSUER}','{SUBJECT}','platform_owner','lab-reviewer',
                clock_timestamp()+interval '1 day')""",
            expect=False).returncode,0)
        self.assertNotEqual(sql(f"""INSERT INTO {self.p}
            (tenant_id,issuer,subject,role,pop_id) VALUES
            ('{TA}','{ISSUER}','{SUBJECT}','tenant_admin','../pop-b')""",
            expect=False).returncode,0)

    def test_platform_principal_is_not_automatically_a_tenant_member(self):
        platform = sql(f"""SELECT count(*) FROM {self.o}
            WHERE issuer='{ISSUER}' AND subject='platform-only-synthetic'""").stdout.strip()
        tenant = sql(f"""SELECT count(*) FROM {self.m}
            WHERE issuer='{ISSUER}' AND subject='platform-only-synthetic'""").stdout.strip()
        self.assertEqual((platform,tenant),("1","0"))
        self.assertNotEqual(sql(f"""INSERT INTO {self.o}
            (issuer,subject,role,approved_by,expires_at) VALUES
            ('{ISSUER}','{SUBJECT}','tenant_admin','lab-reviewer',
                clock_timestamp()+interval '1 day')""",expect=False).returncode,0)

    def test_revocation_expiry_and_no_automatic_grant(self):
        sql(f"""UPDATE {self.m} SET revoked_at=clock_timestamp()
            WHERE tenant_id='{TB}' AND issuer='{ISSUER}'
                AND subject='{SUBJECT}' AND role='helpdesk'""")
        status = sql(f"""SELECT (revoked_at IS NOT NULL)::int FROM {self.m}
            WHERE tenant_id='{TB}' AND role='helpdesk'""").stdout.strip()
        self.assertEqual(status,"1")
        self.assertNotEqual(sql(f"""INSERT INTO {self.m}
            (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
            ('{TA}','{ISSUER}','expired-example','auditor','lab-reviewer',
                clock_timestamp()-interval '1 day')""",expect=False).returncode,0)
        # Created_at vs expiry is structural only. Application MUST check
        # actual current clock, revocation, MFA and approved membership.
        self.assertNotEqual(sql(f"""INSERT INTO {self.m}
            (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
            ('{TA}','{ISSUER}','future-never-approved','helpdesk','',
                clock_timestamp()+interval '1 day')""",expect=False).returncode,0)

if __name__ == "__main__":
    unittest.main()
