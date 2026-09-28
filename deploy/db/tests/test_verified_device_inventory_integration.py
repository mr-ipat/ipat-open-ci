"""R8.0 disposable PostgreSQL real RLS + role/POP inventory protection.
No live OLT, real customer DB, real IdP or trusted MFA is asserted.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA, TB, DA, DB, run, sql

ROOT=Path(__file__).resolve().parents[3]
MIG=ROOT/"deploy/db/migrations/0005_lab_verified_device_inventory.sql"
FN="ipat_platform.list_authorized_lab_devices"
SIG="(text,text,uuid,text,text)"
ISS="https://synthetic.r77.invalid/realms/demo"
SUB="signed-test-operator"
EXTRA="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

def allowed(tenant=TA, role="noc_engineer", pop="pop-a", issuer=ISS, subject=SUB):
    p="NULL" if pop is None else "'" + pop.replace("'","''") + "'"
    q=(f"SET ROLE ipat_identity_query; SELECT id::text FROM {FN}("
       f"'{issuer}','{subject}','{tenant}','{role}',{p})")
    proc=sql(q)
    return [x for x in proc.stdout.strip().splitlines() if x.startswith(
        ("aaaaaaaa","bbbbbbbb","eeeeeeee"))]

class VerifiedDeviceInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST")!="1":
            raise unittest.SkipTest("disposable PostgreSQL ONLY")
        assert os.getenv("PGHOST")=="127.0.0.1"
        assert os.getenv("PGDATABASE")=="ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
        assert sql("SELECT to_regprocedure('ipat_platform.list_authorized_lab_devices(text,text,uuid,text,text)') IS NULL").stdout.strip()=="t"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIG)])
        # Same synthetic signed subject has a SECOND legitimate tenant
        # NOC membership. Verify tenant boundaries even across valid grants.
        sql(f"""INSERT INTO ipat_platform.identity_memberships
          (tenant_id,issuer,subject,role,approved_by,expires_at)
          VALUES ('{TB}','{ISS}','{SUB}','noc_engineer','R80-REVIEWER-B',
             statement_timestamp()+interval '1 day')""")
        sql(f"""INSERT INTO ipat_platform.identity_pop_grants
          (tenant_id,issuer,subject,role,pop_id)
          VALUES ('{TB}','{ISS}','{SUB}','noc_engineer','pop-b')""")
        sql(f"""INSERT INTO ipat_ops.devices
          (tenant_id,id,pop_id,device_kind,vendor,exact_model,firmware) VALUES
          ('{TA}','{EXTRA}','other-pop','olt','SYNTHETIC-NOT-REAL',
           'VIRTUAL-OLT','SYNTHETIC-V0')""")

    def setUp(self):
        sql(f"""UPDATE ipat_platform.tenants SET state='active'
          WHERE id IN ('{TA}','{TB}')""")
        sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=NULL,expires_at=statement_timestamp()+interval '1 day'
          WHERE issuer='{ISS}' AND subject='{SUB}'""")

    def test_00_only_sealed_function_role_sees_inventory(self):
        self.assertEqual(sql(f"""SELECT
           has_function_privilege('ipat_identity_query','{FN}{SIG}','EXECUTE')::int,
           has_function_privilege('ipat_app_runtime','{FN}{SIG}','EXECUTE')::int""").stdout.strip(),
           "1|0")
        for relation in ["ipat_ops.devices","ipat_ops.subscribers"]:
            self.assertEqual(sql(f"""SELECT has_table_privilege(
              'ipat_identity_query','{relation}','SELECT')::int""").stdout.strip(),"0")
        self.assertEqual(sql("""SELECT has_table_privilege(
          'ipat_identity_lookup_owner','ipat_ops.subscribers','SELECT')::int"""
          ).stdout.strip(),"0")
        unauthorized=f"SELECT * FROM {FN}('{ISS}','{SUB}','{TA}','noc_engineer','pop-a')"
        self.assertNotEqual(sql("SET ROLE ipat_app_runtime; "+unauthorized,
                                expect=False).returncode,0)
        # ipat_app_runtime has legacy RLS table SELECT, but no trusted
        # transaction scope: its default result must contain zero rows.
        direct=sql("SET ROLE ipat_app_runtime; SELECT count(*) FROM ipat_ops.devices")
        self.assertEqual(direct.stdout.strip().splitlines()[-1],"0")

    def test_01_real_pg_positive_only_exact_pop_and_no_cross_tenant(self):
        self.assertEqual(allowed(),[DA])
        self.assertEqual(allowed(TB,"noc_engineer","pop-b"),[DB])
        self.assertEqual(allowed(TB,"helpdesk","pop-b"),[])
        for tenant,role,pop in (
            (TA,"noc_engineer","other-pop"),
            (TA,"noc_engineer","pop-b"),
            (TB,"noc_engineer","pop-a"),
            (TA,"tenant_admin",None),
            (TA,"platform_owner","pop-a")
        ):
            self.assertEqual(allowed(tenant,role,pop),[])
        self.assertEqual(allowed(issuer="https://attacker.invalid"),[])
        self.assertEqual(allowed(subject="someone-else"),[])

    def test_02_revoked_expired_and_suspended_all_rejected(self):
        sql(f"""UPDATE ipat_platform.identity_memberships SET
          revoked_at=statement_timestamp() WHERE tenant_id='{TA}'
          AND issuer='{ISS}' AND subject='{SUB}'""")
        self.assertEqual(allowed(),[])
        # Fixture must satisfy DB constraint expires_at > created_at,
        # while BOTH timestamps are safely in the past to test expiration.
        sql(f"""UPDATE ipat_platform.identity_memberships SET
          revoked_at=NULL,created_at=statement_timestamp()-interval '2 days',
          expires_at=statement_timestamp()-interval '1 day'
          WHERE tenant_id='{TA}' AND issuer='{ISS}' AND subject='{SUB}'""")
        self.assertEqual(allowed(),[])
        sql(f"""UPDATE ipat_platform.identity_memberships SET
          expires_at=statement_timestamp()+interval '1 day'
          WHERE tenant_id='{TA}' AND issuer='{ISS}' AND subject='{SUB}'""")
        sql(f"UPDATE ipat_platform.tenants SET state='suspended' WHERE id='{TA}'")
        self.assertEqual(allowed(),[])

    def test_03_unscoped_direct_reader_query_denied_even_if_exists(self):
        sql("SET ROLE ipat_identity_query; SELECT 1")
        self.assertNotEqual(sql("SET ROLE ipat_identity_query; SELECT * FROM ipat_ops.devices",
                                expect=False).returncode,0)
        self.assertEqual(sql(f"""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_identity_lookup_owner'""").stdout.strip(),"0|0")
        policies=sql("""SELECT polname FROM pg_policy WHERE polname =
            'identity_lab_device_inventory_select'""").stdout.strip()
        self.assertEqual(policies,"identity_lab_device_inventory_select")
        self.assertEqual(allowed(),[DA])

if __name__=="__main__":unittest.main()
