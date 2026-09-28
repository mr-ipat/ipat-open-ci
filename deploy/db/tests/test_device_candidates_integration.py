"""Real disposable PostgreSQL security and pending adoption acceptance.
Runs after migrations 0001-0005, only ephemeral ipat_synthetic CI.
NEVER runs against owner PostgreSQL or physical ONT/OLT.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA,TB,run,sql

ROOT=Path(__file__).resolve().parents[3]
MIG=ROOT/"deploy/db/migrations/0006_lab_device_candidates.sql"
ISS="https://synthetic.r83.invalid/realms/demo"
SUB="r83-test-operator"
NOUSER="r83-noc-only"
REG="ipat_platform.propose_lab_device_candidate"
READ="ipat_platform.list_lab_device_candidates"
REQ_A="c0000000-0000-4000-8000-000000000001"
REQ_B="c0000000-0000-4000-8000-000000000002"
REQ_C="c0000000-0000-4000-8000-000000000003"

def register(tenant=TA,subject=SUB,request=REQ_A,pop="pop-a",
             name="LAB-PENDING-C320",ip="10.21.33.44",kind="olt",vendor="ZTE"):
    def q(s):return "NULL" if s is None else "'"+s.replace("'","''")+"'"
    raw=(f"SET ROLE ipat_device_registry_execute; "
         f"SELECT coalesce({REG}("
         f"{q(ISS)},{q(subject)},'{tenant}'::uuid,'{request}'::uuid,"
         f"{q(pop)},{q(name)},{q(kind)},{q(vendor)},"
         f"'VIRTUAL-C320',{q(ip)}),'00000000-0000-0000-0000-000000000000'::uuid)")
    output=sql(raw)
    return output.stdout.strip().splitlines()[-1]

def read(tenant=TA,subject=SUB,role="tenant_admin",pop=None):
    p="NULL" if pop is None else "'"+pop+"'"
    cmd=(f"SET ROLE ipat_identity_query; "
         f"SELECT id::text||'|'||pop_id||'|'||adoption_state||'|'||"
         f"connectivity||'|'||health||'|'||coalesce(management_ipv4,'') "
         f"FROM {READ}('{ISS}','{subject}','{tenant}'::uuid,'{role}',{p})")
    return [r for r in sql(cmd).stdout.strip().splitlines()
            if r.count("|")==5]

class CandidateRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST")!="1":
            raise unittest.SkipTest("disposable PostgreSQL only")
        assert os.getenv("PGHOST")=="127.0.0.1"
        assert os.getenv("PGDATABASE")=="ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.device_candidates') IS NULL").stdout.strip()=="t"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIG)])
        sql(f"""INSERT INTO ipat_platform.identity_memberships
         (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
         ('{TA}','{ISS}','{SUB}','tenant_admin','R83-CHECKER-A',
            statement_timestamp()+interval '1 day'),
         ('{TB}','{ISS}','{SUB}','tenant_admin','R83-CHECKER-B',
            statement_timestamp()+interval '1 day'),
         ('{TA}','{ISS}','{SUB}','noc_engineer','R83-NOC-A',
            statement_timestamp()+interval '1 day'),
         ('{TB}','{ISS}','{SUB}','noc_engineer','R83-NOC-B',
            statement_timestamp()+interval '1 day'),
         ('{TA}','{ISS}','{NOUSER}','noc_engineer','R83-NOC-ONLY',
            statement_timestamp()+interval '1 day')""")
        sql(f"""INSERT INTO ipat_platform.identity_pop_grants
          (tenant_id,issuer,subject,role,pop_id) VALUES
          ('{TA}','{ISS}','{SUB}','noc_engineer','pop-a'),
          ('{TB}','{ISS}','{SUB}','noc_engineer','pop-b'),
          ('{TA}','{ISS}','{NOUSER}','noc_engineer','pop-a')""")

    def setUp(self):
        sql(f"UPDATE ipat_platform.tenants SET state='active' WHERE id IN ('{TA}','{TB}')")
        sql(f"""UPDATE ipat_platform.identity_memberships SET revoked_at=NULL,
          expires_at=statement_timestamp()+interval '1 day'
          WHERE issuer='{ISS}'""")

    def test_00_real_roles_cannot_bypass_function_or_direct_table(self):
        w="(text,text,uuid,uuid,text,text,text,text,text,text)"
        r="(text,text,uuid,text,text)"
        self.assertEqual(sql(f"""SELECT
            has_function_privilege('ipat_device_registry_execute','{REG}{w}','EXECUTE')::int,
            has_function_privilege('ipat_identity_query','{REG}{w}','EXECUTE')::int,
            has_function_privilege('ipat_app_runtime','{REG}{w}','EXECUTE')::int,
            has_function_privilege('ipat_identity_query','{READ}{r}','EXECUTE')::int"""
        ).stdout.strip(),"1|0|0|1")
        for role in ["ipat_device_registry_execute","ipat_identity_query","ipat_app_runtime"]:
            self.assertEqual(sql(f"""SELECT has_table_privilege(
               '{role}','ipat_ops.device_candidates','SELECT')::int""").stdout.strip(),"0")
            self.assertEqual(sql(f"""SELECT has_table_privilege(
               '{role}','ipat_ops.device_candidates','INSERT')::int""").stdout.strip(),"0")
        self.assertEqual(sql("""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_device_registry_owner'""").stdout.strip(),"0|0")
        for role in ["ipat_identity_query","ipat_app_runtime"]:
            self.assertNotEqual(sql(f"SET ROLE {role}; SELECT * FROM ipat_ops.device_candidates",
                                    expect=False).returncode,0)

    def test_01_actual_pending_registry_and_distinct_tenants(self):
        a=register()
        b=register(tenant=TB,request=REQ_B,pop="pop-b",name="LAB-ONT-B",ip="172.20.1.3",
                   kind="ont",vendor="VSOL")
        self.assertNotEqual(a,"00000000-0000-0000-0000-000000000000")
        self.assertNotEqual(b,"00000000-0000-0000-0000-000000000000")
        self.assertNotEqual(a,b)
        a_rows=read()
        b_rows=read(TB)
        self.assertTrue(any(x.startswith(a+"|pop-a|pending_review|unknown|not_measured|10.21.33.44")
                            for x in a_rows),a_rows)
        self.assertTrue(any(x.startswith(b+"|pop-b|pending_review|unknown|not_measured|172.20.1.3")
                            for x in b_rows),b_rows)
        self.assertFalse(any(b in x for x in a_rows))
        self.assertFalse(any(a in x for x in b_rows))
        self.assertFalse(read(TB,role="noc_engineer",pop="pop-a"))
        self.assertTrue(any(a in x for x in read(role="noc_engineer",pop="pop-a")))
        self.assertTrue(any(b in x for x in read(TB,role="noc_engineer",pop="pop-b")))

    def test_02_proposer_requires_active_exact_admin_not_noc_header(self):
        zero="00000000-0000-0000-0000-000000000000"
        self.assertEqual(register(subject=NOUSER,request=REQ_C),zero)
        self.assertFalse(read(subject="forged-subject"))
        self.assertFalse(read(TB,role="noc_engineer",pop="pop-a"))
        self.assertFalse(read(role="platform_owner"))
        self.assertFalse(read(role="noc_engineer"))
        self.assertFalse(read(role="noc_engineer",pop="pop-b"))

    def test_03_idempotency_retries_mismatch_and_no_public_ip(self):
        first=register()
        self.assertEqual(register(),first)
        zero="00000000-0000-0000-0000-000000000000"
        self.assertEqual(register(name="CHANGED-NAME"),zero)
        self.assertEqual(register(request=REQ_C,ip="8.8.8.8"),zero)
        self.assertEqual(register(request=REQ_C,ip="169.254.2.1"),zero)
        self.assertEqual(register(request=REQ_C,ip="127.0.0.1"),zero)
        self.assertEqual(sql(f"""SELECT count(*) FROM ipat_ops.device_candidates
         WHERE tenant_id='{TA}' AND requested_issuer='{ISS}'
           AND requested_subject='{SUB}' AND request_id='{REQ_A}'"""
         ).stdout.strip(),"1")

    def test_04_revocation_and_tenant_suspension_deny_new_writes(self):
        # A disposable PostgreSQL CI job runs later signed-token tests against
        # the SAME fixture. Always restore shared tenant and membership state.
        self.addCleanup(lambda: sql(f"""UPDATE ipat_platform.tenants
          SET state='active' WHERE id='{TA}'"""))
        self.addCleanup(lambda: sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=NULL WHERE tenant_id='{TA}' AND issuer='{ISS}'
          AND subject='{SUB}' AND role='tenant_admin'"""))
        zero="00000000-0000-0000-0000-000000000000"
        sql(f"""UPDATE ipat_platform.identity_memberships SET
            revoked_at=statement_timestamp() WHERE tenant_id='{TA}'
            AND issuer='{ISS}' AND subject='{SUB}' AND role='tenant_admin'""")
        self.assertEqual(register(request=REQ_C),zero)
        self.assertFalse(read())
        sql(f"""UPDATE ipat_platform.identity_memberships SET
          revoked_at=NULL WHERE tenant_id='{TA}'
          AND issuer='{ISS}' AND subject='{SUB}' AND role='tenant_admin'""")
        sql(f"UPDATE ipat_platform.tenants SET state='suspended' WHERE id='{TA}'")
        self.assertEqual(register(request=REQ_C),zero)
        self.assertFalse(read())

if __name__=="__main__":unittest.main()
