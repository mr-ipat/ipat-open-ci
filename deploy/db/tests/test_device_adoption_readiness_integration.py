"""R9.1 genuine disposable PostgreSQL adoption-readiness gates.
Metadata approval and evidence attestations NEVER contact physical equipment.
Run after R8.3/R8.4 migrations in the same disposable CI database.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA,TB,run,sql

MIG=Path(__file__).resolve().parents[1]/"migrations/0008_lab_device_adoption_readiness.sql"
ISS="https://synthetic.r91.invalid/realm/lab"
MAKER="r91-maker"
CHECKER="r91-checker"
OTHER="r91-other-security"
NOC="r91-noc"
ZERO="00000000-0000-0000-0000-000000000000"
REG="ipat_platform.propose_lab_device_candidate"
REVIEW="ipat_platform.review_lab_device_candidate"
ATTEST="ipat_platform.attest_lab_device_adoption_gate"
READ="ipat_platform.list_lab_device_adoption_readiness"

def q(v):
    return "NULL" if v is None else "'"+v.replace("'","''")+"'"

def register(request,tenant=TA,pop="pop-a",name="LAB-R91-C320"):
    stmt=f"""SET ROLE ipat_device_registry_execute;
      SELECT coalesce({REG}({q(ISS)},{q(MAKER)},'{tenant}'::uuid,
      '{request}'::uuid,{q(pop)},{q(name)},'olt','ZTE','VIRTUAL-C320',
      '10.91.0.10'),'{ZERO}'::uuid)"""
    return sql(stmt).stdout.strip().splitlines()[-1]

def approve(candidate,tenant=TA,reviewer=CHECKER,request="91000000-0000-4000-8000-000000000010"):
    stmt=f"""SET ROLE ipat_device_review_execute;
      SELECT coalesce({REVIEW}({q(ISS)},{q(reviewer)},'{tenant}'::uuid,
      '{candidate}'::uuid,'{request}'::uuid,'approved',
      'Approved metadata only'),'{ZERO}'::uuid)"""
    return sql(stmt).stdout.strip().splitlines()[-1]

def attest(candidate,gate,request,verdict="verified",tenant=TA,subject=CHECKER,
           digest=None,note="Verified synthetic evidence",
           captured="statement_timestamp()",valid="statement_timestamp()+interval '1 day'"):
    digest=digest or ("a"*64)
    stmt=f"""SET ROLE ipat_device_readiness_execute;
      SELECT coalesce({ATTEST}({q(ISS)},{q(subject)},'{tenant}'::uuid,
      '{candidate}'::uuid,'{request}'::uuid,{q(gate)},{q(verdict)},
      {q(digest)},{q(note)},{captured},{valid}),'{ZERO}'::uuid)"""
    return sql(stmt).stdout.strip().splitlines()[-1]

def readiness(tenant=TA,subject=NOC,role="noc_engineer",pop="pop-a"):
    p="NULL" if pop is None else q(pop)
    rows=sql(f"""SET ROLE ipat_identity_query;
      SELECT id::text||'|'||metadata_approved::text||'|'||
       secure_management_path::text||'|'||device_identity::text||'|'||
       readonly_account::text||'|'||recovery_plan::text||'|'||
       read_probe_eligible::text
      FROM {READ}({q(ISS)},{q(subject)},'{tenant}'::uuid,{q(role)},{p})""").stdout.strip().splitlines()
    return [x for x in rows if x.count("|")==6]

class AdoptionReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST")!="1":
            raise unittest.SkipTest("disposable PostgreSQL only")
        assert os.getenv("PGHOST")=="127.0.0.1"
        assert os.getenv("PGDATABASE")=="ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.device_adoption_attestations') IS NULL").stdout.strip()=="t"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIG)])
        for tenant,pop in ((TA,"pop-a"),(TB,"pop-b")):
            sql(f"""INSERT INTO ipat_platform.identity_memberships
              (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
              ('{tenant}','{ISS}','{MAKER}','tenant_admin','R91-CI-MAKER',
                statement_timestamp()+interval '1 day'),
              ('{tenant}','{ISS}','{CHECKER}','security_admin','R91-CI-CHECKER',
                statement_timestamp()+interval '1 day'),
              ('{tenant}','{ISS}','{OTHER}','security_admin','R91-CI-OTHER',
                statement_timestamp()+interval '1 day'),
              ('{tenant}','{ISS}','{NOC}','noc_engineer','R91-CI-NOC',
                statement_timestamp()+interval '1 day')""")
            sql(f"""INSERT INTO ipat_platform.identity_pop_grants
              (tenant_id,issuer,subject,role,pop_id)
              VALUES('{tenant}','{ISS}','{NOC}','noc_engineer','{pop}')""")

    def test_00_role_separation_and_append_only_evidence(self):
        sig=f"{ATTEST}(text,text,uuid,uuid,uuid,text,text,text,text,timestamp with time zone,timestamp with time zone)"
        read=f"{READ}(text,text,uuid,text,text)"
        self.assertEqual(sql(f"""SELECT
          has_function_privilege('ipat_device_readiness_execute','{sig}','EXECUTE')::int,
          has_function_privilege('ipat_identity_query','{sig}','EXECUTE')::int,
          has_function_privilege('ipat_identity_query','{read}','EXECUTE')::int,
          has_function_privilege('ipat_device_review_execute','{sig}','EXECUTE')::int"""
        ).stdout.strip(),"1|0|1|0")
        for role in ("ipat_device_readiness_execute","ipat_identity_query",
                     "ipat_device_review_execute","ipat_device_registry_execute"):
            for privilege in ("SELECT","INSERT","UPDATE","DELETE","TRUNCATE"):
                self.assertEqual(sql(f"""SELECT has_table_privilege(
                 '{role}','ipat_ops.device_adoption_attestations','{privilege}')::int"""
                ).stdout.strip(),"0",(role,privilege))
        self.assertEqual(sql("""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_device_readiness_owner'""").stdout.strip(),"0|0")
        self.assertEqual(sql("""SELECT
          has_table_privilege('ipat_device_readiness_owner',
           'ipat_ops.device_adoption_attestations','UPDATE')::int,
          has_table_privilege('ipat_device_readiness_owner',
           'ipat_ops.device_adoption_attestations','DELETE')::int""").stdout.strip(),"0|0")

    def test_01_approved_metadata_never_equals_probe_eligible(self):
        item=register("91000000-0000-4000-8000-000000000001")
        self.assertNotEqual(item,ZERO)
        self.assertNotEqual(approve(item),ZERO)
        row=next(x for x in readiness() if x.startswith(item+"|"))
        self.assertEqual(row,item+"|true|false|false|false|false|false")
        requests=[
          ("secure_management_path","91000000-0000-4000-8000-000000000101"),
          ("device_identity","91000000-0000-4000-8000-000000000102"),
          ("readonly_account","91000000-0000-4000-8000-000000000103"),
          ("recovery_plan","91000000-0000-4000-8000-000000000104"),
        ]
        created=[]
        for gate,request in requests:
            created.append(attest(item,gate,request))
            self.assertNotEqual(created[-1],ZERO)
        row=next(x for x in readiness() if x.startswith(item+"|"))
        self.assertEqual(row,item+"|true|true|true|true|true|true")
        stamps=sql(f"""SELECT captured_at::text||'|'||valid_until::text
          FROM ipat_ops.device_adoption_attestations
          WHERE attestation_id='{created[0]}'::uuid""").stdout.strip().split("|")
        self.assertEqual(len(stamps),2)
        self.assertEqual(
          attest(item,*requests[0],
                 captured=q(stamps[0])+"::timestamptz",
                 valid=q(stamps[1])+"::timestamptz"),
          created[0],"precise retry idempotent with identical immutable timestamps")
        self.assertEqual(sql(f"""SELECT connectivity||'|'||health||'|'||
          coalesce(last_verified_at::text,'NONE')
          FROM ipat_ops.device_candidates WHERE tenant_id='{TA}' AND id='{item}'""").stdout.strip(),
          "unknown|not_measured|NONE")

    def test_02_latest_block_or_expired_evidence_fails_closed(self):
        item=register("91000000-0000-4000-8000-000000000002",name="LAB-R91-BLOCK")
        self.assertNotEqual(approve(item,request="91000000-0000-4000-8000-000000000020"),ZERO)
        gates=("secure_management_path","device_identity","readonly_account","recovery_plan")
        for n,gate in enumerate(gates,201):
            self.assertNotEqual(attest(item,gate,f"91000000-0000-4000-8000-000000000{n}"),ZERO)
        self.assertTrue(next(x for x in readiness() if x.startswith(item+"|")).endswith("|true"))
        blocked=attest(item,"device_identity","91000000-0000-4000-8000-000000000299",
                       verdict="blocked",digest="b"*64,note="Identity evidence revoked")
        self.assertNotEqual(blocked,ZERO)
        row=next(x for x in readiness() if x.startswith(item+"|"))
        self.assertEqual(row.split("|")[-1],"false")
        expired=attest(item,"device_identity","91000000-0000-4000-8000-000000000298",
            digest="c"*64,note="Expired synthetic identity",
            captured="statement_timestamp()-interval '2 days'",
            valid="statement_timestamp()-interval '1 day'")
        self.assertNotEqual(expired,ZERO)
        self.assertEqual(next(x for x in readiness() if x.startswith(item+"|")).split("|")[-1],"false")

    def test_03_wrong_reviewer_cross_tenant_and_unapproved_candidate_denied(self):
        item=register("91000000-0000-4000-8000-000000000003")
        self.assertNotEqual(approve(item,request="91000000-0000-4000-8000-000000000030"),ZERO)
        self.assertEqual(attest(item,"recovery_plan","91000000-0000-4000-8000-000000000031",
                                subject=OTHER),ZERO)
        self.assertEqual(attest(item,"recovery_plan","91000000-0000-4000-8000-000000000032",
                                tenant=TB),ZERO)
        pending=register("91000000-0000-4000-8000-000000000033",name="LAB-R91-PENDING")
        self.assertEqual(attest(pending,"recovery_plan","91000000-0000-4000-8000-000000000034"),ZERO)
        self.assertEqual(attest(item,"firmware_write","91000000-0000-4000-8000-000000000035"),ZERO)
        self.assertEqual(attest(item,"recovery_plan","91000000-0000-4000-8000-000000000036",
                                digest="x"*64),ZERO)

    def test_04_scope_and_revocation_rechecked_at_read_time(self):
        item=register("91000000-0000-4000-8000-000000000004",name="LAB-R91-SCOPE")
        self.assertNotEqual(approve(item,request="91000000-0000-4000-8000-000000000040"),ZERO)
        self.assertTrue(any(x.startswith(item+"|") for x in readiness()))
        self.assertFalse(any(x.startswith(item+"|") for x in readiness(TB,pop="pop-b")))
        self.assertFalse(readiness(pop="pop-b"))
        self.assertTrue(any(x.startswith(item+"|") for x in readiness(subject=MAKER,role="tenant_admin",pop=None)))
        self.addCleanup(lambda:sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=NULL,expires_at=statement_timestamp()+interval '1 day'
          WHERE tenant_id='{TA}' AND issuer='{ISS}' AND subject='{NOC}'
          AND role='noc_engineer'"""))
        sql(f"""UPDATE ipat_platform.identity_memberships SET revoked_at=statement_timestamp()
          WHERE tenant_id='{TA}' AND issuer='{ISS}' AND subject='{NOC}'
          AND role='noc_engineer'""")
        self.assertFalse(readiness())

if __name__=="__main__":unittest.main()
