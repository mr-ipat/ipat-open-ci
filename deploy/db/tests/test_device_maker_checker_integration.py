"""R8.4 real disposable PostgreSQL maker/checker, immutable audit and RLS.
NO owner DB or live device access. Run after R8.3 migration/tests.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA,TB,run,sql

MIG=Path(__file__).resolve().parents[1]/"migrations/0007_lab_device_maker_checker.sql"
ISS="https://synthetic.r84.invalid/realm/lab"
MAKER="r84-maker"
CHECKER="r84-checker"
OTHER="r84-noc"
REQ="e4000000-0000-4000-8000-000000000001"
CANDIDATE="ipat_platform.propose_lab_device_candidate"
REVIEW="ipat_platform.review_lab_device_candidate"
QUEUE="ipat_platform.list_lab_device_review_queue"
ZERO="00000000-0000-0000-0000-000000000000"

def q(v):
    return "NULL" if v is None else "'"+v.replace("'","''")+"'"

def register(tenant=TA,subject=MAKER,request=REQ,pop="pop-a"):
    stmt=(f"SET ROLE ipat_device_registry_execute; SELECT coalesce({CANDIDATE}("
          f"{q(ISS)},{q(subject)},'{tenant}'::uuid,'{request}'::uuid,"
          f"{q(pop)},'LAB-R84-CANDIDATE','olt','ZTE','VIRTUAL-C320',"
          f"'10.24.8.9'),'{ZERO}'::uuid)")
    return sql(stmt).stdout.strip().splitlines()[-1]

def decide(candidate,tenant=TA,reviewer=CHECKER,decision="approved",
           reason="Reviewed metadata only",request="e4000000-0000-4000-8000-000000000008"):
    return sql(
       f"SET ROLE ipat_device_review_execute; SELECT coalesce({REVIEW}("
       f"{q(ISS)},{q(reviewer)},'{tenant}'::uuid,'{candidate}'::uuid,"
       f"'{request}'::uuid,{q(decision)},{q(reason)}),'{ZERO}'::uuid)"
    ).stdout.strip().splitlines()[-1]

def queue(tenant=TA,reviewer=CHECKER):
    rows=sql(f"SET ROLE ipat_device_review_execute; SELECT id::text||'|'||pop_id "
               f"FROM {QUEUE}({q(ISS)},{q(reviewer)},'{tenant}'::uuid)").stdout.strip().splitlines()
    # psql emits a harmless SET command-completion line even for zero rows.
    return "\n".join(row for row in rows if row.count('|')==1)

def state(tenant,candidate):
    return sql(f"""SELECT adoption_state||'|'||connectivity||'|'||health
       ||'|'||coalesce(last_verified_at::text,'NONE')
       FROM ipat_ops.device_candidates WHERE tenant_id='{tenant}' AND id='{candidate}'""").stdout.strip()

class MakerChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST")!="1":
            raise unittest.SkipTest("disposable PostgreSQL only")
        assert os.getenv("PGHOST")=="127.0.0.1"
        assert os.getenv("PGDATABASE")=="ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.device_candidate_reviews') IS NULL").stdout.strip()=="t"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIG)])
        for tenant in (TA,TB):
            sql(f"""INSERT INTO ipat_platform.identity_memberships
              (tenant_id,issuer,subject,role,approved_by,expires_at) VALUES
              ('{tenant}','{ISS}','{MAKER}','tenant_admin','CI-APPROVAL',
                statement_timestamp()+interval '1 day'),
              ('{tenant}','{ISS}','{MAKER}','security_admin','CI-SELF-ROLE',
                statement_timestamp()+interval '1 day'),
              ('{tenant}','{ISS}','{CHECKER}','security_admin','CI-SEPARATE-ROLE',
                statement_timestamp()+interval '1 day')""")
    def test_00_distinct_no_login_review_role_and_append_only_audit(self):
        review=f"{REVIEW}(text,text,uuid,uuid,uuid,text,text)"
        read=f"{QUEUE}(text,text,uuid)"
        lookup="ipat_platform.lookup_lab_device_reviewer(text,text,uuid)"
        self.assertEqual(sql(f"""SELECT
          has_function_privilege('ipat_device_review_execute','{review}','EXECUTE')::int,
          has_function_privilege('ipat_identity_query','{review}','EXECUTE')::int,
          has_function_privilege('ipat_device_registry_execute','{review}','EXECUTE')::int,
          has_function_privilege('ipat_app_runtime','{review}','EXECUTE')::int,
          has_function_privilege('ipat_device_review_execute','{read}','EXECUTE')::int,
          has_function_privilege('ipat_device_review_execute','{lookup}','EXECUTE')::int"""
        ).stdout.strip(),"1|0|0|0|1|1")
        for role in ["ipat_device_review_execute","ipat_identity_query",
                     "ipat_device_registry_execute","ipat_app_runtime"]:
            for table in ["ipat_ops.device_candidate_reviews","ipat_ops.device_candidates"]:
                for priv in ["SELECT","INSERT","UPDATE","DELETE"]:
                    self.assertEqual(sql(f"SELECT has_table_privilege('{role}','{table}','{priv}')::int").stdout.strip(),"0",(role,table,priv))
        self.assertEqual(sql("""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_device_review_owner'""").stdout.strip(),"0|0")
        self.assertEqual(sql("""SELECT has_table_privilege(
           'ipat_device_review_owner','ipat_ops.device_candidate_reviews','UPDATE')::int,
           has_table_privilege('ipat_device_review_owner',
             'ipat_ops.device_candidate_reviews','DELETE')::int""").stdout.strip(),"0|0")
    def test_01_other_human_can_review_own_tenant_only_and_audit_is_immutable(self):
        a=register()
        b=register(tenant=TB,request="e4000000-0000-4000-8000-000000000002",pop="pop-b")
        self.assertNotEqual(a,ZERO)
        self.assertNotEqual(b,ZERO)
        self.assertIn(a,queue())
        self.assertNotIn(b,queue())
        self.assertIn(b,queue(TB))
        self.assertNotIn(a,queue(TB))
        self.assertNotIn(a,queue(reviewer=MAKER))
        self.assertEqual(decide(a,reviewer=MAKER),ZERO,"cannot self review, even with additional security_admin role")
        self.assertEqual(decide(a,tenant=TB),ZERO,"cannot cross tenant")
        self.assertEqual(decide(a,reviewer=OTHER),ZERO)
        audit=decide(a)
        self.assertNotEqual(audit,ZERO)
        self.assertEqual(state(TA,a),"approved|unknown|not_measured|NONE")
        self.assertEqual(decide(a),audit,"same precise retry idempotent")
        self.assertEqual(decide(a,decision="rejected"),ZERO,"cannot overwrite prior decision")
        self.assertEqual(decide(a,reason="Changed rationale text"),ZERO)
        self.assertNotIn(a,queue())
        self.assertEqual(sql(f"""SELECT count(*) FROM ipat_ops.device_candidate_reviews
          WHERE tenant_id='{TA}' AND candidate_id='{a}'""").stdout.strip(),"1")
    def test_02_rejected_metadata_is_never_physical_status(self):
        item=register(request="e4000000-0000-4000-8000-000000000003")
        self.assertNotEqual(item,ZERO)
        audit=decide(item,decision="rejected",
          reason="Unverified exact firmware",
          request="e4000000-0000-4000-8000-000000000004")
        self.assertNotEqual(audit,ZERO)
        self.assertEqual(state(TA,item),"rejected|unknown|not_measured|NONE")
        self.assertNotIn(item,queue())
        self.assertEqual(decide(item,decision="approved"),ZERO)
    def test_03_invalid_reviewer_reason_or_revoked_grant_denied(self):
        item=register(request="e4000000-0000-4000-8000-000000000005")
        self.assertEqual(decide(item,reason="secret=hello; outside"),ZERO)
        self.assertEqual(decide(item,reason="short"),ZERO)
        self.assertEqual(decide(item,decision="quarantined"),ZERO)
        self.addCleanup(lambda:sql(f"""UPDATE ipat_platform.identity_memberships
          SET revoked_at=NULL,expires_at=statement_timestamp()+interval '1 day'
          WHERE tenant_id='{TA}' AND issuer='{ISS}' AND subject='{CHECKER}'
          AND role='security_admin'"""))
        sql(f"""UPDATE ipat_platform.identity_memberships SET revoked_at=statement_timestamp()
           WHERE tenant_id='{TA}' AND issuer='{ISS}' AND subject='{CHECKER}'
             AND role='security_admin'""")
        self.assertEqual(decide(item),ZERO)
        self.assertFalse(queue())
        self.assertEqual(state(TA,item),"pending_review|unknown|not_measured|NONE")
    def test_04_suspend_tenant_and_cross_role_denials(self):
        item=register(request="e4000000-0000-4000-8000-000000000006")
        self.addCleanup(lambda:sql(f"UPDATE ipat_platform.tenants SET state='active' WHERE id='{TA}'"))
        sql(f"UPDATE ipat_platform.tenants SET state='suspended' WHERE id='{TA}'")
        self.assertEqual(decide(item),ZERO)
        self.assertFalse(queue())
        self.assertEqual(state(TA,item),"pending_review|unknown|not_measured|NONE")

if __name__=="__main__":unittest.main()
