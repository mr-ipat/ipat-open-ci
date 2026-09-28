"""R9.2 disposable-only genuine PostgreSQL durable NONEXECUTABLE intent.
No real device, no actual credentials, no outbound network or worker.
Runs after 0001-0008 in the SAME ephemeral PostgreSQL CI job.
"""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA,TB,run,sql

ROOT=Path(__file__).resolve().parents[1]
MIG=ROOT/"migrations/0009_lab_read_probe_intent.sql"
ISS="https://synthetic.r92.invalid/realm/lab"
MAKER="r92-maker"
CHECKER="r92-reviewer"
NOC="r92-noc"
ZERO="00000000-0000-0000-0000-000000000000"
FN="ipat_platform.request_lab_read_probe_intent"
READ="ipat_platform.list_lab_read_probe_intents"
def q(x):
    return "'"+x.replace("'","''")+"'"
def statement(sql_text,role):
    return sql(f"SET ROLE {role};{sql_text}").stdout.strip().splitlines()[-1]
def candidate(tenant,request,pop):
    return statement(f"""SELECT coalesce(ipat_platform.propose_lab_device_candidate(
     {q(ISS)},{q(MAKER)},'{tenant}'::uuid,'{request}'::uuid,
     {q(pop)},'LAB-R92-DEVICE','olt','ZTE','VIRTUAL-C320',NULL
    ),'{ZERO}'::uuid)""","ipat_device_registry_execute")
def approve(tenant,item,request):
    return statement(f"""SELECT coalesce(ipat_platform.review_lab_device_candidate(
     {q(ISS)},{q(CHECKER)},'{tenant}'::uuid,'{item}'::uuid,
     '{request}'::uuid,'approved','Metadata only reviewed'
    ),'{ZERO}'::uuid)""","ipat_device_review_execute")
def attest(tenant,item,gate,request,verdict="verified"):
    return statement(f"""SELECT coalesce(ipat_platform.attest_lab_device_adoption_gate(
     {q(ISS)},{q(CHECKER)},'{tenant}'::uuid,'{item}'::uuid,
     '{request}'::uuid,{q(gate)},{q(verdict)},{q('a'*64)},
     'Synthetic scoped evidence',
     statement_timestamp(),statement_timestamp()+interval '1 day'
    ),'{ZERO}'::uuid)""","ipat_device_readiness_execute")
def intent(tenant,item,req,pop,subject=NOC,issuer=ISS):
    return statement(f"""SELECT coalesce({FN}(
       {q(issuer)},{q(subject)},'{tenant}'::uuid,'{item}'::uuid,
       '{req}'::uuid,{q(pop)}
     ),'{ZERO}'::uuid)""","ipat_read_intent_execute")
def list_intents(tenant,pop,subject=NOC):
    return sql(f"""SET ROLE ipat_identity_query;
      SELECT intent_id::text||'|'||candidate_id::text||'|'||pop_id||'|'||
       state||'|'||must_revalidate_before_execution::text
      FROM {READ}({q(ISS)},{q(subject)},'{tenant}'::uuid,{q(pop)})""").stdout
class DurableReadOnlyIntent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST")!="1":
            raise unittest.SkipTest("disposable PostgreSQL only")
        assert os.getenv("PGHOST")=="127.0.0.1"
        assert os.getenv("PGDATABASE")=="ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.device_adoption_attestations') IS NOT NULL").stdout.strip()=="t"
        assert sql("SELECT to_regclass('ipat_ops.device_read_probe_intents') IS NULL").stdout.strip()=="t"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIG)])
        for tenant,pop in ((TA,"pop-a"),(TB,"pop-b")):
            sql(f"""INSERT INTO ipat_platform.identity_memberships
              (tenant_id,issuer,subject,role,approved_by,expires_at)
              VALUES('{tenant}',{q(ISS)},{q(MAKER)},'tenant_admin',
                'CI-maker',statement_timestamp()+interval '1 day'),
              ('{tenant}',{q(ISS)},{q(CHECKER)},'security_admin',
                'CI-checker',statement_timestamp()+interval '1 day'),
              ('{tenant}',{q(ISS)},{q(NOC)},'noc_engineer',
                'CI-noc',statement_timestamp()+interval '1 day')""")
            sql(f"""INSERT INTO ipat_platform.identity_pop_grants
              (tenant_id,issuer,subject,role,pop_id)
              VALUES('{tenant}',{q(ISS)},{q(NOC)},'noc_engineer',{q(pop)})""")
    def test_00_only_dedicated_execution_role_and_no_worker_grants(self):
        signature=f"{FN}(text,text,uuid,uuid,uuid,text)"
        self.assertEqual(sql(f"""SELECT
          has_function_privilege('ipat_read_intent_execute','{signature}','EXECUTE')::int,
          has_function_privilege('ipat_identity_query','{signature}','EXECUTE')::int,
          has_function_privilege('ipat_device_readiness_execute','{signature}','EXECUTE')::int,
          has_function_privilege('ipat_app_runtime','{signature}','EXECUTE')::int
          """).stdout.strip(),"1|0|0|0")
        for role in ("ipat_identity_query","ipat_app_runtime",
                     "ipat_read_intent_execute","ipat_device_readiness_execute"):
            for table in ("ipat_ops.device_read_probe_intents",
                          "ipat_ops.device_read_probe_intent_audit"):
                for perm in ("SELECT","INSERT","UPDATE","DELETE"):
                    self.assertEqual(sql(f"""SELECT has_table_privilege(
                      '{role}','{table}','{perm}')::int""").stdout.strip(),"0",(role,table,perm))
        self.assertEqual(sql("""SELECT
           has_table_privilege('ipat_read_intent_owner',
              'ipat_ops.device_read_probe_intents','UPDATE')::int,
           has_table_privilege('ipat_read_intent_owner',
              'ipat_ops.device_read_probe_intents','DELETE')::int,
           has_table_privilege('ipat_read_intent_owner',
              'ipat_ops.device_read_probe_intent_audit','UPDATE')::int
        """).stdout.strip(),"0|0|0")
        self.assertEqual(sql("""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_read_intent_owner'""").stdout.strip(),"0|0")
    def test_01_unapproved_and_missing_gates_never_create_intent(self):
        a=candidate(TA,"92000000-0000-4000-8000-000000000001","pop-a")
        self.assertNotEqual(a,ZERO)
        req="92000000-0000-4000-8000-000000000011"
        self.assertEqual(intent(TA,a,req,"pop-a"),ZERO)
        self.assertNotEqual(approve(TA,a,"92000000-0000-4000-8000-000000000021"),ZERO)
        self.assertEqual(intent(TA,a,req,"pop-a"),ZERO)
        for index,gate in enumerate(("secure_management_path","device_identity",
             "readonly_account","recovery_plan"),1):
            self.assertNotEqual(attest(TA,a,gate,f"92000000-0000-4000-8000-{index:012d}"),ZERO)
            if index<4:self.assertEqual(intent(TA,a,req,"pop-a"),ZERO)
        self.assertEqual(intent(TA,a,req,"pop-b"),ZERO)
        self.assertEqual(intent(TB,a,req,"pop-b"),ZERO)
        self.assertEqual(intent(TA,a,req,"pop-a",subject=MAKER),ZERO)
        created=intent(TA,a,req,"pop-a")
        self.assertNotEqual(created,ZERO)
        self.assertEqual(intent(TA,a,req,"pop-a"),created)
        self.assertEqual(intent(TA,a,"92000000-0000-4000-8000-000000000022","pop-a"),ZERO)
        self.assertIn(created+"|"+a+"|pop-a|awaiting_separate_execution_review|true",
                       list_intents(TA,"pop-a"))
        self.assertNotIn(created,list_intents(TB,"pop-b"))
        self.assertNotIn(created,list_intents(TA,"pop-b"))
        self.assertEqual(sql(f"""SELECT count(*)||'|'||
           bool_and(published_at IS NULL)::text
           FROM ipat_ops.device_read_probe_intent_audit
           WHERE tenant_id='{TA}' AND intent_id='{created}'::uuid""").stdout.strip(),"1|true")
        self.assertEqual(sql(f"""SELECT
           state||'|'||must_revalidate_before_execution::text
           FROM ipat_ops.device_read_probe_intents
           WHERE tenant_id='{TA}' AND intent_id='{created}'::uuid""").stdout.strip(),
           "awaiting_separate_execution_review|true")
        self.assertEqual(sql(f"""SELECT connectivity||'|'||health||'|'||
           coalesce(last_verified_at::text,'NONE')
           FROM ipat_ops.device_candidates
           WHERE tenant_id='{TA}' AND id='{a}'""").stdout.strip(),"unknown|not_measured|NONE")
    def test_02_later_block_rejects_new_intent_but_immutable_audit_remains(self):
        b=candidate(TB,"92000000-0000-4000-8000-000000000002","pop-b")
        self.assertNotEqual(b,ZERO)
        self.assertNotEqual(approve(TB,b,"92000000-0000-4000-8000-000000000032"),ZERO)
        for i,gate in enumerate(("secure_management_path","device_identity",
             "readonly_account","recovery_plan"),10):
            self.assertNotEqual(attest(TB,b,gate,f"92000000-0000-4000-8000-{i:012d}"),ZERO)
        self.assertNotEqual(attest(TB,b,"device_identity",
          "92000000-0000-4000-8000-000000000099",verdict="blocked"),ZERO)
        self.assertEqual(intent(TB,b,"92000000-0000-4000-8000-000000000033","pop-b"),ZERO)
        self.assertEqual(list_intents(TB,"pop-b"),"SET\n")
    def test_03_unknown_role_untrusted_issuer_and_duplicate_request_denied(self):
        a=candidate(TA,"92000000-0000-4000-8000-000000000004","pop-a")
        self.assertNotEqual(a,ZERO)
        self.assertNotEqual(approve(TA,a,"92000000-0000-4000-8000-000000000034"),ZERO)
        for i,gate in enumerate(("secure_management_path","device_identity",
            "readonly_account","recovery_plan"),20):
            self.assertNotEqual(attest(TA,a,gate,f"92000000-0000-4000-8000-{i:012d}"),ZERO)
        old_req="92000000-0000-4000-8000-000000000011"
        self.assertEqual(intent(TA,a,old_req,"pop-a"),ZERO)
        self.assertEqual(intent(TA,a,"92000000-0000-4000-8000-000000000035",
                                "pop-a",issuer="https://forged.invalid"),ZERO)
        self.assertEqual(intent(TA,a,"92000000-0000-4000-8000-000000000035",
                                "pop-a",subject=CHECKER),ZERO)
        self.assertEqual(list_intents(TA,"pop-b"),"SET\n")
def load_tests(loader, standard_tests, pattern):
    # R9.7 piggybacks on the EXISTING disposable R9.2 CI discovery step;
    # the OAuth bot has no workflow-edit scope. Existing R9.2 fixtures run
    # first; then R9.7 adds a separately gated, nonexecuting 0010 migration.
    import test_connection_drafts_integration
    standard_tests.addTests(loader.loadTestsFromModule(test_connection_drafts_integration))
    return standard_tests

if __name__=="__main__": unittest.main()
