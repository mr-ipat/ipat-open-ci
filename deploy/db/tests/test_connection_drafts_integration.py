"""R9.7 disposable-only actual PG tenant plan drafts; never device or VPN I/O."""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA, TB, run, sql

MIG=Path(__file__).resolve().parents[1]/"migrations/0010_lab_connection_drafts.sql"
ISS="https://synthetic.r92.invalid/realm/lab"
MAKER="r92-maker"
ZERO="00000000-0000-0000-0000-000000000000"
FN="ipat_platform.propose_lab_connection_draft"
READ="ipat_platform.list_lab_connection_drafts"

def invoke(statement,role):
    return sql("SET ROLE "+role+";"+statement).stdout.strip().splitlines()[-1]

def candidate(tenant,request,pop):
    return invoke(f"""SELECT coalesce(ipat_platform.propose_lab_device_candidate(
       '{ISS}','{MAKER}','{tenant}'::uuid,'{request}'::uuid,
       '{pop}','LAB-R97-C320','olt','ZTE','VIRTUAL-C320',NULL
       ),'{ZERO}'::uuid)""","ipat_device_registry_execute")

def draft(tenant,item,req,pop,method="wireguard",gateway="routeros7",subject=MAKER):
    return invoke(f"""SELECT coalesce({FN}(
      '{ISS}','{subject}','{tenant}'::uuid,'{item}'::uuid,
      '{req}'::uuid,'{pop}','{method}','{gateway}'
      ),'{ZERO}'::uuid)""","ipat_connection_draft_execute")

class DurableConnectionDrafts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST")!="1":
            raise unittest.SkipTest("disposable PostgreSQL only")
        assert os.getenv("PGHOST")=="127.0.0.1"
        assert os.getenv("PGDATABASE")=="ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD")=="local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.device_read_probe_intents') IS NOT NULL").stdout.strip()=="t"
        assert sql("SELECT to_regclass('ipat_ops.tenant_connection_drafts') IS NULL").stdout.strip()=="t"
        assert sql(f"SELECT count(*) FROM ipat_platform.identity_memberships WHERE issuer='{ISS}' AND subject='{MAKER}'").stdout.strip()=="2"
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIG)])
    def test_00_privilege_and_secret_free_immutable_schema(self):
        fn=f"{FN}(text,text,uuid,uuid,uuid,text,text,text)"
        self.assertEqual(sql(f"""SELECT
          has_function_privilege('ipat_connection_draft_execute','{fn}','EXECUTE')::int,
          has_function_privilege('ipat_app_runtime','{fn}','EXECUTE')::int,
          has_function_privilege('ipat_identity_query','{fn}','EXECUTE')::int
        """).stdout.strip(),"1|0|0")
        for role in ("ipat_connection_draft_execute","ipat_app_runtime","ipat_identity_query"):
            for table in ("ipat_ops.tenant_connection_drafts",
                          "ipat_ops.tenant_connection_draft_audit"):
                for action in ("SELECT","INSERT","UPDATE","DELETE"):
                    self.assertEqual(sql(f"SELECT has_table_privilege('{role}','{table}','{action}')::int").stdout.strip(),"0")
        self.assertEqual(sql("""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_connection_draft_owner'""").stdout.strip(),"0|0")
        fields=sql("""SELECT column_name FROM information_schema.columns
           WHERE table_schema='ipat_ops' AND table_name='tenant_connection_drafts'""").stdout
        for forbidden in ('management_ip','password','secret','private_key',
                          'endpoint','cidr','ssh_key','provisioning_job'):
            self.assertNotIn(forbidden,fields)

    def test_01_isolated_tenant_pop_and_nondeployable_draft(self):
        a=candidate(TA,"97000000-0000-4000-8000-000000000001","pop-a")
        b=candidate(TB,"97000000-0000-4000-8000-000000000002","pop-b")
        self.assertNotIn(ZERO,(a,b))
        req="97000000-0000-4000-8000-000000000011"
        self.assertEqual(draft(TB,a,req,"pop-a"),ZERO)
        self.assertEqual(draft(TA,a,req,"pop-b"),ZERO)
        self.assertEqual(draft(TA,a,req,"pop-a",subject="unknown"),ZERO)
        self.assertEqual(draft(TA,a,req,"pop-a",gateway="routeros6"),ZERO)
        self.assertEqual(draft(TA,a,req,"pop-a",method="public_telnet"),ZERO)
        created=draft(TA,a,req,"pop-a")
        self.assertNotEqual(created,ZERO)
        self.assertEqual(draft(TA,a,req,"pop-a"),created)
        self.assertEqual(draft(TA,a,"97000000-0000-4000-8000-000000000012","pop-a"),ZERO)
        own=sql(f"""SET ROLE ipat_identity_query;
         SELECT draft_id::text||'|'||state||'|'||provisioning_enabled::text
         FROM {READ}('{ISS}','{MAKER}','{TA}'::uuid)""").stdout
        self.assertIn(created+"|awaiting_separate_review|false",own)
        other=sql(f"""SET ROLE ipat_identity_query;
         SELECT draft_id::text FROM {READ}('{ISS}','{MAKER}','{TB}'::uuid)""").stdout
        self.assertNotIn(created,other)
        self.assertEqual(sql(f"""SELECT count(*) FROM
           ipat_ops.tenant_connection_draft_audit
           WHERE tenant_id='{TA}' AND draft_id='{created}'::uuid""").stdout.strip(),"1")
        self.assertNotEqual(draft(TB,b,"97000000-0000-4000-8000-000000000013","pop-b",method="ipsec",gateway="routeros6"),ZERO)
        self.assertEqual(sql(f"""SELECT count(*) FROM
           ipat_ops.tenant_connection_drafts WHERE tenant_id='{TA}'""").stdout.strip(),"1")
        # Even this restricted callable SQL role cannot mutate the draft table.
        denied=sql(f"""SET ROLE ipat_connection_draft_execute;
          UPDATE ipat_ops.tenant_connection_drafts SET provisioning_enabled=true
          WHERE draft_id='{created}'::uuid""",expect=False)
        self.assertNotEqual(denied.returncode,0)

def load_tests(loader, standard_tests, pattern):
    # Ordered under the existing R9.2 disposable PG CI after migration 0010.
    import test_physical_site_evidence_integration
    standard_tests.addTests(loader.loadTestsFromModule(test_physical_site_evidence_integration))
    return standard_tests

if __name__=='__main__':
    unittest.main()
