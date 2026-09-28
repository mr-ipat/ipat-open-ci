"""Real disposable PG physical site metadata. NEVER test real OLT access."""
import os
from pathlib import Path
import unittest
from test_postgres_rls_integration import TA, TB, run, sql
from test_read_probe_intent_integration import ISS, MAKER, CHECKER, ZERO, candidate, approve, q

MIG=Path(__file__).resolve().parents[1]/'migrations/0011_lab_physical_site_evidence.sql'
FN='ipat_platform.attest_lab_physical_site_gate'
READ='ipat_platform.list_lab_physical_site_readiness'
GATES=('trusted_oob_host_key','isolated_management_last_hop',
       'restricted_publickey_account','firmware_readonly_command',
       'live_service_baseline','dedicated_worker_private_route')

def insert(tenant, item, request, gate, verdict='verified', subject=CHECKER):
    return sql(f"""SET ROLE ipat_site_evidence_execute;
      SELECT coalesce({FN}({q(ISS)},{q(subject)},'{tenant}'::uuid,
       '{item}'::uuid,'{request}'::uuid,{q(gate)},{q(verdict)},
       '{'a'*64}',statement_timestamp(),statement_timestamp()+interval '8 hours'),
       '{ZERO}'::uuid)""").stdout.strip().splitlines()[-1]

class PhysicalSiteEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv('IPAT_PG_EPHEMERAL_TEST')!='1':
            raise unittest.SkipTest('disposable PostgreSQL only')
        assert os.getenv('PGHOST')=='127.0.0.1'
        assert os.getenv('PGDATABASE')=='ipat_synthetic'
        assert os.getenv('IPAT_PG_SYNTHETIC_PASSWORD')=='local_ci_synthetic_only'
        assert sql("SELECT to_regclass('ipat_ops.tenant_connection_drafts') IS NOT NULL").stdout.strip()=='t'
        assert sql("SELECT to_regclass('ipat_ops.physical_site_evidence') IS NULL").stdout.strip()=='t'
        run(['psql','-X','-v','ON_ERROR_STOP=1','-f',str(MIG)])
    def test_00_private_roles_no_mutations_or_secret_fields(self):
        signature=FN+'(text,text,uuid,uuid,uuid,text,text,text,timestamptz,timestamptz)'
        out=sql(f"""SELECT
         has_function_privilege('ipat_site_evidence_execute','{signature}','EXECUTE')::int,
         has_function_privilege('ipat_app_runtime','{signature}','EXECUTE')::int,
         has_function_privilege('ipat_identity_query','{signature}','EXECUTE')::int""").stdout.strip()
        self.assertEqual(out,'1|0|0')
        for role in ('ipat_site_evidence_execute','ipat_identity_query','ipat_app_runtime'):
            for permission in ('SELECT','INSERT','UPDATE','DELETE'):
                self.assertEqual(sql(f"""SELECT has_table_privilege(
                   '{role}','ipat_ops.physical_site_evidence','{permission}')::int""").stdout.strip(),'0')
        self.assertEqual(sql("""SELECT rolsuper::int,rolbypassrls::int
          FROM pg_roles WHERE rolname='ipat_site_evidence_owner'""").stdout.strip(),'0|0')
        columns=sql("""SELECT column_name FROM information_schema.columns
          WHERE table_schema='ipat_ops' AND table_name='physical_site_evidence'""").stdout
        for prohibited in ('password','secret','endpoint','private_key','management_ip'):
            self.assertNotIn(prohibited,columns)

    def test_01_site_gates_tenant_scope_block_and_never_execute(self):
        a=candidate(TA,'91400000-0000-4000-8000-000000000001','pop-a')
        self.assertNotEqual(a,ZERO)
        first='91400000-0000-4000-8000-000000000011'
        self.assertEqual(insert(TA,a,first,GATES[0]),ZERO)
        self.assertNotEqual(approve(TA,a,'91400000-0000-4000-8000-000000000012'),ZERO)
        self.assertEqual(insert(TB,a,first,GATES[0]),ZERO)
        self.assertEqual(insert(TA,a,first,GATES[0],subject=MAKER),ZERO)
        self.assertEqual(insert(TA,a,first,'unsafe_public_telnet'),ZERO)
        self.assertNotEqual(insert(TA,a,first,GATES[0]),ZERO)
        for n,g in enumerate(GATES[1:],20):
            self.assertNotEqual(insert(TA,a,f'91400000-0000-4000-8000-{n:012d}',g),ZERO)
        listed=sql(f"""SET ROLE ipat_identity_query;
         SELECT gate||'|'||gate_verified::text||'|'||physical_worker_enabled::text
         FROM {READ}({q(ISS)},{q(MAKER)},'{TA}'::uuid)
         WHERE candidate_id='{a}'::uuid ORDER BY gate""").stdout.strip().splitlines()
        listed=[line for line in listed if '|' in line]  # psql also prints SET
        self.assertEqual(len(listed),6)
        self.assertTrue(all(s.endswith('|true|false') for s in listed),listed)
        other=sql(f"""SET ROLE ipat_identity_query;
          SELECT gate FROM {READ}({q(ISS)},{q(MAKER)},'{TB}'::uuid)
          WHERE candidate_id='{a}'::uuid""").stdout.strip().splitlines()
        self.assertEqual(other,['SET'])
        denied=sql(f"""SET ROLE ipat_site_evidence_execute;
          UPDATE ipat_ops.physical_site_evidence SET verdict='verified'
          WHERE tenant_id='{TA}'""",expect=False)
        self.assertNotEqual(denied.returncode,0)
        self.assertNotEqual(insert(TA,a,'91400000-0000-4000-8000-000000000039',GATES[0],verdict='blocked'),ZERO)
        recheck=sql(f"""SET ROLE ipat_identity_query;
          SELECT gate_verified::text||'|'||physical_worker_enabled::text
          FROM {READ}({q(ISS)},{q(MAKER)},'{TA}'::uuid)
          WHERE candidate_id='{a}' AND gate='{GATES[0]}'""").stdout.strip().splitlines()[-1]
        self.assertEqual(recheck,'false|false')

if __name__=='__main__':unittest.main()
