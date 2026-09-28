"""IPAT synthetic-only ephemeral PostgreSQL 16 RLS + isolated logical restore.

Runs ONLY with explicit IPAT_PG_EPHEMERAL_TEST=1 on a disposable database.
Do not point at the lab VPS or real data. Requires psql, pg_dump, createdb, pg_restore.
This tests DATABASE RLS, not verified OIDC, trusted API binding or production PITR.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "deploy/db/migrations/0001_lab_tenant_rls.sql"
TA = "11111111-1111-4111-8111-111111111111"
TB = "22222222-2222-4222-8222-222222222222"
DA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SA = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
SB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

def run(cmd, *, user="postgres", database="ipat_synthetic", expect=True):
    env = os.environ.copy()
    env["PGUSER"] = user
    env["PGDATABASE"] = database
    if user == "ipat_app_runtime":
        env["PGPASSWORD"] = os.environ["IPAT_PG_SYNTHETIC_PASSWORD"]
    p = subprocess.run(cmd, env=env, text=True, capture_output=True)
    if expect and p.returncode:
        raise AssertionError(f"Command {cmd[0]} failed; stderr: {p.stderr[:600]}")
    return p

def sql(query, *, user="postgres", database="ipat_synthetic", expect=True):
    return run(["psql","-X","-A","-t","-v","ON_ERROR_STOP=1","-c",query],
               user=user,database=database,expect=expect)

def seeded_rows(db="ipat_synthetic"):
    # Never include a real customer's records in this test or its dump.
    q = """SELECT 'd:'||tenant_id||':'||id||':'||pop_id FROM ipat_ops.devices
           UNION ALL SELECT 's:'||tenant_id||':'||id||':'||customer_ref
           FROM ipat_ops.subscribers ORDER BY 1"""
    return sql(q,database=db).stdout.strip().splitlines()

class SyntheticPostgresRlsAndRestore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST") != "1":
            raise unittest.SkipTest("Opt-in ephemeral synthetic PostgreSQL required")
        # Require exact distinct synthetic disposable DB to avoid accidentally touching real DB.
        assert os.getenv("PGDATABASE") == "ipat_synthetic"
        assert os.getenv("PGHOST") == "127.0.0.1"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD") == "local_ci_synthetic_only"
        assert not sql("SELECT to_regclass('ipat_ops.devices') IS NOT NULL").stdout.strip() == "t", (
            "Refusing to touch a non-empty or previously migrated test DB"
        )
        run(["psql","-X","-v","ON_ERROR_STOP=1","-f",str(MIGRATION)])
        # Disposable test-only runtime auth. Never store actual runtime credential in repo.
        sql("ALTER ROLE ipat_app_runtime PASSWORD 'local_ci_synthetic_only'")
        sql(f"""INSERT INTO ipat_platform.tenants(id,tenant_slug) VALUES
                ('{TA}','tenant-alpha'),('{TB}','tenant-beta')""")
        sql(f"""INSERT INTO ipat_ops.devices(tenant_id,id,pop_id,device_kind,vendor) VALUES
                ('{TA}','{DA}','pop-a','ont','synthetic'),
                ('{TB}','{DB}','pop-b','ont','synthetic')""")
        sql(f"""INSERT INTO ipat_ops.subscribers
                (tenant_id,id,pop_id,customer_ref,device_id) VALUES
                ('{TA}','{SA}','pop-a','synthetic-a','{DA}'),
                ('{TB}','{SB}','pop-b','synthetic-b','{DB}')""")

    def test_runtime_is_not_owner_and_cannot_bypass_rls(self):
        roles = sql("""SELECT rolsuper::int,rolbypassrls::int,rolcreaterole::int
                      FROM pg_roles WHERE rolname='ipat_app_runtime'""").stdout.strip()
        self.assertEqual(roles,"0|0|0")
        self.assertEqual(sql("SELECT count(*) FROM ipat_ops.devices",
                             user="ipat_app_runtime").stdout.strip(),"0")
        self.assertNotEqual(sql("SELECT count(*) FROM ipat_platform.tenants",
                                user="ipat_app_runtime",expect=False).returncode,0)

    def test_isolation_and_transaction_local_scope(self):
        q = f"""BEGIN;
                 SET LOCAL ipat.tenant_id = '{TA}';
                 SELECT count(*) FROM ipat_ops.devices;
                 SELECT count(*) FROM ipat_ops.subscribers;
                 COMMIT;
                 SELECT count(*) FROM ipat_ops.devices;"""
        out = sql(q,user="ipat_app_runtime").stdout.splitlines()
        self.assertEqual([x for x in out if x in ("0","1")],["1","1","0"])
        other = sql(f"""BEGIN; SET LOCAL ipat.tenant_id='{TB}';
                        SELECT customer_ref FROM ipat_ops.subscribers;
                        COMMIT;""",user="ipat_app_runtime").stdout
        self.assertIn("synthetic-b",other)
        self.assertNotIn("synthetic-a",other)

    def test_cross_tenant_writes_and_truncate_fail(self):
        q = f"""BEGIN;SET LOCAL ipat.tenant_id='{TA}';
                INSERT INTO ipat_ops.devices(tenant_id,id,pop_id,device_kind,vendor)
                VALUES ('{TB}','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','pop-b','ont','bad');
                COMMIT;"""
        self.assertNotEqual(sql(q,user="ipat_app_runtime",expect=False).returncode,0)
        q2 = f"""BEGIN;SET LOCAL ipat.tenant_id='{TA}';
                 UPDATE ipat_ops.devices SET vendor='tampered' WHERE tenant_id='{TB}';
                 COMMIT;"""
        self.assertIn("UPDATE 0",sql(q2,user="ipat_app_runtime").stdout)
        self.assertNotEqual(sql("TRUNCATE ipat_ops.devices",
                                user="ipat_app_runtime",expect=False).returncode,0)
        q3 = f"""INSERT INTO ipat_ops.subscribers(tenant_id,id,pop_id,customer_ref,device_id)
                 VALUES ('{TA}','ffffffff-ffff-4fff-8fff-ffffffffffff',
                         'pop-a','synthetic-invalid','{DB}')"""
        self.assertNotEqual(sql(q3,expect=False).returncode,0)

    def test_rls_force_and_malformed_tenant_fails_closed(self):
        flags = sql("""SELECT relname, relrowsecurity::int,relforcerowsecurity::int
                       FROM pg_class WHERE relname IN ('devices','subscribers')
                       ORDER BY relname""").stdout.strip().splitlines()
        self.assertEqual(flags,["devices|1|1","subscribers|1|1"])
        bad = sql("""BEGIN;SET LOCAL ipat.tenant_id='not-a-uuid';
                     SELECT * FROM ipat_ops.devices;COMMIT;""",
                  user="ipat_app_runtime",expect=False)
        self.assertNotEqual(bad.returncode,0)

    def test_pg_dump_and_isolated_new_database_restore(self):
        before = seeded_rows()
        self.assertEqual(len(before),4)
        with tempfile.TemporaryDirectory(prefix="ipat-synthetic-pg-") as temp:
            dump = Path(temp)/"isolated.dump"
            run(["pg_dump","-Fc","--no-owner",
                 "--schema=ipat_platform","--schema=ipat_ops","-f",str(dump)])
            self.assertGreater(dump.stat().st_size,256)
            run(["createdb","ipat_synthetic_restored"])
            run(["pg_restore","--no-owner","--exit-on-error",
                 "-d","ipat_synthetic_restored",str(dump)])
            after = seeded_rows("ipat_synthetic_restored")
            self.assertEqual(
                hashlib.sha256("\n".join(before).encode()).hexdigest(),
                hashlib.sha256("\n".join(after).encode()).hexdigest())
            self.assertEqual(sql("SELECT count(*) FROM ipat_ops.devices",
                                 user="ipat_app_runtime",database="ipat_synthetic_restored").stdout.strip(),
                             "0")
            self.assertEqual(sql(f"""BEGIN;SET LOCAL ipat.tenant_id='{TA}';
                                     SELECT count(*) FROM ipat_ops.devices;COMMIT;""",
                                 user="ipat_app_runtime",
                                 database="ipat_synthetic_restored").stdout.splitlines()[-2],"1")
            print("SYNTHETIC_POSTGRES_NEW_DATABASE_RESTORE_SHA256_MATCH=PASS")

if __name__=="__main__":
    unittest.main()
