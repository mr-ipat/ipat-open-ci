"""Mr. iPat / IPAT: opt-in disposable PostgreSQL R5.4 transactional lab.
Run AFTER the existing R5.1 integration test on the SAME throwaway CI database.
A trusted synthetic superuser is used ONLY as a test harness, not a product API.
"""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4
from test_postgres_rls_integration import TA, TB, sql, run

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "deploy/db/migrations/0002_lab_job_outbox.sql"
DIGEST = "a" * 64

class SyntheticJobOutbox(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getenv("IPAT_PG_EPHEMERAL_TEST") != "1":
            raise unittest.SkipTest("Explicit disposable PostgreSQL CI required")
        assert os.getenv("PGHOST") == "127.0.0.1"
        assert os.getenv("PGDATABASE") == "ipat_synthetic"
        assert os.getenv("IPAT_PG_SYNTHETIC_PASSWORD") == "local_ci_synthetic_only"
        assert sql("SELECT to_regclass('ipat_ops.devices') IS NOT NULL").stdout.strip() == "t", (
            "Run previous R5.1 synthetic suite first; refuse missing schema"
        )
        assert sql("SELECT to_regclass('ipat_ops.provisioning_jobs') IS NULL").stdout.strip() == "t", (
            "Refusing to migrate or overwrite a previously used jobs test DB"
        )
        run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-f", str(MIGRATION)])

    def setUp(self):
        # Unique synthetic hardware references prevent inter-test lock collisions.
        self.router_a, self.router_b = str(uuid4()), str(uuid4())
        sql(f"""INSERT INTO ipat_ops.devices(tenant_id,id,pop_id,device_kind,vendor)
             VALUES ('{TA}','{self.router_a}','pop-a','router','synthetic'),
                    ('{TB}','{self.router_b}','pop-b','router','synthetic')""")

    def create(self, tenant, router, pop, key=None, job=None):
        job, key = job or str(uuid4()), key or str(uuid4())
        sql(f"""INSERT INTO ipat_ops.provisioning_jobs
             (tenant_id,id,router_id,pop_id,idempotency_key,plan_digest,requested_by)
             VALUES ('{tenant}','{job}','{router}','{pop}','{key}','{DIGEST}','maker')""")
        return job

    def approve(self, tenant, job):
        sql(f"""UPDATE ipat_ops.provisioning_jobs
             SET state='approved',approved_by='checker',
                 approval_expires_at=clock_timestamp()+interval '10 minutes'
             WHERE tenant_id='{tenant}' AND id='{job}'""")

    def lease(self, tenant, job, seconds=30, expect=True):
        return sql(f"""UPDATE ipat_ops.provisioning_jobs
             SET state='leased',lease_owner='synthetic-worker',lease_epoch=1,
                 lease_until=clock_timestamp()+interval '{seconds} seconds'
             WHERE tenant_id='{tenant}' AND id='{job}'""", expect=expect)

    def events(self, tenant, job):
        return sql(f"""SELECT event_type FROM ipat_ops.job_outbox
                        WHERE tenant_id='{tenant}' AND job_id='{job}'
                        ORDER BY created_at,event_type""").stdout.strip().splitlines()

    def test_missing_tenant_or_pop_and_cross_scope_are_invisible(self):
        j = self.create(TA, self.router_a, "pop-a")
        self.assertEqual(sql("SELECT count(*) FROM ipat_ops.provisioning_jobs",
                             user="ipat_app_runtime").stdout.strip(), "0")
        q = f"""BEGIN;SET LOCAL ipat.tenant_id='{TA}';
                SELECT count(*) FROM ipat_ops.provisioning_jobs;
                SELECT count(*) FROM ipat_ops.job_outbox;COMMIT;"""
        self.assertEqual([s for s in sql(q,user="ipat_app_runtime").stdout.splitlines()
                          if s.isdigit()], ["0","0"])
        for t, pop, expected in [(TA,"pop-a",1),(TB,"pop-a",0),(TA,"pop-b",0)]:
            q = f"""BEGIN;SET LOCAL ipat.tenant_id='{t}';
                     SET LOCAL ipat.pop_id='{pop}';
                     SELECT count(*) FROM ipat_ops.provisioning_jobs WHERE id='{j}';
                     SELECT count(*) FROM ipat_ops.job_outbox WHERE job_id='{j}';
                     COMMIT;"""
            counts = [s for s in sql(q,user="ipat_app_runtime").stdout.splitlines()
                      if s.isdigit()]
            self.assertEqual(counts,[str(expected),str(expected)])
        self.assertNotEqual(sql(f"""BEGIN;SET LOCAL ipat.tenant_id='{TA}';
            SET LOCAL ipat.pop_id='pop-a';
            DELETE FROM ipat_ops.provisioning_jobs WHERE id='{j}';COMMIT;""",
            user="ipat_app_runtime",expect=False).returncode,0)
        self.assertNotEqual(sql("TRUNCATE ipat_ops.job_outbox",
                                user="ipat_app_runtime",expect=False).returncode,0)

    def test_idempotency_immutable_plan_and_cross_tenant_router_fk(self):
        key, job = str(uuid4()), str(uuid4())
        self.create(TA, self.router_a,"pop-a",key=key,job=job)
        self.assertNotEqual(sql(f"""INSERT INTO ipat_ops.provisioning_jobs
             (tenant_id,id,router_id,pop_id,idempotency_key,plan_digest,requested_by)
             VALUES ('{TA}','{uuid4()}','{self.router_a}','pop-a','{key}','{DIGEST}','maker')""",
             expect=False).returncode,0)
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
             SET plan_digest='{'b'*64}' WHERE tenant_id='{TA}' AND id='{job}'""",
             expect=False).returncode,0)
        self.assertNotEqual(sql(f"""INSERT INTO ipat_ops.provisioning_jobs
             (tenant_id,id,router_id,pop_id,idempotency_key,plan_digest,requested_by)
             VALUES ('{TA}','{uuid4()}','{self.router_b}','pop-a','{uuid4()}','{DIGEST}','maker')""",
             expect=False).returncode,0)
        self.assertEqual(self.events(TA,job), ["awaiting_approval"])

    def test_approval_state_validation_and_atomic_outbox(self):
        j = self.create(TA,self.router_a,"pop-a")
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
            SET state='approved',approved_by='maker',
                approval_expires_at=clock_timestamp()+interval '5 minutes'
            WHERE id='{j}'""", expect=False).returncode,0)
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
            SET state='approved',approved_by='checker',
                approval_expires_at=clock_timestamp()+interval '2 hours'
            WHERE id='{j}'""",expect=False).returncode,0)
        self.approve(TA,j)
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
            SET state='approved' WHERE id='{j}'""",expect=False).returncode,0)
        self.assertEqual(set(self.events(TA,j)),{"awaiting_approval","approved"})

    def test_conflicting_leases_and_unknown_quarantine(self):
        # Same hardware UUID across two synthetic tenants must fail closed;
        # enrollment uniqueness must later be validated outside SQL fixtures.
        sql(f"""INSERT INTO ipat_ops.devices(tenant_id,id,pop_id,device_kind,vendor)
                 VALUES ('{TB}','{self.router_a}','pop-b','router','synthetic')""")
        ja = self.create(TA,self.router_a,"pop-a")
        jb = self.create(TB,self.router_a,"pop-b")
        self.approve(TA,ja)
        self.approve(TB,jb)
        self.lease(TA,ja,seconds=1)
        self.assertNotEqual(self.lease(TB,jb,expect=False).returncode,0)
        sql("SELECT pg_sleep(1.1)")
        sql(f"""UPDATE ipat_ops.provisioning_jobs SET state='unknown'
                WHERE tenant_id='{TA}' AND id='{ja}'""")
        self.assertNotEqual(self.lease(TB,jb,expect=False).returncode,0)
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
            SET state='approved' WHERE tenant_id='{TA}' AND id='{ja}'""",
            expect=False).returncode,0)
        self.assertIn("unknown",self.events(TA,ja))
        self.assertEqual(sql(f"""SELECT count(*) FROM ipat_ops.provisioning_jobs
             WHERE router_id='{self.router_a}' AND state='unknown'""").stdout.strip(),"1")

    def test_worker_fence_and_bounded_completion(self):
        j = self.create(TA,self.router_a,"pop-a")
        self.approve(TA,j)
        self.assertNotEqual(self.lease(TA,j,seconds=65,expect=False).returncode,0)
        self.lease(TA,j,seconds=30)
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
           SET state='completed',lease_epoch=2 WHERE tenant_id='{TA}' AND id='{j}'""",
           expect=False).returncode,0)
        sql(f"""UPDATE ipat_ops.provisioning_jobs SET state='completed'
                WHERE tenant_id='{TA}' AND id='{j}'""")
        self.assertNotEqual(sql(f"""UPDATE ipat_ops.provisioning_jobs
           SET state='leased' WHERE tenant_id='{TA}' AND id='{j}'""",
           expect=False).returncode,0)
        self.assertEqual(set(self.events(TA,j)),
            {"awaiting_approval","approved","leased","completed"})

    def test_transaction_rollback_does_not_leave_orphan_event(self):
        j, key = str(uuid4()),str(uuid4())
        bad = sql(f"""BEGIN;
           INSERT INTO ipat_ops.provisioning_jobs
           (tenant_id,id,router_id,pop_id,idempotency_key,plan_digest,requested_by)
           VALUES ('{TA}','{j}','{self.router_a}','pop-a','{key}','{DIGEST}','maker');
           SELECT 1/0;COMMIT;""",expect=False)
        self.assertNotEqual(bad.returncode,0)
        self.assertEqual(sql(f"""SELECT count(*) FROM ipat_ops.provisioning_jobs
            WHERE id='{j}'""").stdout.strip(),"0")
        self.assertEqual(sql(f"""SELECT count(*) FROM ipat_ops.job_outbox
            WHERE job_id='{j}'""").stdout.strip(),"0")

    def test_zz_restore_jobs_and_outbox_into_second_synthetic_database(self):
        j = self.create(TA,self.router_a,"pop-a")
        self.approve(TA,j)
        query = """SELECT 'job:'||tenant_id||':'||id||':'||state FROM ipat_ops.provisioning_jobs
                   UNION ALL SELECT 'event:'||tenant_id||':'||job_id||':'||event_type
                   FROM ipat_ops.job_outbox ORDER BY 1"""
        before = sql(query).stdout.strip().splitlines()
        self.assertGreaterEqual(len(before),2)
        with tempfile.TemporaryDirectory(prefix="ipat-jobs-pg-synthetic-") as d:
            dump = Path(d)/"synthetic-jobs.dump"
            run(["pg_dump","-Fc","--no-owner","--schema=ipat_platform",
                 "--schema=ipat_ops","-f",str(dump)])
            self.assertGreater(dump.stat().st_size,256)
            run(["createdb","ipat_synthetic_jobs_restored"])
            run(["pg_restore","--no-owner","--exit-on-error","-d",
                 "ipat_synthetic_jobs_restored",str(dump)])
            after = sql(query,database="ipat_synthetic_jobs_restored").stdout.strip().splitlines()
            digest = lambda rows: hashlib.sha256("\n".join(rows).encode()).hexdigest()
            self.assertEqual(digest(before),digest(after))
            self.assertEqual(sql("SELECT count(*) FROM ipat_ops.provisioning_jobs",
                                 user="ipat_app_runtime",
                                 database="ipat_synthetic_jobs_restored").stdout.strip(),"0")
            scoped = sql(f"""BEGIN;SET LOCAL ipat.tenant_id='{TA}';
                SET LOCAL ipat.pop_id='pop-a';
                SELECT count(*) FROM ipat_ops.provisioning_jobs WHERE id='{j}';COMMIT;""",
                user="ipat_app_runtime", database="ipat_synthetic_jobs_restored").stdout
            self.assertIn("\n1\n",scoped)
            print("SYNTHETIC_JOB_OUTBOX_NEW_DATABASE_RESTORE_SHA256_MATCH=PASS")

if __name__ == "__main__":
    unittest.main()
