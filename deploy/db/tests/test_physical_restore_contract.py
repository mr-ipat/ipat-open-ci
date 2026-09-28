"""Fail-closed source contract for disposable PostgreSQL physical recovery drill."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = (ROOT / "deploy/db/tests/physical_restore_ephemeral.sh").read_text()
CI = (ROOT / ".github/workflows/ci.yml").read_text()

class PhysicalRestoreContract(unittest.TestCase):
    def test_disposable_host_and_credentials_are_required(self):
        for marker in ('GITHUB_ACTIONS:-', 'IPAT_PG_EPHEMERAL_TEST:-',
                       'PGHOST:-', 'PGDATABASE:-', 'ipat_synthetic',
                       'local_ci_synthetic_only', 'PGUSER:-'):
            self.assertIn(marker, SCRIPT)
        self.assertIn("REFUSED: CI disposable synthetic PostgreSQL only", SCRIPT)

    def test_actual_basebackup_verify_and_separate_process(self):
        for marker in ('pg_basebackup', '-X stream', 'pg_verifybackup', 'docker cp',
                       'pg_ctl', '-p 5544', 'PGPORT=5544',
                       'sha256sum', "unscoped", 'trap cleanup EXIT'):
            self.assertIn(marker, SCRIPT)
        self.assertIn('NOT_PRODUCTION_PITR_OR_INDEPENDENT_FAILURE_DOMAIN', SCRIPT)

    def test_scoped_cleanup_and_no_network_mutations(self):
        self.assertIn('/tmp/ipat-ci-physical.*', SCRIPT)
        self.assertIn('if [[ "$hostdir" == /tmp/ipat-ci-physical.*', SCRIPT)
        for danger in ('nft -f', 'kubectl apply', 'iptables -A',
                       'systemctl stop', 'curl -sfL', 'ssh ', 'ufw allow'):
            self.assertNotIn(danger, SCRIPT)

    def test_separate_disposable_ci_job_is_explicit(self):
        self.assertIn('postgres-physical-recovery-lab:', CI)
        self.assertIn('postgres:16.9', CI)
        self.assertIn('test_physical_restore_contract.py', CI)
        self.assertIn('physical_restore_ephemeral.sh', CI)

if __name__ == "__main__":
    unittest.main()
