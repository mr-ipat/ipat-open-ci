"""Offline boundary-only review. Not an executed genuine IdP/PG BFF test."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
BRIDGE=(ROOT/'apps/control-api/src/browser_session_lab.rs').read_text()
API=(ROOT/'apps/control-api/src/main.rs').read_text()
LAB=(ROOT/'apps/control-api/src/device_workbench_lab.rs').read_text()

class R98Boundary(unittest.TestCase):
    def test_unmounted_scoped_draft_bridge(self):
        name='submit_nonexecutable_connection_draft_for_session'
        self.assertIn('async fn '+name,BRIDGE)
        method=BRIDGE.split('async fn '+name,1)[1].split('#[cfg(test)]',1)[0]
        for required in ('vault.authenticate(', 'RequestKind::Mutation',
                         '"tenant_admin"', 'restricted_reader',
                         'restricted_draft_writer.query_one(',
                         'ipat_platform.propose_lab_connection_draft',
                         'routeros6', 'wireguard'):
            self.assertIn(required,method)
        self.assertNotIn(name,API)
        self.assertNotIn(name,LAB)

if __name__=='__main__': unittest.main()
