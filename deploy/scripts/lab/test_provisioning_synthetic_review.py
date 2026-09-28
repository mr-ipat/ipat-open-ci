"""Static contract for the sealed, non-executable R5.3 provisioning simulator."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "crates/provisioning-core/src/lib.rs").read_text()
PRODUCTION = SOURCE.split("#[cfg(test)]", 1)[0]

class ProvisioningSyntheticContract(unittest.TestCase):
    def test_identity_proofs_remain_private_without_prod_constructors(self):
        self.assertIn("pub struct VerifiedActor {", PRODUCTION)
        self.assertIn("pub struct VerifiedWorker {", PRODUCTION)
        self.assertEqual(PRODUCTION.count("VerifiedActor {"), 1)
        self.assertEqual(PRODUCTION.count("VerifiedWorker {"), 1)
        self.assertNotIn("impl VerifiedActor", PRODUCTION)
        self.assertNotIn("impl VerifiedWorker", PRODUCTION)

    def test_no_real_execution_transport(self):
        for forbidden in ("std::net", "std::process::Command", "TcpListener",
                          "reqwest", "routeros", "unsafe {"):
            self.assertNotIn(forbidden, PRODUCTION)
        self.assertIn("JobState::Unknown", PRODUCTION)
        self.assertIn("self.active_routers", PRODUCTION)

    def test_bounded_approval_and_lease(self):
        self.assertIn("MAX_OPERATIONS: usize = 128", PRODUCTION)
        self.assertIn("MAX_APPROVAL_SECONDS: u64 = 3_600", PRODUCTION)
        self.assertIn("MAX_LEASE_SECONDS: u64 = 60", PRODUCTION)
        self.assertIn("checker.subject == job.proposer", PRODUCTION)

if __name__ == "__main__":
    unittest.main()
