"""No hardware/network tests of independent console RSA key comparison."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner_console',HERE/'verify_owner_console_host_key.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
KEY='ssh-rsa '+('A'*100)+' ConsoleKey'
FP='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

class OfflineConsoleKeyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='ipat-r914-oob-');self.addCleanup(temp.cleanup)
        self.folder=Path(temp.name)
        self.key=self.folder/'trusted-console.pub'
        self.key.write_text(KEY+'\n');self.key.chmod(0o600)
    def test_exact_mock_owner_asserted_match_has_no_adoption(self):
        def fake(argv,**kwargs):
            self.assertEqual(argv,['ssh-keygen','-lf',str(self.key)])
            return subprocess.CompletedProcess(argv,0,'2048 '+FP+' ConsoleKey (RSA)\n','')
        result=M.verify(self.key,fake)
        self.assertTrue(result['owner_asserted_console_key_matches_observed'])
        self.assertFalse(result['independent_reviewer_approval_recorded'])
        self.assertFalse(result['device_adopted'])
        self.assertEqual(result['network_packets_sent'],0)
    def test_fingerprint_mismatch_fails_matching_not_marking_adopted(self):
        def fake(argv,**kwargs):
            return subprocess.CompletedProcess(argv,0,
                '2048 SHA256:'+'B'*43+' ConsoleKey (RSA)\n','')
        result=M.verify(self.key,fake)
        self.assertFalse(result['owner_asserted_console_key_matches_observed'])
        self.assertFalse(result['device_adopted'])
    def test_refuses_symlink_world_readable_repo_or_invalid_key(self):
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):M.trusted_file(self.key)
        self.key.chmod(0o600)
        link=self.folder/'linked.pub';link.symlink_to(self.key)
        with self.assertRaises(ValueError):M.trusted_file(link)
        self.key.write_text('ssh-dss '+'A'*120+'\n')
        with self.assertRaises(ValueError):M.trusted_file(self.key)
    def test_failure_does_not_claim_console_trust(self):
        def fail(argv,**kwargs):return subprocess.CompletedProcess(argv,1,'','invalid')
        with self.assertRaises(ValueError):M.verify(self.key,fail)

if __name__=='__main__':unittest.main()
