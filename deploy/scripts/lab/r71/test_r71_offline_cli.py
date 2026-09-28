"""Real offline Rust CLI contract against throwaway synthetic CLI text.
NO actual OLT, network, firmware or credentials are used here.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
BIN = ROOT / 'target/debug/c320-offline-review'
CARDS = ('Rack Shelf Slot CfgType RealType Port HardVer SoftVer Status\n'
         '1 1 1 GTGO GTGOG 8 120301 V2.0.0 INSERVICE\n'
         '1 1 3 SMXA SMXA 0 110702 V2.0.0 INSERVICE\n'
         '1 1 4 SMXA SMXA 0 110702 V2.0.0 STANDBY\n')
VERSIONS = ('PhyLoc FileType VerType VerTag BuildTime VerLength\n'
            '1/1/1 GTGOG MVR V0.0.LAB 2026-01-01 01:02:03 100\n'
            '1/1/3 SMXA MVR V0.0.LAB 2026-01-01 01:02:03 100\n'
            '1/1/4 SMXA MVR V0.0.LAB 2026-01-01 01:02:03 100\n')

class OfflineEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert BIN.is_file(), 'Compile offline Rust CLI on disposable CI checkout first'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ipat-r71-private-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        os.chmod(self.folder,0o700)
        self.cards = self.folder / 'cards.txt'
        self.versions = self.folder / 'versions.txt'
        self.cards.write_text(CARDS)
        self.versions.write_text(VERSIONS)
        os.chmod(self.cards,0o600)
        os.chmod(self.versions,0o600)

    def call(self,optin=True,method='--parse'):
        env=os.environ.copy()
        env.pop('IPAT_R71_OWNER_CONFIRMS_REDACTED_OFFLINE_CAPTURE',None)
        if optin:
            env['IPAT_R71_OWNER_CONFIRMS_REDACTED_OFFLINE_CAPTURE']='YES'
        return subprocess.run([str(BIN),method,str(self.folder)],
                              capture_output=True,text=True,env=env,timeout=5)

    def test_private_synthetic_inventory_never_claims_physical_validation(self):
        p=self.call()
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('CARDS=3 VERSION_ROWS=3',p.stdout)
        self.assertIn('PHYSICAL_DEVICE_IDENTITY=UNVERIFIED',p.stdout)
        self.assertIn('FIRMWARE_EXECUTION=DISABLED',p.stdout)
        self.assertNotIn('V0.0.LAB',p.stdout)
        self.assertNotIn('GTGOG',p.stdout)

    def test_configured_card_alias_is_accepted_only_for_same_slot(self):
        self.cards.write_text(CARDS.replace("GTGO GTGOG", "ETGO ETGOD"))
        self.versions.write_text(VERSIONS.replace("GTGOG MVR", "ETGO MVR"))
        os.chmod(self.cards,0o600)
        os.chmod(self.versions,0o600)
        result=self.call()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('PHYSICAL_DEVICE_IDENTITY=UNVERIFIED',result.stdout)
        self.versions.write_text(
            self.versions.read_text().replace("ETGO MVR","UNRELATED MVR")
        )
        os.chmod(self.versions,0o600)
        self.assertEqual(self.call().returncode,4)

    def test_non_opted_in_and_unknown_flags_fail_without_access(self):
        self.assertEqual(self.call(optin=False).returncode,4)
        self.assertEqual(self.call(method='--live').returncode,4)

    def test_owner_files_and_symlinks_required(self):
        os.chmod(self.cards,0o644)
        self.assertEqual(self.call().returncode,4)
        os.chmod(self.cards,0o600)
        self.cards.unlink()
        self.cards.symlink_to(self.versions)
        self.assertEqual(self.call().returncode,4)

    def test_private_folder_and_cross_card_version_mismatch_denied(self):
        os.chmod(self.folder,0o755)
        self.assertEqual(self.call().returncode,4)
        os.chmod(self.folder,0o700)
        self.versions.write_text(VERSIONS.replace('GTGOG MVR','SMXA MVR'))
        os.chmod(self.versions,0o600)
        self.assertEqual(self.call().returncode,4)

    def test_raw_sensitive_or_cli_unsafe_inputs_cannot_be_normalized(self):
        self.cards.write_text(CARDS + '\x1b[0m')
        os.chmod(self.cards,0o600)
        p=self.call()
        self.assertEqual(p.returncode,4)
        self.assertNotIn('GTGOG',p.stdout)
        self.assertNotIn('GTGOG',p.stderr)

if __name__=='__main__':
    unittest.main()
