"""No network/credentials: synthetic full private C320 configuration safety."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

P=Path(__file__).resolve().parent/'verify_private_backup.py'
spec=importlib.util.spec_from_file_location('r931_private_backup',P)
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
DATA=b'Building configuration...\r\nconfig-version 2.1\r\n'+ b'!\r\ninterface synthetic_1\r\n shutdown\r\n'*1100 + b'!\r\nend\r\n'
class RealPrivateBackupSafety(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='ipat-r931-synthetic-')
  self.addCleanup(self.temp.cleanup)
  self.folder=Path(self.temp.name).resolve();os.chmod(self.folder,0o700)
  self.raw=self.folder/M.EXPECTED[0]
  self.receipt=self.folder/M.EXPECTED[1]
  self.set(DATA)
 def set(self,data,**overrides):
  self.raw.write_bytes(data);self.raw.chmod(0o600)
  r={'source':'ACTUAL_MANUAL_INTERACTIVE_ENCRYPTED_PRIVATE_SSH_CLI',
     'complete_running_config_marker_verified':True,'device_adopted':False,
     'on_olt_configuration_writes':0,'vendor_restorability_tested':False,
     'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
  r.update(overrides);self.receipt.write_text(json.dumps(r));self.receipt.chmod(0o600)
 def test_complete_synthetic_private_digest_stays_not_adopted(self):
  r=M.verify(self.folder)
  self.assertEqual(r['integrity'],'SHA256_MATCH_AND_VENDOR_END_MARKER')
  for key in ('off_host_encrypted_backup_restored','device_restore_tested',
              'restricted_account_verified','production_worker_authorized','device_adopted'):
   self.assertFalse(r[key])
  self.assertEqual(r['network_actions'],0)
 def test_rejects_truncated_or_pager_even_with_new_matching_digest(self):
  self.set(DATA[:-5]);
  with self.assertRaises(M.Denied):M.verify(self.folder)
  self.set(DATA[:-7]+b'--More--\r\nend\r\n')
  with self.assertRaises(M.Denied):M.verify(self.folder)
 def test_rejects_tamper_overshared_mode_and_symlink(self):
  self.raw.write_bytes(DATA+b'x')
  with self.assertRaises(M.Denied):M.verify(self.folder)
  self.set(DATA);self.raw.chmod(0o644)
  with self.assertRaises(M.Denied):M.verify(self.folder)
  self.raw.unlink();self.raw.symlink_to(self.receipt)
  with self.assertRaises(M.Denied):M.verify(self.folder)
 def test_refuses_false_backup_restorability_or_unapproved_config_writes(self):
  self.set(DATA,vendor_restorability_tested=True)
  with self.assertRaises(M.Denied):M.verify(self.folder)
  self.set(DATA,on_olt_configuration_writes=1)
  with self.assertRaises(M.Denied):M.verify(self.folder)
  self.set(DATA,device_adopted=True)
  with self.assertRaises(M.Denied):M.verify(self.folder)
if __name__=='__main__':unittest.main()
