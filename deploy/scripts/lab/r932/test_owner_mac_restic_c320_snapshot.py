"""Pure synthetic and no-network safety regression for owner-operated backup."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

FILE=Path(__file__).resolve().parent/'owner_mac_restic_c320_snapshot.py'
spec=importlib.util.spec_from_file_location('r932_owner_only_mac',FILE)
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
class OwnerOnlyBackupTests(unittest.TestCase):
 def test_default_requirements_is_offline_and_explicit(self):
  p=subprocess.run([sys.executable,str(FILE),'--requirements'],capture_output=True,text=True,timeout=3)
  self.assertEqual(p.returncode,0)
  r=json.loads(p.stdout)
  self.assertEqual(r['mode'],'HUMAN_OWNER_MAC_TERMINAL_ONLY')
  self.assertEqual(r['device_commands'],0)
  self.assertFalse(r['actual_device_adopted'])
  self.assertNotIn('10.77.13.233',p.stdout)
  self.assertNotIn(M.EXPECTED_SHA,p.stdout)
 def test_offline_real_mac_prerequisites_are_distinct_from_backup_success(self):
  p=subprocess.run([sys.executable,str(FILE),'--local-readiness'],capture_output=True,text=True,timeout=10)
  if sys.platform=='darwin':
   self.assertEqual(p.returncode,0)
   self.assertIn('BACKUP_AND_RESTORE_NOT_PERFORMED_BY_READINESS',p.stdout)
  else:self.assertNotEqual(p.returncode,0)
 def test_non_tty_backup_fails_before_network_or_password_access(self):
  for opt in ('--backup-and-restore','--verify-only'):
   p=subprocess.run([sys.executable,str(FILE),opt],input='',capture_output=True,text=True,timeout=3)
   self.assertEqual(p.returncode,4)
   self.assertIn('NOT_VERIFIED_FAIL_CLOSED',p.stderr)
   self.assertNotIn('Building configuration',p.stdout+p.stderr)
 def test_private_directory_denies_symlink_or_world_readable(self):
  with tempfile.TemporaryDirectory(prefix='ipat-r932-synthetic-') as tmp:
   p=Path(tmp).resolve();os.chmod(p,0o700)
   M.private_dir(p)
   p.chmod(0o755)
   with self.assertRaises(M.Refused):M.private_dir(p)
   p.chmod(0o700)
   link=p.parent/(p.name+'-link')
   link.symlink_to(p)
   try:
    with self.assertRaises(M.Refused):M.private_dir(link)
   finally:link.unlink()
 def test_remote_producer_enforces_actual_integrity_before_stdout(self):
  s=M.REMOTE_PRODUCER
  self.assertIn('hashlib.sha256(content).hexdigest()',s)
  self.assertIn('sys.stdout.buffer.write(content)',s)
  self.assertLess(s.index('assert r.get(\'bytes\')'),s.index('sys.stdout.buffer.write(content)'))
  self.assertEqual(s.count('/home/openai/.local/share/ipat/r931-private-olt-backup'),1)
  self.assertNotIn('zte:zte',s)
 def test_restore_mismatch_always_cleans_private_temp_folder(self):
  class FakeComplete:pass
  with tempfile.TemporaryDirectory(prefix='ipat-r932-receipt-synthetic-') as tmp:
   root=Path(tmp);root.chmod(0o700)
   def fake_run(args,**kwargs):
    if 'restore' in args:
     restored=Path(args[-1])/M.SNAPSHOT_NAME
     restored.write_bytes(b'wrong synthetic content')
    return FakeComplete()
   with patch.object(M.subprocess,'run',side_effect=fake_run):
    with self.assertRaises(M.Refused):M.verify_existing(root,{},'synthetic-id',root)
   self.assertEqual(sorted(x.name for x in root.iterdir()),[])
 def test_repeat_independent_restore_checks_immutable_receipt_without_overwriting(self):
  import stat
  with tempfile.TemporaryDirectory(prefix='ipat-r932-receipt-') as tmp:
   p=Path(tmp)/'existing.json'
   trusted={'restic_snapshot_id':'a'*64,'sha256':'synthetic'}
   p.write_text(json.dumps({**trusted,'verified_utc':'previous-day'}));p.chmod(0o600)
   M.reverify_existing_receipt(p,{**trusted,'verified_utc':'today'})
   self.assertEqual(json.loads(p.read_text())['verified_utc'],'previous-day')
   with self.assertRaises(M.Refused):M.reverify_existing_receipt(p,{**trusted,'sha256':'tampered','verified_utc':'today'})
   p.chmod(0o644)
   with self.assertRaises(M.Refused):M.reverify_existing_receipt(p,trusted)
 def test_sensitive_real_files_never_enter_public_build(self):
  src=FILE.read_text()
  self.assertIn('NOT vendor-native',src)
  self.assertIn('StrictHostKeyChecking=yes',src)
  self.assertIn('BatchMode=yes',src)
  self.assertIn('snapshot',src)
  self.assertNotIn('sshpass',src)
if __name__=='__main__':unittest.main()
