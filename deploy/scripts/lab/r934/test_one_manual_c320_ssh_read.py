"""Static and synthetic no-network checks; actual SSH one-shot separately audited."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

FILE=Path(__file__).resolve().parent/'one_manual_c320_ssh_read.py'
spec=importlib.util.spec_from_file_location('r934_ephemeral_manual_ssh',FILE)
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

class OneTimeLabReadSafety(unittest.TestCase):
 def test_requirements_without_any_network_or_credentials(self):
  p=subprocess.run([sys.executable,str(FILE),'--requirements'],capture_output=True,text=True,timeout=3)
  self.assertEqual(p.returncode,0)
  self.assertIn('HUMAN_INTERACTIVE_ONE_SHOT_LAB_ONLY',p.stdout)
  self.assertIn('"default_network_actions": 0',p.stdout)
  self.assertNotIn('zte:zte',p.stdout)
 def test_remote_noninteractive_auto_worker_cannot_login(self):
  env=os.environ.copy();env[M.AUTH]='YES'
  p=subprocess.run([sys.executable,str(FILE),'--one-manual-lab-read'],
                   input='',capture_output=True,text=True,env=env,timeout=3)
  self.assertEqual(p.returncode,4)
  self.assertIn('UNVERIFIED_NO_SECRET_OUTPUT',p.stderr)
 def test_actual_vendor_shaped_card_capture_is_bounded(self):
  s=b'show card\r\nRack Shelf Slot CfgType RealType Port HardVer SoftVer Status\r\n-----------\r\n1 1 1 GTGH GTGHK 16 V1.0.0 V2.1.0 INSERVICE\r\n'
  self.assertEqual(M.accept_one_actual_card_cli(s),s)
  for bad in (b'',b'invalid command',s+b'--More--',s+b'\x1b',s+b'\x00',b'A'*65537):
   with self.assertRaises(M.Refused):M.accept_one_actual_card_cli(bad)
 def test_owner_private_pin_blocks_link_and_world_readable(self):
  with tempfile.TemporaryDirectory(prefix='r934-only-test-') as tmp:
   p=Path(tmp)/'pin';p.write_text('synthetic-only');p.chmod(0o600)
   M.owner_private_file(p)
   p.chmod(0o644)
   with self.assertRaises(M.Refused):M.owner_private_file(p)
   p.unlink();p.symlink_to(Path(tmp)/'fake')
   with self.assertRaises((M.Refused,FileNotFoundError)):M.owner_private_file(p)
 def test_never_use_insecure_ssh_or_persistent_password(self):
  s=FILE.read_text()
  for exact in ('StrictHostKeyChecking=yes','NumberOfPasswordPrompts=1',
      'ClearAllForwardings=yes','getpass.getpass','os.umask(0o077)',
      'manual-one-read-result.json','credential_persisted'):
   self.assertIn(exact,s)
  for forbidden in ('StrictHostKeyChecking=no','sshpass','password="zte"',
                    'set_password','telnetlib','no username','save configuration'):
   self.assertNotIn(forbidden,s)
if __name__=='__main__':unittest.main()
