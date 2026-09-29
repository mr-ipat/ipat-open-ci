"""Synthetic-only private C320 site evidence intake regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

P=Path(__file__).resolve().parent/'assess_site_packet.py'
spec=importlib.util.spec_from_file_location('r926_site_packet',P)
M=importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
SSH='''ZXAN(config)#show ssh
SSH configuration:
SSH enable-flag configuration : enable
SSH version : ver2.0
SSH only configuration : disable
SSH init server key : not initialized
SSH auth mode : local
SSH auth type : pap
'''
CARDS='''ZXAN#show card
Rack Shelf Slot CfgType RealType Port HardVer SoftVer Status
-------------------------
1 1 1 ETGO ETGOD 8 091201 V1.2.5P2 INSERVICE
'''
VERSIONS='''ZXAN#show version-running
PhyLoc FileType VerType VerTag BuildTime VerLength
-------------------------
1/1/1 ETGO MVR V1.2.5P2 2013-08-27 23:36:54 5008113
'''
class OfflineIntakeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='ipat-r926-synthetic-')
  self.addCleanup(self.temp.cleanup)
  self.folder=Path(self.temp.name).resolve()
  os.chmod(self.folder,0o700)
 def write(self,name,content):
  p=self.folder/name
  p.write_text(content)
  os.chmod(p,0o600)
  return p
 def test_realistic_current_owner_only_plan_never_promotes(self):
  self.write('plan.json','{}\n')
  record=M.classify(self.folder)
  self.assertEqual(record['site_files_present'],['plan.json'])
  self.assertFalse(record['device_adopted'])
  self.assertFalse(record['actual_chassis_identity_independently_verified'])
  self.assertEqual(record['network_packets_sent_by_tool'],0)
  self.assertIn('INDEPENDENT_PHYSICAL_CHASSIS_RSA_PUBLIC_KEY',record['outstanding'])
  self.assertIn('DEDICATED_RESTRICTED_ROLE_ACTUALLY_PROVEN',record['outstanding'])
 def test_even_all_synthetic_captures_cannot_become_real_adoption(self):
  self.write('show-ssh.txt',SSH)
  self.write('cards.txt',CARDS)
  self.write('versions.txt',VERSIONS)
  record=M.classify(self.folder)
  self.assertIn('SSHV2_HOST_KEY_INITIALIZATION_FIELD_AMBIGUOUS',
                record['verified_offline_properties']['ssh_server_key_status_interpretation'])
  self.assertFalse(record['device_adopted'])
  self.assertFalse(record['actual_restricted_role_verified'])
  self.assertFalse(record['live_baseline_verified'])
  self.assertEqual(record['physical_olt_commands_executed_by_tool'],0)
  self.assertIn('INDEPENDENT_PHYSICAL_CHASSIS_RSA_PUBLIC_KEY',record['outstanding'])
 def test_private_synthetic_rsa_match_is_owner_assertion_not_independent_proof(self):
  key=self.folder/'fixture'
  result=subprocess.run(['ssh-keygen','-q','-t','rsa','-b','2048','-N','',
                         '-f',str(key)],capture_output=True,timeout=8)
  self.assertEqual(result.returncode,0)
  pub=key.with_suffix('.pub').read_text()
  key.unlink();key.with_suffix('.pub').unlink()
  self.write('console-host-rsa.pub',pub)
  observed=subprocess.run(['ssh-keygen','-lf',str(self.folder/'console-host-rsa.pub')],
                          capture_output=True,text=True,check=True).stdout.split()[1]
  old=M.keymod.OBSERVATION
  obs=self.folder/'outside-observation.json'
  obs.write_text(json.dumps({'target_slot':'DEV-01','device_adopted':False,
    'out_of_band_host_key_verified':False,'observed_rsa_fingerprint':observed}))
  # Test mocks observation source; no real RSA/proof or network involved.
  M.keymod.OBSERVATION=obs
  self.addCleanup(lambda:setattr(M.keymod,'OBSERVATION',old))
  # Mock observation file is not part of operator evidence folder in production.
  obs.unlink();obs=self.folder.parent/(self.folder.name+'-synthetic-observation.json')
  obs.write_text(json.dumps({'target_slot':'DEV-01','device_adopted':False,
    'out_of_band_host_key_verified':False,'observed_rsa_fingerprint':observed}))
  self.addCleanup(lambda:obs.unlink(missing_ok=True))
  M.keymod.OBSERVATION=obs
  record=M.classify(self.folder)
  self.assertTrue(record['verified_offline_properties'][
     'owner_claimed_console_rsa_matches_historical_network_key'])
  self.assertIn('INDEPENDENT_CONSOLE_SOURCE_AND_REVIEWER_ATTESTATION',record['outstanding'])
  self.assertFalse(record['device_adopted'])
  self.assertFalse(record['actual_chassis_identity_independently_verified'])
 def test_rejects_wrong_owner_mode_extra_file_symlink_and_control_chars(self):
  self.write('cards.txt',CARDS)
  self.write('show-ssh.txt',SSH)
  self.write('versions.txt',VERSIONS)
  self.folder.joinpath('extra-key').write_text('junk')
  with self.assertRaises(M.Denied):M.classify(self.folder)
  self.folder.joinpath('extra-key').unlink()
  (self.folder/'console-host-rsa.pub').symlink_to(self.folder/'cards.txt')
  with self.assertRaises(M.Denied):M.classify(self.folder)
  (self.folder/'console-host-rsa.pub').unlink()
  self.folder.chmod(0o755)
  with self.assertRaises(M.Denied):M.classify(self.folder)
  self.folder.chmod(0o700)
  self.folder.joinpath('cards.txt').chmod(0o644)
  self.assertIn('UNSAFE_CARDS_TXT',M.classify(self.folder)['outstanding'])
  self.folder.joinpath('cards.txt').chmod(0o600)
  self.write('cards.txt',CARDS+'\x1b[0m')
  self.assertIn('UNSAFE_CARDS_TXT',M.classify(self.folder)['outstanding'])
 def test_no_false_accepted_actual_capture_if_header_missing(self):
  self.write('cards.txt','ZXAN#invalid\n')
  r=M.classify(self.folder)
  self.assertIn('UNSAFE_CARDS_TXT',r['outstanding'])
  self.assertNotIn('cards_txt_sha256',r['verified_offline_properties'])
if __name__=='__main__':unittest.main()
