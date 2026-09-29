"""Synthetic/static fail-closed acceptance of factual R933 private LAB snapshot."""
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[4]
class ActualBackupHistoricCatalog(unittest.TestCase):
 def test_new_owner_provenance_keeps_unverified_device_role_and_restore_blocked(self):
  p=json.loads((ROOT/'web/lab/physical-intake-evidence.json').read_text())
  proof=p['r933_owner_off_vps_recovery']
  assert proof['actual_encrypted_off_vps_restic_snapshot_verified'] is True
  assert proof['actual_isolated_restic_reference_byte_restore_identical'] is True
  assert proof['actual_vendor_native_config_import_verified'] is False
  assert proof['actual_hardware_recovery_drill_passed'] is False
  assert proof['actual_privilege_15_accounts_observed']==2
  assert proof['actual_restricted_device_identity_proven'] is False
  assert proof['actual_current_alarms_semantically_validated'] is False
  assert proof['real_saas_auto_adopted'] is False
  assert proof['actual_device_config_writes_this_milestone']==0
  self.assertFalse(p['device_adopted'])
 def test_historic_first_real_inventory_never_becomes_telemetry(self):
  s=(ROOT/'apps/control-api/src/c320_actions_lab.rs').read_text()
  for line in ('"verified_off_vps_encrypted_running_cli_reference_backup":true',
   '"verified_mac_restic_isolated_byte_identical_restore":true',
   '"vendor_native_startup_config_restore_tested":false',
   '"actual_local_account_privilege15_count":2',
   '"actual_local_restricted_account_proven":false',
   '"observed_lab_ssh_password_session_authenticated":true',
   '"device_adopted":false',
   '"production_auto_adoption_approved":false',
   '"raw_captures_private_only":true',
   '"observation_is_live":false'):
   self.assertIn(line,s,line)
  self.assertIn('get(super::c320_actions_lab::first_read)',
   (ROOT/'apps/control-api/src/device_workbench_lab.rs').read_text())
 def test_public_html_and_js_show_genuine_historical_hardware_not_running_poll(self):
  html=(ROOT/'web/lab/device-workbench.html').read_text()
  js=(ROOT/'web/lab/c320-first-real-inventory.js').read_text()
  self.assertIn('/lab/c320-first-real-inventory.js',html)
  self.assertIn('c320-real-inventory-status',html)
  self.assertIn("r.observation_is_live!==false",js)
  self.assertIn('r.real_saas_device_adopted!==false',js)
  self.assertIn('output.replaceChildren()',js)
  self.assertNotIn('zte:zte',js+html)
  self.assertNotIn('10.77.13.233',js+html)
  self.assertLess(len(js.encode()),5000)
if __name__=='__main__':unittest.main()
