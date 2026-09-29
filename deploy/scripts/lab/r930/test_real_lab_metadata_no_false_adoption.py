"""R9.30 synthetic static regressions for actual authenticated LAB read reporting.

No live SSH/Telnet, no password/private key, no production enrollment.
"""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
class LiveFirstReadDisplayContracts(unittest.TestCase):
    def test_new_actual_first_read_metadata_does_not_rewrite_old_noauth_history(self):
        ev=json.loads((ROOT/'web/lab/physical-intake-evidence.json').read_text())
        self.assertFalse(ev['direct_private_vps_group14_actual_login_verified'])
        self.assertFalse(ev['credentials_sent'])
        actual=ev['r930_owner_lab_first_read']
        self.assertTrue(actual['user_attests_customer_disconnected_lab'])
        self.assertTrue(actual['treat_management_changes_as_live'])
        self.assertTrue(actual['temporary_telnet_authenticated_interactive'])
        self.assertTrue(actual['temporary_ssh_authenticated_interactive'])
        self.assertEqual(actual['observed_cards_insvc'],3)
        self.assertEqual(actual['observed_running_version_rows'],5)
        self.assertFalse(actual['raw_cli_captured_byte_exact'])
        self.assertFalse(actual['ssh_independent_chassis_identity_verified'])
        self.assertFalse(actual['private_operator_credential_rotated'])
        self.assertFalse(actual['independently_approved_scoped_worker_enabled'])
        self.assertFalse(actual['adopted'])
        self.assertEqual(actual['configuration_changes'],0)
    def test_real_lab_readiness_never_unlocks_a_live_hardware_action(self):
        src=(ROOT/'apps/control-api/src/c320_actions_lab.rs').read_text()
        for token in ('"real_device_authenticated":true',
                      '"model_and_firmware_read_from_real_hardware":true',
                      '"temporary_default_test_credential_needs_rotation":true',
                      '"independent_oob_olt_host_key_verified":false',
                      '"worker_enabled":false','"device_adopted":false',
                      '"production_auto_adoption_approved":false',
                      '"enabled":false','"can_run_on_live_device":false'):
            self.assertIn(token,src)
        for forbidden in ('sshpass','telnetlib','Command::new(','"enabled":true'):
            self.assertNotIn(forbidden,src)
        browser=(ROOT/'web/lab/device-workbench.js').read_text()
        self.assertIn('BELUM DIADOPSI',browser)
        self.assertIn('catalog.observed_lab_ssh_password_session_authenticated!==true',browser)
        self.assertIn('catalog.worker_enabled!==false',browser)
        self.assertIn("row.append(el('span','flag unknown','TERKUNCI')",browser)
        self.assertLessEqual(len(browser.encode()),32768)
    def test_only_approved_physical_read_metadata_and_no_secret_in_source(self):
        ev=(ROOT/'web/lab/physical-intake-evidence.json').read_text()
        r=(ROOT/'apps/control-api/src/c320_actions_lab.rs').read_text()
        self.assertNotIn('zte:zte',ev+r)
        self.assertNotIn('password_value',ev+r)
        self.assertIn('"lab_manual_successful_read_commands":5',r)
        self.assertIn('"lab_unsupported_read_command_rejected":1',r)
        self.assertIn('"actual_pram_running_mvr_not_reported":true',r)
        self.assertIn('"actual_firmware_filetype_alias_unresolved":true',r)
        self.assertIn('"firmware_write_enabled":false',
            (ROOT/'crates/olt-core/src/bin/olt-evidence.rs').read_text())
if __name__=='__main__':unittest.main()
