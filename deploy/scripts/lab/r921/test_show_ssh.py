"""Synthetic legacy ZTE CLI show ssh output, not actual DEV-01."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SRC=Path(__file__).resolve().parent/'inspect_show_ssh.py'
spec=importlib.util.spec_from_file_location('r921_show_ssh',SRC)
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
BASE='''ZXAN(config)#show ssh
SSH configuration:
SSH enable-flag configuration : enable
SSH version : ver2.0
SSH only configuration : disable
SSH init server key : not initialized
SSH auth mode : local
SSH auth type : pap
'''
class StrictOfflineLegacySshStatus(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='ipat-r921-synthetic-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()
        os.chmod(self.root,0o700)
        self.capture=self.root/'console-show-ssh.txt'
        self.capture.write_text(BASE)
        self.capture.chmod(0o600)
    def test_synthetic_uninitialized_key_triage_does_not_prove_live_cause(self):
        text,raw=M.owner_input(self.capture)
        value=M.analyze(text)
        self.assertEqual(value['ssh_version_reported'],'ver2.0')
        self.assertEqual(value['ssh_host_key_state_reported'],'not initialized')
        self.assertEqual(value['preauthentication_triage'],
                         'SSHV2_HOST_KEY_INITIALIZATION_FIELD_AMBIGUOUS')
        for flag in ('real_chassis_identity_verified','firmware_verified',
                     'live_ssh_config_changes_authorized','operational_read_enabled',
                     'device_adopted','real_olt_login_attempted'):
            self.assertIs(value[flag],False)
        self.assertEqual(value['network_packets_sent'],0)
        self.assertEqual(value['olt_commands_executed'],0)
        self.assertGreater(len(raw),100)
    def test_present_key_still_needs_other_kex_and_trust_diagnostics(self):
        case=BASE.replace('not initialized','initialized')
        value=M.analyze(case)
        self.assertEqual(value['preauthentication_triage'],
                         'HOST_KEY_REPORTED_PRESENT_KEX_STILL_NEEDS_DIAGNOSIS')
        self.assertFalse(value['ssh_host_key_from_physical_console_obtained'])
        self.assertFalse(value['device_adopted'])
    def test_historical_ssh2_disable_field_is_ambiguous_not_proof_of_broken_key(self):
        sample=BASE.replace('not initialized','disable')
        result=M.analyze(sample)
        self.assertEqual(result['preauthentication_triage'],
                         'SSHV2_HOST_KEY_INITIALIZATION_FIELD_AMBIGUOUS')
        self.assertIs(result['live_ssh_config_changes_authorized'],False)
        self.assertIs(result['device_adopted'],False)

    def test_duplicates_unsafe_text_and_world_readable_capture_denied(self):
        with self.assertRaises(M.Denied):M.analyze(BASE+'SSH version : ver2.0\n')
        with self.assertRaises(M.Denied):M.analyze(BASE.replace('ver2.0','unknown'))
        with self.assertRaises(M.Denied):M.analyze(BASE.replace('SSH configuration:', 'Unknown configuration:'))
        self.capture.chmod(0o644)
        with self.assertRaises(M.Denied):M.owner_input(self.capture)
        self.capture.chmod(0o600)
        self.capture.write_text(BASE+'\npassword : unauthorized\n')
        with self.assertRaises(M.Denied):M.owner_input(self.capture)
    def test_disabled_server_never_authorizes_remediation(self):
        text=BASE.replace('SSH enable-flag configuration : enable',
                          'SSH enable-flag configuration : disable')
        value=M.analyze(text)
        self.assertEqual(value['preauthentication_triage'],'SSH_DAEMON_REPORTED_DISABLED')
        self.assertIs(value['site_security_review_required'],True)
        self.assertIs(value['live_ssh_config_changes_authorized'],False)
if __name__=='__main__':unittest.main()
