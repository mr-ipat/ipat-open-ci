import importlib.util
from pathlib import Path
import unittest
SRC=Path(__file__).resolve().parent/'plan_ssh_remediation.py'
spec=importlib.util.spec_from_file_location('r923_plan',SRC)
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
BASE='''ZXAN(config)#show ssh
SSH configuration:
SSH enable-flag configuration : enable
SSH version : ver2.0
SSH only configuration : disable
SSH init server key : initialized
SSH auth mode : local
SSH auth type : pap
'''
class OnSiteNoNetworkChangePlanTests(unittest.TestCase):
    def check_unapplied(self,record):
        self.assertEqual(record['physical_commands_sent'],0)
        self.assertEqual(record['configuration_commands_executed'],[])
        self.assertEqual(record['network_packets_sent'],0)
        self.assertIs(record['device_adopted'],False)
        self.assertIs(record['service_baseline_compared'],False)
        self.assertIs(record['independent_reviewer_signed'],False)
        self.assertIs(record['actual_olt_login_verified'],False)
        self.assertEqual(record['client_only_working_profile']['kex'],
                         'diffie-hellman-group14-sha256')
    def test_verified_reported_v2_enabled_prefers_no_olt_change(self):
        r=M.create_plan(BASE,BASE.encode())
        self.check_unapplied(r)
        self.assertEqual(r['decision'],'CLIENT_COMPATIBILITY_SUFFICIENT_DO_NOT_CHANGE_OLT_SSH')
        self.assertEqual(r['proposed_config_cli_requires_site_console_and_change_approval'],[])
        self.assertNotIn('ssh server generate-key',str(r))
    def test_disabled_report_only_proposes_enable_never_executes(self):
        r=M.create_plan(BASE.replace('configuration : enable','configuration : disable'),BASE.encode())
        self.check_unapplied(r)
        self.assertEqual(r['proposed_config_cli_requires_site_console_and_change_approval'],
                         ['ssh server enable'])
    def test_ssh1_report_proposes_only_version2(self):
        r=M.create_plan(BASE.replace('ver2.0','ver1.0'),BASE.encode())
        self.check_unapplied(r)
        self.assertEqual(r['proposed_config_cli_requires_site_console_and_change_approval'],
                         ['ssh server version 2'])
    def test_ssh2_uninitialized_key_no_blind_regenerate(self):
        r=M.create_plan(BASE.replace('initialized','not initialized'),BASE.encode())
        self.check_unapplied(r)
        self.assertEqual(r['decision'],'NO_AUTOMATIC_SERVER_KEY_GENERATION_FOR_SSHV2')
        self.assertEqual(r['proposed_config_cli_requires_site_console_and_change_approval'],[])
if __name__=='__main__':unittest.main()
