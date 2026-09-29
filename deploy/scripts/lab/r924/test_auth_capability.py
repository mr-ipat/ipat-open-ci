import importlib.util
from pathlib import Path
import unittest
src=Path(__file__).resolve().parent/'auth_capability.py'
spec=importlib.util.spec_from_file_location('r924_auth_capability',src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestActualAuthMethodDiscoveries(unittest.TestCase):
    def test_actual_noauth_password_offer_does_not_support_key_only_collector(self):
        x=m.evaluate('password')
        self.assertEqual(x['observed_methods'],['password'])
        self.assertIs(x['key_only_collector_compatible_with_observed_account'],False)
        self.assertIs(x['manual_password_supported_by_observed_account'],True)
        self.assertIs(x['actual_olt_authenticated'],False)
        self.assertIs(x['physical_read_eligible'],False)
        self.assertIs(x['device_adopted'],False)
        self.assertEqual(x['olt_commands_executed'],0)
    def test_proof_flags_never_claim_authenticated_or_adopted(self):
        x=m.evaluate('password',True,True,True,True)
        self.assertIs(x['physical_read_eligible'],True)
        self.assertIs(x['physical_read_dispatched'],False)
        self.assertIs(x['actual_olt_authenticated'],False)
        self.assertIs(x['device_adopted'],False)
    def test_key_auth_is_conditional_on_actual_server_offer(self):
        x=m.evaluate('publickey,password')
        self.assertIs(x['key_only_collector_compatible_with_observed_account'],True)
        self.assertIs(x['physical_read_eligible'],False)
    def test_rejects_untrusted_or_malformed_server_method_claims(self):
        for sample in ('password,password','password;reboot','', 'none',
                       'password,' ,['password']):
            with self.subTest(sample=sample):
                with self.assertRaises(ValueError):m.evaluate(sample)
if __name__=='__main__':unittest.main()
