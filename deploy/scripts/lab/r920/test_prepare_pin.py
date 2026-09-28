import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SRC=Path(__file__).resolve().parent/'prepare_pin.py'
spec=importlib.util.spec_from_file_location('r920_prepare_pin',SRC)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class OperatorOfflinePinTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ipat-r920-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        os.chmod(self.root,0o700)
        self.input=self.root/'console';self.input.mkdir(mode=0o700)
        self.output=self.root/'pin';self.output.mkdir(mode=0o700)
        self.key=self.input/'host_rsa.pub'
        private=self.input/'synthetic_host'
        subprocess.run(['ssh-keygen','-q','-t','rsa','-b','2048','-N','',
           '-f',str(private)],check=True,capture_output=True,timeout=6)
        self.key.write_bytes(private.with_suffix('.pub').read_bytes())
        self.key.chmod(0o600)
        private.unlink()
        private.with_suffix('.pub').unlink()
        self.expected=mod.compute_fp(self.key) if hasattr(mod,'compute_fp') else subprocess.run(
          ['ssh-keygen','-lf',str(self.key)],capture_output=True,text=True,check=True).stdout.split()[1]
        self.old_obs=mod.verify_mod.OBSERVATION
        obs=self.root/'fake-observation.json'
        obs.write_text(json.dumps({'target_slot':'DEV-01','device_adopted':False,
          'out_of_band_host_key_verified':False,'observed_rsa_fingerprint':self.expected}))
        mod.verify_mod.OBSERVATION=obs
        self.addCleanup(lambda:setattr(mod.verify_mod,'OBSERVATION',self.old_obs))
    def test_owner_asserted_matching_rsa_outputs_private_pin_but_never_adopts(self):
        r=mod.render_pin(self.key,self.output,'192.168.77.10',321)
        pin=self.output/'known_hosts'
        self.assertEqual(stat.S_IMODE(pin.stat().st_mode),0o600)
        self.assertTrue(pin.read_text().startswith('[192.168.77.10]:321 ssh-rsa '))
        self.assertEqual(r['result'],'OWNER_ASSERTED_CONSOLE_RSA_MATCHES_HISTORICAL_NETWORK')
        for field in ('independent_provenance_cryptographically_verified',
          'independent_reviewer_approved','restricted_device_account_verified',
          'tenant_mfa_verified','physical_read_permitted','device_adopted'):
            self.assertIs(r[field],False)
        self.assertEqual(r['olt_commands_executed'],0)
        self.assertEqual(r['network_packets_sent'],0)
        with self.assertRaises(mod.Denied):
            mod.render_pin(self.key,self.output,'192.168.77.10',321)
    def test_mismatch_denied_without_any_output(self):
        fake=self.root/'fake.json'
        fake.write_text(json.dumps({'target_slot':'DEV-01','device_adopted':False,
          'out_of_band_host_key_verified':False,
          'observed_rsa_fingerprint':'SHA256:'+'A'*43}))
        mod.verify_mod.OBSERVATION=fake
        with self.assertRaises(mod.Denied):
            mod.render_pin(self.key,self.output,'192.168.77.10',321)
        self.assertEqual(list(self.output.iterdir()),[])
    def test_rejects_bad_permissions_and_wrong_address(self):
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            mod.render_pin(self.key,self.output,'192.168.77.10',321)
        self.key.chmod(0o600)
        with self.assertRaises(mod.Denied):
            mod.render_pin(self.key,self.output,'8.8.8.8',321)
        self.assertEqual(list(self.output.iterdir()),[])
if __name__=='__main__':unittest.main()
