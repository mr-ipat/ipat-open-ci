"""Synthetic exact-target private C320 passive Telnet 323 regression."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

FILE=Path(__file__).resolve().parent/'private_telnet_323.py'
spec=importlib.util.spec_from_file_location('r928_exact_private_telnet',FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class FakeSocket:
    def __init__(self,answer):self.answer=answer;self.writes=0
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def settimeout(self,n):assert n<=2
    def recv(self,n):
        assert n<=512
        if isinstance(self.answer,BaseException):raise self.answer
        return self.answer
    def sendall(self,*args):raise AssertionError('never write ANY Telnet bytes')

class PassivePrivateTelnetTests(unittest.TestCase):
    def test_one_exact_private_target_iac_observed_without_any_writes(self):
        calls=[]
        def connect(endpoint,timeout):
            calls.append((endpoint,timeout));return FakeSocket(b'\xff\xfb\x01\xff\xfd\x18')
        r=m.probe(connector=connect)
        self.assertEqual(calls,[(('10.77.13.233',323),5)])
        self.assertTrue(r['tcp_reachable'])
        self.assertTrue(r['telnet_iac_observed'])
        self.assertEqual(r['bytes_received'],6)
        for key in ('credential_bytes_sent','telnet_option_responses_sent',
                    'olt_commands_executed','olt_configuration_changes'):
            self.assertEqual(r[key],0)
        for key in ('server_identity_verified','encrypted_transport',
                    'safe_for_password','physical_read_performed','device_adopted'):
            self.assertFalse(r[key])
    def test_tcp_only_or_no_banner_is_not_authenticated_olt(self):
        r=m.probe(connector=lambda _e,timeout:FakeSocket(b'Welcome to impersonator'))
        self.assertTrue(r['tcp_reachable'])
        self.assertFalse(r['telnet_iac_observed'])
        self.assertFalse(r['safe_for_password'])
        r=m.probe(connector=lambda _e,timeout:FakeSocket(socket.timeout()))
        self.assertTrue(r['tcp_reachable'])
        self.assertFalse(r['device_adopted'])
    def test_refusal_is_not_customer_health_fault(self):
        def refuse(*args,**kwargs):raise ConnectionRefusedError('synthetic')
        r=m.probe(connector=refuse)
        self.assertFalse(r['tcp_reachable'])
        self.assertEqual(r['failure_class'],'REFUSED')
        self.assertFalse(r['server_identity_verified'])
    def test_no_network_default_and_no_credentials_cli(self):
        environment=os.environ.copy();environment.pop(m.APPROVAL,None)
        r=subprocess.run([sys.executable,str(FILE),'--one-passive-check'],
            env=environment,capture_output=True,text=True,timeout=3)
        self.assertNotEqual(r.returncode,0)
        info=subprocess.check_output([sys.executable,str(FILE),'--requirements'],text=True)
        self.assertIn('"password_allowed": false',info)
        self.assertNotIn('10.77.13.233',info)
if __name__=='__main__':unittest.main()
