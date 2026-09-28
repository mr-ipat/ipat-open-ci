"""No-device tests: the temporary Mac owner SSH relay never saves keys."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r913_relay',HERE/'temporary_mac_relay_noauth.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
IP='10.77.13.233'

class TemporaryRelayTests(unittest.TestCase):
    def test_no_public_ip_untrusted_host_or_invalid_port(self):
        self.assertEqual(M.approved_target(IP,321),IP)
        for value in ('198.51.100.109','127.0.0.1','localhost','::1','10.1.2.3;rm'):
            with self.assertRaises(ValueError):M.approved_target(value,321)
        for port in (0,65536,True):
            with self.assertRaises(ValueError):M.approved_target(IP,port)
    def test_reverse_socket_is_owner_only_not_public_or_credentialed(self):
        socket='/home/openai/.cache/ipat/r913-preview/test.sock'
        args=M.relay_args(IP,321,socket)
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn('BatchMode=yes',args)
        self.assertIn('ExitOnForwardFailure=yes',args)
        self.assertIn(socket+':'+IP+':321',args)
        self.assertNotIn('0.0.0.0',str(args))
        self.assertNotIn('password',str(args).lower())
    def test_denied_without_optin_never_invokes_ssh(self):
        with patch.object(M,'perform',side_effect=AssertionError('network forbidden')):
            with patch.dict(M.os.environ,{},clear=True):
                with patch.object(M.sys,'argv',['probe','--probe','--private-ipv4',IP,'--port','321']):
                    with self.assertRaises(SystemExit) as denied:
                        M.main()
                    self.assertEqual(denied.exception.code,2)

class OneShotCleanup(unittest.TestCase):
    def test_exact_one_recv_then_reverse_tunnel_stops_and_cleans(self):
        calls=[];relay=[]
        class Bridge:
            stopped=False
            def poll(self): return None
            def terminate(self):self.stopped=True
            def wait(self,timeout):return 0
        b=Bridge()
        def fake_run(argv,**kwargs):
            calls.append(argv[-1]);command=argv[-1]
            if command.startswith('python3 -c '):
                value=dict(ssh_transport_observed=True,
                           zte_ssh_banner_observed=True,bytes_received=20,
                           credentials_sent=False,olt_commands_executed=0,
                           device_adopted=False,trusted_last_hop_verified=False,
                           long_lived_worker_route_verified=False)
                return subprocess.CompletedProcess(argv,0,json.dumps(value),'')
            return subprocess.CompletedProcess(argv,0,'','')
        def fake_popen(argv,**kwargs):relay.append(argv);return b
        with patch.object(M.uuid,'uuid4') as uid:
            uid.return_value.hex='a'*32
            result=M.perform(IP,321,run=fake_run,popen=fake_popen)
        self.assertTrue(result['ssh_transport_observed'])
        self.assertFalse(result['device_adopted'])
        self.assertEqual(result['olt_commands_executed'],0)
        self.assertEqual(len(relay),1)
        self.assertEqual(sum('python3 -c ' in call for call in calls),1)
        self.assertTrue(calls[-1].startswith('rm -f '))
        self.assertTrue(b.stopped)
    def test_failed_cleanup_is_denied_not_reported_as_success(self):
        class Bridge:
            def poll(self):return None
            def terminate(self):pass
            def wait(self,timeout):return 0
        def fail_cleanup(argv,**kwargs):
            cmd=argv[-1]
            if cmd.startswith('rm -f '):return subprocess.CompletedProcess(argv,1,'','')
            if cmd.startswith('python3 -c '):
                return subprocess.CompletedProcess(argv,0,json.dumps(dict(
                    credentials_sent=False,olt_commands_executed=0,
                    device_adopted=False,long_lived_worker_route_verified=False)),'')
            return subprocess.CompletedProcess(argv,0,'','')
        with self.assertRaisesRegex(ValueError,'cleanup unverified'):
            M.perform(IP,321,run=fail_cleanup,popen=lambda *a,**kw:Bridge())
