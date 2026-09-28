"""Offline unit tests for route-table-only, zero-packet negative gate."""
import importlib.util
from pathlib import Path
import subprocess
import unittest

P=Path(__file__).with_name('verify_restricted_private_route.py')
sp=importlib.util.spec_from_file_location('route_gate',P)
M=importlib.util.module_from_spec(sp);sp.loader.exec_module(M)
IP='10.77.13.233'

class RouteGateTests(unittest.TestCase):
    def test_actual_vps_pattern_default_is_not_verified(self):
        result=M.parse(IP,[{'dst':IP,'gateway':'10.0.0.1','dev':'eth0'}],
                       [{'dst':'default','gateway':'10.0.0.1','dev':'eth0'}])
        self.assertEqual(result['route_candidate'],'DEFAULT_ROUTE_ONLY')
        self.assertFalse(result['isolated_management_route_verified'])
        self.assertEqual(result['network_packets_sent'],0)
    def test_other_routes_also_require_independent_proof(self):
        result=M.parse(IP,[{'dst':IP,'gateway':'10.100.2.1','dev':'wg-ipat'}],
                       [{'dst':'default','gateway':'10.0.0.1','dev':'eth0'}])
        self.assertEqual(result['route_candidate'],'NONDEFAULT_ROUTE_REQUIRES_PROOF')
        self.assertFalse(result['isolated_management_route_verified'])
    def test_rejects_wrong_ip_public_empty_missing_interface(self):
        for ip,route in [('198.51.100.109',[]),(IP,[]),(IP,[{'dst':'10.77.13.234'}])]:
            with self.assertRaises(ValueError): M.parse(ip,route,[])
        with self.assertRaises(ValueError):M.parse(IP,[{'dst':IP}],[])
    def test_exact_two_local_route_calls_without_packets(self):
        calls=[]
        def fake(cmd,**kwargs):
            calls.append(cmd)
            value=('[{"dst":"10.77.13.233","gateway":"10.0.0.1","dev":"eth0"}]'
                   if 'get' in cmd else
                   '[{"dst":"default","gateway":"10.0.0.1","dev":"eth0"}]')
            return subprocess.CompletedProcess(cmd,0,value,'')
        outcome=M.inspect(IP,fake)
        self.assertEqual(outcome['route_candidate'],'DEFAULT_ROUTE_ONLY')
        self.assertEqual(calls,[['ip','-j','-4','route','get',IP],
                                ['ip','-j','-4','route','show','default']])
        self.assertNotIn('ping',P.read_text())
        self.assertNotIn('ssh ',P.read_text())

if __name__=='__main__':unittest.main()

class PrivatePhysicalCandidateUnit(unittest.TestCase):
    def test_replacement_user_unit_cannot_open_real_device_actions(self):
        root=Path(__file__).resolve().parents[4]
        unit=(root/'deploy/scripts/lab/r913/ipat-r911-preview.service').read_text()
        smoke=(root/'deploy/scripts/lab/r913/actual_lab_physical_candidate_http_smoke.py').read_text()
        for safe in ('IPAT_LAB_WEB=1','IPAT_R911_PRIVATE_CANARY=YES',
                     'IPAT_RUN_K3S_LAB=0','IPAT_LAB_OIDC_VERIFY=NO',
                     'NoNewPrivileges=yes','MemoryMax=256M','CPUQuota=20%',
                     '/home/openai/.cache/ipat/r913-preview/target/debug/control-api'):
            self.assertIn(safe,unit)
        for forbidden in ('User=root','ExecStartPre','iptables','nft ',
                          'IPAT_R83_REGISTRY_WRITE=YES'):
            self.assertNotIn(forbidden,unit)
        for marker in ('OBSERVED_NOT_ADOPTED','DEFAULT_ROUTE_ONLY',
                       'physical-observed-row','/v1/devices/DEV-01',
                       'actual_worker_private_route_verified'):
            self.assertIn(marker,smoke)
