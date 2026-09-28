"""Lab-only no-device central Site A connection decision tests."""
import importlib.util
import base64
import sys
import json
import subprocess
import tempfile
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('site_a_plan',
    Path(__file__).with_name('site_a_plan.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
P = module
sys.path.insert(0,str(Path(__file__).resolve().parent))
from pairing_bundle_review import render, public_key
AKEY=base64.b64encode(b'A'*32).decode()
BKEY=base64.b64encode(b'B'*32).decode()

BASE = {'mode':'wireguard', 'site_a_endpoint':'198.51.100.9',
    'site_b_gateway':'routeros7','management_host':'192.168.77.10',
    'vpn_subnet':'10.253.77.0/30', 'site_a_networks':['10.99.0.0/24'],
    'site_b_networks':['192.168.77.0/24'],
    'private_path_verified':False, 'site_b_recovery_verified':False}

class HubSpokeTests(unittest.TestCase):
    def test_public_hub_is_spoke_self_configuration_only(self):
        result=P.review(BASE)
        self.assertEqual(result['site_a_endpoint_kind'],'PUBLIC')
        self.assertEqual(result['site_a_role'],'CENTRAL_HUB_LISTENER')
        self.assertEqual(result['site_b_role'],'SELF_CONFIGURED_SPOKE')
        self.assertFalse(result['router_push_enabled'])
        self.assertFalse(result['config_generated'])
        self.assertFalse(result['device_adopted'])
        self.assertEqual(result['network_actions'],0)
        self.assertEqual(result['target_host_route'],'192.168.77.10/32')
    def test_real_verified_same_private_network_no_tunnel_required(self):
        data=dict(BASE,mode='direct_private',site_a_endpoint='10.99.0.10',
                  private_path_verified=True)
        result=P.review(data)
        self.assertEqual(result['site_a_endpoint_kind'],'PRIVATE')
        self.assertEqual(result['link_mode'],'direct_private')
        self.assertEqual(result['site_a_role'],'EXISTING_PRIVATE_SITE_A_NO_TUNNEL')
        self.assertEqual(result['site_b_role'],'EXISTING_PRIVATE_SITE_B_NO_TUNNEL')
    def test_unverified_private_hub_cannot_be_external_endpoint(self):
        with self.assertRaises(ValueError):
            P.review(dict(BASE,site_a_endpoint='10.99.0.10'))
        with self.assertRaises(ValueError):
            P.review(dict(BASE,mode='direct_private'))
    def test_no_secrets_or_network_overlap_or_false_gateway(self):
        for data in (dict(BASE,password='forbidden'),
                     dict(BASE,vpn_subnet='192.168.77.0/30'),
                     dict(BASE,site_b_gateway='routeros6'),
                     dict(BASE,management_host='8.8.8.8'),
                     dict(BASE,site_a_endpoint='127.0.0.1'),
                     dict(BASE,site_a_endpoint='224.0.0.1'),
                     dict(BASE,site_a_existing_networks=[123]),
                     dict(BASE,private_path_verified='yes'),
                     dict(BASE,site_b_networks=['10.99.0.0/24','192.168.77.0/24'])):
            with self.subTest(data=data):
                with self.assertRaises((ValueError,TypeError)):
                    P.review(data)
    def test_ipsec_not_claimed_implemented(self):
        result=P.review(dict(BASE,mode='ipsec'))
        self.assertEqual(result['state'],'REVIEW_ONLY')
        self.assertFalse(result['router_push_enabled'])

class SiteADashboardContracts(unittest.TestCase):
    def test_nonroot_user_unit_preserves_private_listener_and_demo_only(self):
        root=Path(__file__).resolve().parents[4]
        unit=(root/'deploy/scripts/lab/r915/ipat-r911-preview.service').read_text()
        smoke=(root/'deploy/scripts/lab/r915/actual_lab_hub_http_smoke.py').read_text()
        for expected in ('/home/openai/.cache/ipat/r915-preview/target/debug/control-api',
                         'IPAT_LAB_WEB=1','IPAT_R911_PRIVATE_CANARY=YES',
                         'IPAT_RUN_K3S_LAB=0','IPAT_LAB_OIDC_VERIFY=NO',
                         'NoNewPrivileges=yes','ProtectSystem=strict',
                         'MemoryMax=256M','CPUQuota=20%'):
            self.assertIn(expected,unit)
        for unsafe in ('User=root','ExecStartPre','iptables','nft ',
                       '0.0.0.0:3002','IPAT_R83_REGISTRY_WRITE=YES'):
            self.assertNotIn(unsafe,unit)
        self.assertIn("actual_listeners=subprocess.check_output(['ss','-lnt']",smoke)
        for marker in ('PUBLIC_HUB_WG_SITE_B_INITIATES','PRIVATE_HUB_WG_SITE_B_INITIATES',
                       'SITE_OPERATOR_SELF_CONFIGURES_NO_PUSH','router_push_enabled',
                       'direct_private_vps_ssh_transport_observed'):
            self.assertIn(marker,smoke)

    def test_nonroot_actual_private_preview_upgrade_has_strict_rollback(self):
        root=Path(__file__).resolve().parents[4]
        deploy=(root/'deploy/scripts/lab/r915/deploy_private_preview.sh').read_text()
        for marker in ('IPAT_R915_APPROVE_PRIVATE_PREVIEW','test "$(id -un)" = openai',
                       'trap rollback ERR','rollback-unit.service',
                       'IPAT_R915_LAB_HTTP_SMOKE=YES',
                       'a236e184e8c0e6abaa0feda9095dfb5c2d3e56fd00f343eef61e668d3c41eaa9'):
            self.assertIn(marker,deploy)
        for forbidden in ('sudo ', 'iptables ', 'nft ', 'ufw ',
                          'systemctl restart ssh','wg-quick up','ssh 10.'):
            self.assertNotIn(forbidden,deploy)

    def test_hub_dashboard_and_backend_are_paired_and_no_push(self):
        root=Path(__file__).resolve().parents[4]
        html=(root/'web/lab/device-workbench.html').read_text()
        js=(root/'web/lab/device-workbench.js').read_text()
        rust=(root/'apps/control-api/src/device_workbench_lab.rs').read_text()
        for marker in ('site-a-hub-panel','hub-method','hub-address-scope',
                       'site-b-path','site-b-gateway','check-site-a-plan'):
            self.assertIn(marker,html)
        for marker in ('/lab/demo/site-a-plan','router_push_enabled!==false',
                       'site_path_independently_verified!==false',
                       'IPAT_CENTRAL_CONFIGURATION_AUTHORITY',
                       'SITE_OPERATOR_SELF_CONFIGURES_NO_PUSH'):
            self.assertIn(marker,js)
        self.assertIn('async fn preview_site_a_plan(',rust)
        self.assertIn('r915_hub_is_site_a_and_never_pushes_to_site_b',rust)
        self.assertIn('\"router_push_enabled\":false',rust)
        self.assertIn('\"network_actions\":0',rust)

class ManualSiteBPairingBundleTests(unittest.TestCase):
    def test_approved_topology_only_generates_disabled_operator_package(self):
        result=render(BASE,'lab-a',AKEY,BKEY,51820)
        self.assertEqual(result['mode'],'NONEXECUTABLE_PAIRING_REVIEW')
        self.assertFalse(result['router_push_enabled'])
        self.assertFalse(result['config_applied'])
        self.assertEqual(result['network_actions'],0)
        self.assertFalse(result['device_adopted'])
        self.assertEqual(result['site_a_management_route'],'192.168.77.10/32')
        self.assertEqual(result['site_b_peer_allowed_ips'],['10.253.77.1/32'])
        self.assertEqual(result['site_a_peer_allowed_ips'],['10.253.77.2/32','192.168.77.10/32'])
        lines=result['site_b_routeros_disabled_review_commands']
        self.assertEqual(len(lines),3)
        self.assertTrue(all('disabled=yes' in line for line in lines))
        self.assertIn('endpoint-address=198.51.100.9',lines[2])
        self.assertIn('public-key="'+AKEY+'"',lines[2])
        self.assertNotIn(BKEY,' '.join(lines))
        self.assertNotIn('0.0.0.0/0',str(result))
        self.assertNotIn('private-key=',str(result))
    def test_only_real_site_owner_keypair_can_be_inserted_and_must_be_distinct(self):
        with self.assertRaises(ValueError):public_key('bad')
        with self.assertRaises(ValueError):public_key(base64.b64encode(bytes(32)).decode())
        with self.assertRaises(ValueError):render(BASE,'lab-a',AKEY,AKEY,51820)
        with self.assertRaises(ValueError):render(BASE,'unsafe / name',AKEY,BKEY,51820)
        with self.assertRaises(ValueError):render(BASE,'lab-a',AKEY,BKEY,80)
        with self.assertRaises(ValueError):render(dict(BASE,mode='ipsec'),'lab-a',AKEY,BKEY,51820)
        with self.assertRaises(ValueError):render(dict(BASE,site_b_gateway='linux'),'lab-a',AKEY,BKEY,51820)
    def test_direct_verified_path_requires_no_vpn_package(self):
        data=dict(BASE,mode='direct_private',site_a_endpoint='10.99.0.10',
                  private_path_verified=True)
        result=render(data,'lab-a','','',51820)
        self.assertEqual(result['mode'],'DIRECT_PRIVATE_NO_PAIRING')
        self.assertFalse(result['router_push_enabled'])
        self.assertFalse(result['config_generated'])
    def test_static_preview_never_calls_ssh_or_firewall(self):
        source=Path(__file__).with_name('pairing_bundle_review.py').read_text()
        for forbidden in ('subprocess','paramiko','iptables','wg set','ip route add',
                          'RouterOS API','ssh '):
            self.assertNotIn(forbidden,source)

class PrivateTopologyInputFileTests(unittest.TestCase):
    def test_operator_only_topology_cli_enforces_0600_and_no_secret_fields(self):
        with tempfile.TemporaryDirectory(prefix='ipat-r915-') as folder:
            path=Path(folder)/'topology.json'
            path.write_text(json.dumps(BASE));path.chmod(0o600)
            script=Path(__file__).with_name('site_a_plan.py')
            command=[sys.executable,str(script),'--local-reviewed-topology-json',str(path)]
            result=subprocess.run(command,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            parsed=json.loads(result.stdout)
            self.assertEqual(parsed['network_actions'],0)
            self.assertFalse(parsed['device_adopted'])
            path.chmod(0o644)
            denied=subprocess.run(command,text=True,capture_output=True)
            self.assertEqual(denied.returncode,2)
            self.assertEqual(denied.stdout,'')
            path.chmod(0o600)
            path.write_text(json.dumps(dict(BASE,password='FORBIDDEN')))
            denied=subprocess.run(command,text=True,capture_output=True)
            self.assertEqual(denied.returncode,2)
            self.assertEqual(denied.stdout,'')

if __name__=='__main__': unittest.main()
