"""Actual owner-only local Site A/B pairing with synthetic B PUBLIC key only.
Requires cryptography. Run nonroot, no real router connection or listener.
"""
import base64
import json
import tempfile
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric import x25519
import reconcile_site_a_pairing as R
from site_a_keypair import create,public_from_folder

SYNTHETIC={'mode':'wireguard','site_a_endpoint':'198.51.100.9',
 'site_b_gateway':'routeros7','management_host':'192.168.77.10',
 'vpn_subnet':'10.253.77.0/30','site_a_networks':['10.99.0.0/24'],
 'site_b_networks':['192.168.77.0/24'],
 'private_path_verified':False,'site_b_recovery_verified':False}

class ActualLocalCryptoReview(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='ipat-r916-review-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.base.chmod(0o700)
        self.keydir=self.base/'keydir';self.keydir.mkdir(mode=0o700)
        self.topology=self.base/'topology.json'
        self.topology.write_text(json.dumps(SYNTHETIC));self.topology.chmod(0o600)
        remote=x25519.X25519PrivateKey.generate().public_key()
        from cryptography.hazmat.primitives import serialization
        self.remote_public=base64.b64encode(remote.public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        self.bpub=self.base/'synthetic-b-public.txt'
        self.bpub.write_text(self.remote_public+'\n');self.bpub.chmod(0o600)
        create(self.keydir,'test-site')

    def test_matching_site_a_local_and_b_public_never_pushes(self):
        package=R.reconcile(self.keydir,'test-site',self.topology,self.bpub,51820)
        self.assertEqual(package['mode'],'NONEXECUTABLE_PAIRING_REVIEW')
        self.assertFalse(package['router_push_enabled'])
        self.assertFalse(package['config_applied'])
        self.assertEqual(package['network_actions'],0)
        self.assertEqual(package['site_a_management_route'],'192.168.77.10/32')
        lines=package['site_b_routeros_disabled_review_commands']
        self.assertEqual(len(lines),3)
        self.assertTrue(all('disabled=yes' in line for line in lines))
        self.assertIn(public_from_folder(self.keydir,'test-site')['site_a_public_key'],lines[2])
        self.assertNotIn(self.remote_public,' '.join(lines))
        self.assertNotIn('private-key=',str(package))
        self.assertNotIn('0.0.0.0/0',str(package))

    def test_verified_private_existing_path_refuses_unnecessary_vpn(self):
        direct=dict(SYNTHETIC,mode='direct_private',
                    site_a_endpoint='10.99.0.10',private_path_verified=True)
        self.topology.write_text(json.dumps(direct))
        self.assertEqual(R.reconcile(self.keydir,'test-site',self.topology,None,51820)['mode'],
                         'DIRECT_PRIVATE_NO_PAIRING')

    def test_no_router_b_public_or_invalid_topology_denied(self):
        with self.assertRaises(ValueError):
            R.reconcile(self.keydir,'test-site',self.topology,None,51820)
        self.bpub.chmod(0o644)
        with self.assertRaises(ValueError):
            R.reconcile(self.keydir,'test-site',self.topology,self.bpub,51820)
        self.bpub.chmod(0o600)
        self.topology.write_text(json.dumps(dict(SYNTHETIC,password='forbidden')))
        with self.assertRaises(ValueError):
            R.reconcile(self.keydir,'test-site',self.topology,self.bpub,51820)

if __name__=='__main__':unittest.main()
