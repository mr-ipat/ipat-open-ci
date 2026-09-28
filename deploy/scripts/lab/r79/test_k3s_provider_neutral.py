"""R7.9 topology-plan tests: NO cluster install or firewall changes."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
S=importlib.util.spec_from_file_location("ipat_r79_k3s",
    HERE/"k3s-provider-neutral-plan.py")
M=importlib.util.module_from_spec(S)
S.loader.exec_module(M)

class K3sPortableTopologies(unittest.TestCase):
    def setUp(self):
        self.s=copy.deepcopy(M.SAMPLE)
    def test_heterogeneous_vps_no_provider_api_or_host_firewall(self):
        p=M.plan(self.s)
        self.assertFalse(p["installation_authorized"])
        self.assertFalse(p["host_firewall_dependency"])
        self.assertFalse(p["provider_api_required"])
        self.assertFalse(p["provider_firewall_api_required"])
        self.assertTrue(p["network_isolation_required"])
        self.assertFalse(p["multi_cloud_etcd_ha_supported"])
        self.assertEqual([x["arch"] for x in p["nodes"]],
            ["x86_64","aarch64"])
        self.assertIn("vpn_end_to_end_prepared",p["external_blockers"])
        self.assertEqual(p["nodes"][1]["role"],"agent")
        self.assertIn("--flannel-iface",p["nodes"][1]["review_only_k3s_args"])
        for node in p["nodes"]:
            text=" ".join(node["review_only_k3s_args"])
            self.assertNotIn("--token",text)
            self.assertNotIn("0.0.0.0",text)
            self.assertNotIn("firewall-cmd",text)
            self.assertNotIn("provider-a",text)
    def test_single_node_private_not_forced_to_buy_vpn(self):
        s=copy.deepcopy(self.s)
        s["mode"]="single-vps-private"
        s["nodes"]=s["nodes"][:1]
        s["nodes"][0]["interface"]="ens3"
        s["vpn_end_to_end_prepared"]=False
        s["private_peer_reachability_verified"]=False
        p=M.plan(s)
        self.assertEqual(p["mode"],"single-vps-private")
        self.assertNotIn("vpn_end_to_end_prepared",p["external_blockers"])
        self.assertEqual(len(p["nodes"]),1)
        self.assertFalse(p["installation_authorized"])
    def test_no_public_ip_fake_private_or_unrouted_ip(self):
        for addr in ("198.51.100.58","127.0.0.1","169.254.1.1",
                     "192.0.2.5","10.88.1.4"):
            s=copy.deepcopy(self.s)
            s["nodes"][1]["private_ip"]=addr
            with self.assertRaises((M.Denied,ValueError)):
                M.plan(s)
    def test_no_overlapping_networks_or_ambiguous_multi_cloud_etcd(self):
        for cidr in ("10.42.0.0/16","0.0.0.0/0","10.77.0.0/24"):
            s=copy.deepcopy(self.s)
            s["service_cidr"]=cidr
            with self.assertRaises((M.Denied,ValueError)):
                M.plan(s)
        s=copy.deepcopy(self.s)
        s["nodes"][1]["role"]="server"
        with self.assertRaises(M.Denied):M.plan(s)
    def test_bad_iface_and_duplicates_fail_closed(self):
        for iface in ("eth0","wg-ipat;reboot","wg@ipat",""):
            s=copy.deepcopy(self.s)
            s["nodes"][1]["interface"]=iface
            with self.assertRaises(M.Denied):M.plan(s)
        for key in ("name","private_ip"):
            s=copy.deepcopy(self.s)
            s["nodes"][1][key]=s["nodes"][0][key]
            with self.assertRaises(M.Denied):M.plan(s)
    def test_requires_explicit_booleans_and_no_implicit_install(self):
        for bad in (None,1,"true"):
            s=copy.deepcopy(self.s)
            s["rescue_console_verified"]=bad
            with self.assertRaises(M.Denied):M.plan(s)
        s=copy.deepcopy(self.s)
        for flag in M.FLAGS:
            s[flag]=True
        p=M.plan(s)
        self.assertEqual(p["external_blockers"],[])
        self.assertFalse(p["installation_authorized"])
    def test_unknown_json_fields_and_duplicate_keys_rejected(self):
        s=copy.deepcopy(self.s);s["shell"]="curl|sh"
        with self.assertRaises(M.Denied):M.plan(s)
        s=copy.deepcopy(self.s);s["nodes"][0]["api_key"]="secret"
        with self.assertRaises(M.Denied):M.plan(s)
        with self.assertRaises(M.Denied):
            json.loads('{"role":"server","role":"agent"}',
                       object_pairs_hook=M.unique)
    def test_real_cli_outputs_offline_blocked_and_no_install(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Path(temp)/"plan.json"
            f.write_text(json.dumps(self.s))
            p=subprocess.run([sys.executable,str(HERE/"k3s-provider-neutral-plan.py"),
                "--plan",str(f)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            output=json.loads(p.stdout)
            self.assertFalse(output["installation_authorized"])
            self.assertNotIn("KUBECONFIG=",p.stdout)
            self.assertNotIn("K3S_TOKEN=",p.stdout)
            f.write_text('{"schema":1,"schema":2}')
            r=subprocess.run([sys.executable,str(HERE/"k3s-provider-neutral-plan.py"),
                "--plan",str(f)],capture_output=True,text=True)
            self.assertEqual(r.returncode,4)
if __name__=="__main__":unittest.main()
