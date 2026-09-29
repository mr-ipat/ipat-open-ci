"""No-network tests for R7.9 strict SSH C320 two-command transport."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("r79_ssh", HERE / "c320-ssh-readonly.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
PLAN = {
    "target_id":"DEV-01", "environment":"isolated_lab",
    "transport":"ssh-strict-pinned-publickey",
    "profile":"zte-c320-exact-two-readonly-show-candidate",
    "private_ipv4":"10.72.4.10", "ssh_port":22, "ssh_user":"onlyread",
    **{k:True for k in M.GATES},
}
CARDS = b"Rack Shelf Slot CfgType RealType Port HardVer SoftVer Status\n1 1 1 GTGO GTGOG 8 120301 V2.0.0 INSERVICE\n"
VERSIONS = b"PhyLoc FileType VerType VerTag BuildTime VerLength\n1/1/1 GTGOG MVR V0.0.LAB 2026-01-01 01:02:03 100\n"

class RemoteSSHNoL1(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="ipat-r79-")
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.private=root/"private";self.private.mkdir(mode=0o700)
        self.out=root/"encrypted";self.out.mkdir(mode=0o700)
        self.file("plan.json",json.dumps(PLAN))
        self.file("known_hosts","10.72.4.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA\n")
        self.file("id_readonly","EXAMPLE-ONLY-NOT-A-REAL-KEY")
    def file(self,name,content):
        path=self.private/name
        if isinstance(content,str):content=content.encode()
        path.write_bytes(content);path.chmod(0o600)
    def test_requires_explicit_no_network_plan_and_no_physical_l1(self):
        result=subprocess.run([sys.executable,str(HERE/"c320-ssh-readonly.py"),
            "--check-plan",str(self.private)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        output=json.loads(result.stdout)
        self.assertEqual(output["status"],"HUMAN_REVIEW_REQUIRED")
        self.assertFalse(output["network_performed"])
        self.assertFalse(output["physical_interop_verified"])
        self.assertFalse(output["firmware_enabled"])
    def test_remains_blocked_on_each_missing_gate(self):
        for gate in M.GATES:
            plan=dict(PLAN);plan[gate]=False
            self.file("plan.json",json.dumps(plan))
            validated,missing=M.packet(self.private)
            self.assertEqual(validated,plan)
            self.assertEqual(missing,[gate])
        self.file("plan.json",json.dumps(PLAN))
    def test_no_public_address_injection_or_unsafe_username(self):
        for k,v in [("private_ipv4","8.8.8.8"),
            ("private_ipv4","127.0.0.1"),("ssh_port",True),
            ("ssh_port",0),("ssh_user","operator;rm -rf /"),
            ("profile","ssh-write")]:
            plan=dict(PLAN);plan[k]=v
            with self.assertRaises((M.Denied,ValueError)):
                M.validate(plan)
        for cmd in ("configure terminal","reboot","write","show version-running; reboot"):
            with self.assertRaises(M.Denied):
                M.command_argv(self.private,PLAN,cmd)
    def test_strict_host_pin_no_host_keyscan_password_or_forwarding(self):
        argv=M.command_argv(self.private,PLAN,"show card")
        self.assertEqual(argv[-1],"show card")
        self.assertIn("StrictHostKeyChecking=yes",argv)
        for term in ("BatchMode=yes","IdentityAgent=none",
                     "PasswordAuthentication=no","ProxyCommand=none",
                     "ClearAllForwardings=yes"):
            self.assertIn(term,argv)
        for command in ("ssh-keyscan","sshpass","telnet","tr069","enable"):
            self.assertNotIn(command," ".join(argv).lower())
        self.file("known_hosts","8.8.8.8 ssh-ed25519 AAAAC3\n")
        with self.assertRaises(M.Denied): M.packet(self.private)
    def test_strict_legacy_c320_rsa_cbc_is_process_scoped_and_never_tofu(self):
        plan=dict(PLAN,transport="ssh-strict-pinned-publickey-legacy-rsa-cbc",
                  private_ipv4="10.77.13.233",ssh_port=321)
        self.file("plan.json",json.dumps(plan))
        self.file("known_hosts","[10.77.13.233]:321 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQTESTONLY\n")
        parsed,missing=M.packet(self.private)
        self.assertEqual(parsed,plan)
        self.assertEqual(missing,[])
        args=M.command_argv(self.private,plan,"show card")
        self.assertEqual(args[-1],"show card")
        for flag in ("HostKeyAlgorithms=ssh-rsa","Ciphers=aes128-cbc",
                     "StrictHostKeyChecking=yes","PasswordAuthentication=no",
                     "BatchMode=yes","IdentitiesOnly=yes"):
            self.assertIn(flag,args)
        self.assertNotIn("ssh-dss"," ".join(args))
        self.assertNotIn("StrictHostKeyChecking=no",args)
        self.assertNotIn("UserKnownHostsFile=/dev/null",args)
        self.file("known_hosts","[10.77.13.233]:321 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA\n")
        with self.assertRaisesRegex(M.Denied,"pinned RSA"):
            M.packet(self.private)

    def test_actual_observed_group14_sha256_compat_is_explicit_and_process_only(self):
        plan=dict(PLAN,transport=(
            "ssh-strict-pinned-publickey-legacy-rsa-cbc-group14-sha256"),
            private_ipv4="10.77.13.233",ssh_port=321)
        self.file("plan.json",json.dumps(plan))
        self.file("known_hosts","[10.77.13.233]:321 ssh-rsa "
                  "AAAAB3NzaC1yc2EAAAADAQABAAABAQTESTSYNTHETICONLY\n")
        self.assertEqual(M.packet(self.private)[1],[])
        args=M.command_argv(self.private,plan,"show card")
        for option in ("HostKeyAlgorithms=ssh-rsa","Ciphers=aes128-cbc",
             "KexAlgorithms=diffie-hellman-group14-sha256",
             "StrictHostKeyChecking=yes","PasswordAuthentication=no",
             "PreferredAuthentications=publickey","IdentityAgent=none",
             "ProxyCommand=none","BatchMode=yes"):
            self.assertIn(option,args)
        self.assertNotIn("ssh-dss"," ".join(args))
        self.assertNotIn("StrictHostKeyChecking=no",args)
        self.assertNotIn("PubkeyAcceptedAlgorithms=+ssh-rsa",args)
        self.assertEqual(args[-1],"show card")
        self.file("known_hosts","[10.77.13.233]:321 ssh-ed25519 "
                  "AAAAC3NzaC1lZDI1NTE5AAAAIAAA\n")
        with self.assertRaisesRegex(M.Denied,"pinned RSA"):
            M.packet(self.private)
        with self.assertRaisesRegex(M.Denied,"factory or privileged"):
            M.validate(dict(plan,ssh_user="zte"))

    def test_factory_account_never_valid_for_live_readonly(self):
        for user in ("zte","root","admin","administrator"):
            with self.subTest(user=user):
                with self.assertRaisesRegex(M.Denied,"factory or privileged"):
                    M.validate(dict(PLAN,ssh_user=user))
        self.assertEqual(M.validate(PLAN),[])

    def test_requires_owner_only_packet_not_symlink_hardlink(self):
        p=self.private/"id_readonly"
        p.chmod(0o644)
        with self.assertRaises(M.Denied):M.packet(self.private)
        p.chmod(0o600)
        p.rename(self.private/"saved")
        p.symlink_to(self.private/"saved")
        with self.assertRaises(M.Denied):M.packet(self.private)
    def test_collect_never_runs_without_new_explicit_opt_in(self):
        with patch.dict(os.environ,{},clear=True):
            with patch.object(M.subprocess,"run",side_effect=AssertionError("network attempted")):
                with self.assertRaises(M.Denied):
                    M.collect(self.private,self.out,PLAN)
        self.assertEqual(list(self.out.iterdir()),[])
    def test_fake_exact_two_fixed_remote_exec_outputs_never_logged(self):
        calls=[]
        def fake(argv,**kwargs):
            calls.append(argv[-1])
            return types.SimpleNamespace(
                stdout=CARDS if len(calls)==1 else VERSIONS,returncode=0)
        with patch.dict(os.environ,{"IPAT_R79_OPERATOR_APPROVES_REMOTE_READ":"YES"}):
            with patch.object(M.subprocess,"run",side_effect=fake):
                result=M.collect(self.private,self.out,PLAN)
        self.assertEqual(calls,["show card","show version-running"])
        self.assertEqual(result["commands"],2)
        self.assertFalse(result["compatibility_verified"])
        self.assertFalse(result["firmware_enabled"])
        self.assertEqual((self.out/"cards.txt").read_bytes(),CARDS)
        self.assertEqual((self.out/"versions.txt").read_bytes(),VERSIONS)
        for f in self.out.iterdir():
            self.assertEqual(f.stat().st_mode & 0o777,0o600)
    def test_first_read_mode_is_single_fixed_show_with_explicit_opt_in(self):
        calls=[]
        def fake(argv,**kwargs):
            calls.append(argv[-1])
            return types.SimpleNamespace(stdout=CARDS,returncode=0)
        with patch.dict(os.environ,{"IPAT_R79_OPERATOR_APPROVES_REMOTE_READ":"YES"}):
            with patch.object(M.subprocess,"run",side_effect=fake):
                result=M.collect(self.private,self.out,PLAN,first_read_only=True)
        self.assertEqual(calls,["show card"])
        self.assertEqual(result["commands"],1)
        self.assertFalse(result["compatibility_verified"])
        self.assertFalse(result["tenant_enrolled"])
        self.assertEqual({p.name for p in self.out.iterdir()},{"cards.txt"})

    def test_failed_second_read_leaves_no_partial_sensitive_files(self):
        calls=[]
        def fail(argv,**kwargs):
            calls.append(argv)
            return types.SimpleNamespace(stdout=CARDS if len(calls)==1 else b"",
                                         returncode=0 if len(calls)==1 else 4)
        with patch.dict(os.environ,{"IPAT_R79_OPERATOR_APPROVES_REMOTE_READ":"YES"}):
            with patch.object(M.subprocess,"run",side_effect=fail):
                with self.assertRaises(M.Denied):
                    M.collect(self.private,self.out,PLAN)
        self.assertEqual(list(self.out.iterdir()),[])
def load_tests(loader, suite, pattern):
    # R9.13 local no-packet route checks join the locked CI R7.9 stage.
    path=HERE.parent / 'r913' / 'test_restricted_route.py'
    spec=importlib.util.spec_from_file_location('r913_route_tests',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    path=HERE.parent / 'r913' / 'test_temporary_relay.py'
    spec=importlib.util.spec_from_file_location('r913_temporary_relay_tests',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    path=HERE.parent / 'r914' / 'test_console_host_key.py'
    spec=importlib.util.spec_from_file_location('r914_console_key_tests',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite.addTests(loader.loadTestsFromModule(module))
    return suite

if __name__=="__main__":unittest.main()
