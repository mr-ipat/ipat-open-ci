"""Safety contracts for IPAT infrastructure preparation (Mr. iPat)."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[3]
FILE = ROOT / "deploy/scripts/production/readiness.py"
spec = spec_from_file_location("production_readiness", FILE)
assert spec and spec.loader
m = module_from_spec(spec)
spec.loader.exec_module(m)

class ReadOnlyInfrastructureGateTests(TestCase):
    @staticmethod
    def all_pass_facts():
        return {
            "clean_git_main": True,
            "github_matches_mac": True,
            "vps_matches_mac": True,
            "mac_filevault_on": True,
            "latest_source_encrypted_snapshot_exists": True,
            "key_only_ssh_reachable": True,
            "ubuntu_2604": True,
            "no_pending_ssh_rollback": True,
        }

    def test_all_automatic_green_still_does_not_authorize_production(self):
        report = m.evaluate(self.all_pass_facts())
        self.assertEqual(report["evaluation"], "NO_GO")
        self.assertFalse(report["production_db_apply"])
        self.assertFalse(report["native_firewall_apply"])
        self.assertFalse(report["k3s_install"])
        self.assertTrue(all(x["pass"] for x in report["automatic_checks"]))
        self.assertEqual(len(report["external_independent_gates"]), 7)
        self.assertEqual(len(report["blocker_ids"]), 7)

    def test_missing_and_false_facts_fail_closed(self):
        report = m.evaluate({})
        self.assertFalse(any(x["pass"] for x in report["automatic_checks"]))
        self.assertEqual(len(report["blocker_ids"]), 15)
        facts = self.all_pass_facts()
        facts["latest_source_encrypted_snapshot_exists"] = False
        report = m.evaluate(facts)
        self.assertIn("latest_source_encrypted_snapshot_exists", report["blocker_ids"])

    def test_claimed_manual_fields_cannot_overwrite_external_gates(self):
        fake = self.all_pass_facts()
        for key in m.EXTERNAL_GATES:
            fake[key] = True
        report = m.evaluate(fake)
        self.assertEqual(len(report["external_independent_gates"]), 7)
        self.assertTrue(all(x["status"] == "BLOCKED_UNVERIFIED"
                            for x in report["external_independent_gates"]))
        self.assertFalse(report["k3s_install"])

    def test_no_mutation_or_privileged_execution_in_source(self):
        text = FILE.read_text()
        forbidden = ['["sudo"', "os.system(", "shell=True",
                     "nft -f", "iptables -A", "kubectl apply",
                     "apt install", "systemctl enable", "curl -sfL",
                     "create_subprocess_shell", "git push"]
        for bad in forbidden:
            self.assertNotIn(bad, text)
        self.assertIn("StrictHostKeyChecking=yes", text)
        self.assertIn("BatchMode=yes", text)
        self.assertIn("RESTIC_PASSWORD_COMMAND", text)

    def test_cli_reports_no_go_even_when_all_automatic_checks_pass(self):
        with mock.patch.object(m, "collect", return_value=self.all_pass_facts()):
            with mock.patch("sys.argv", ["readiness.py", "--json"]):
                with mock.patch("builtins.print") as print_mock:
                    self.assertEqual(m.main(), 3)
        rendered = "\n".join(str(call) for call in print_mock.call_args_list)
        self.assertIn("NO_GO", rendered)

if __name__ == "__main__":
    main()
