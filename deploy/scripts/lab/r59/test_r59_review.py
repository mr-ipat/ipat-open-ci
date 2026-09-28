"""Mr. iPat: R5.9 private read-only browser preview source and negative safety tests."""
from pathlib import Path
import os
import subprocess
import unittest
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[4]
RUST = (ROOT / "apps/control-api/src/main.rs").read_text()
INDEX = (ROOT / "web/lab/index.html").read_text()
JS = (ROOT / "web/lab/app.js").read_text()
CSS = (ROOT / "web/lab/style.css").read_text()
START = ROOT / "deploy/scripts/lab/r59/start-private-web-mac.sh"
STOP = ROOT / "deploy/scripts/lab/r59/stop-private-web-mac.sh"
CHART = (ROOT / "deploy/helm/ipat-lab/templates/control-api.yaml").read_text()

class PrivateWebSafetyTests(unittest.TestCase):
    def test_browser_is_opt_in_and_impossible_in_public_k3s_mode(self):
        for x in ("IPAT_LAB_WEB", "lab_requested && !k3s_lab",
                  "lab_routes_are_missing_by_default_and_on_k3s_router",
                  "StatusCode::UNAUTHORIZED", "127.0.0.1:3000"):
            self.assertIn(x, RUST)
        self.assertNotIn("IPAT_LAB_WEB", CHART)
        self.assertIn('automountServiceAccountToken: false', CHART)

    def test_sensitive_browser_headers_and_read_only_server(self):
        for marker in ("default-src 'none'", "script-src 'self'",
                       "connect-src 'self'", "form-action 'none'",
                       "frame-ancestors 'none'", "x-frame-options",
                       "x-content-type-options", "no-store",
                       'content-security-policy'):
            self.assertIn(marker, RUST)
        status_literal = RUST.split('const LAB_STATUS: &str = ', 1)[1].split(';', 1)[0]
        for marker in ('"production_access":false',
                       '"authentication_enabled":false',
                       '"device_operations_enabled":false'):
            self.assertIn(marker, status_literal)
        self.assertNotIn(".route(\"/login\"", RUST)
        self.assertNotIn(".route(\"/api/admin\"", RUST)

    def test_html_is_local_accessible_without_fake_login(self):
        class Parser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = []
                self.urls = []
            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                self.urls += [value for name, value in attrs if name in ("src", "href")]
        p = Parser()
        p.feed(INDEX)
        self.assertEqual(p.tags.count("script"), 1)
        self.assertNotIn("form", p.tags)
        self.assertNotIn("input", p.tags)
        self.assertTrue(all(url.startswith(("/lab/", "#", "https://github.com/mr-ipat/ipat/"))
                            for url in p.urls))
        self.assertIn('href="#main"', INDEX)
        self.assertIn('Developed by <strong>Mr. iPat</strong>', INDEX)
        self.assertGreater(len(CSS), 4000)

    def test_browser_requests_are_same_origin_and_safe_dom(self):
        self.assertIn('fetch("/healthz"', JS)
        self.assertIn('fetch("/lab/status"', JS)
        self.assertIn("textContent", JS)
        for forbidden in ("innerHTML", "document.cookie", "localStorage",
                          "https://", "eval(", "Authorization", "password"):
            self.assertNotIn(forbidden, JS)

    def test_start_stop_never_open_host_or_provider_firewall(self):
        s = START.read_text()
        stop = STOP.read_text()
        for marker in ("IPAT_R59_ENABLE_PRIVATE_WEB:-", "== main",
                       "git status --porcelain", "gh api repos/mr-ipat/ipat",
                       "FileVault is On.", "StrictHostKeyChecking=yes",
                       "BatchMode=yes", "127.0.0.1:48765:127.0.0.1:3000",
                       "IPAT_LAB_WEB=1", "127.0.0.1:3000", "curl",
                       "ssh-control.sock"):
            self.assertIn(marker, s)
        for forbidden in ("sudo ", "systemctl enable", "nft -f",
                          "ufw allow", "iptables -A", "docker push",
                          "gh secret", "0.0.0.0:48765"):
            self.assertNotIn(forbidden, s + stop)
        self.assertIn("IPAT_R59_STOP_PRIVATE_WEB:-", stop)
        self.assertIn('readlink -f "/proc/$pid/exe"', stop)

    def test_scripts_fail_closed_without_opt_in(self):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        for script, failure in ((START, "IPAT_R59_PRIVATE_WEB_BLOCKED"),
                                (STOP, "R59_STOP_DENIED")):
            completed = subprocess.run(
                ["bash", str(script)], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=6
            )
            self.assertEqual(completed.returncode, 4, script.name)
            self.assertIn(failure, completed.stderr)

if __name__ == "__main__":
    unittest.main()
