"""R8.6 static audit guards. Actual HTTP/Rust unit tests separately required CI."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[4]
PKCE=(ROOT/"crates/identity-core/src/browser_pkce.rs").read_text()
RUST=(ROOT/"apps/control-api/src/oidc_browser_lab.rs").read_text()
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
SMOKE=(ROOT/"deploy/scripts/lab/r86/browser-http-smoke.sh").read_text()
HTTP=(ROOT/"deploy/scripts/lab/r86/browser_http_smoke.py").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()
CLI=(ROOT/"crates/identity-core/tests/oidc_cli.rs").read_text()
class BrowserPKCEContract(unittest.TestCase):
    def test_entropy_and_bound_exact_idp_no_token_leak(self):
        for part in ("getrandom::fill","Sha256::digest","URL_SAFE_NO_PAD",
                     "code_challenge_method=S256","scope=openid",
                     "response_type=code","redirect_uri=http%3A%2F%2F127.0.0.1%3A48765"):
            self.assertIn(part,PKCE)
        self.assertNotIn("response_type=token",PKCE)
        self.assertNotIn("client_secret",PKCE)
    def test_separate_optin_callback_consumes_state_and_never_grants_login(self):
        for part in ("IPAT_R86_BROWSER_FLOW","IPAT_LAB_OIDC_VERIFY",
                     "geteuid()","NO", "HttpOnly; SameSite=Lax",
                     "MAX_AGE: Duration = Duration::from_secs(300)",
                     "pending.remove","ConstantTimeEq","StatusCode::SERVICE_UNAVAILABLE",
                     '"authenticated":false'):
            if part=="NO": continue
            self.assertIn(part,RUST if part not in ("IPAT_R86_BROWSER_FLOW",) else MAIN+RUST)
        self.assertNotIn("Set-Cookie: session",RUST)
        self.assertNotIn("Access-Control-Allow-Origin",RUST)
        self.assertNotIn("connect(NoTls)",RUST)
        self.assertNotIn("std::process::Command",RUST)
    def test_k3s_absence_default_no_sessions_and_safe_existing_reviewer(self):
        self.assertIn('std::env::var("IPAT_R86_BROWSER_FLOW")',MAIN)
        self.assertIn("if !lab_web_enabled",MAIN)
        self.assertIn('app.merge(oidc_browser_lab::router(',MAIN)
        self.assertIn('"/v1/platform/{*path}"',MAIN)
        self.assertIn('"/v1/operations/{*path}"',MAIN)
        self.assertIn("std::io::ErrorKind::BrokenPipe",CLI)
    def test_actual_compiled_local_socket_proof_is_required_in_ci(self):
        for part in ("IPAT_R86_BROWSER_TEST","IPAT_R86_BROWSER_FLOW=YES",
                     "IPAT_LAB_OIDC_VERIFY=YES","127.0.0.1",
                     "mktemp -d","trap cleanup EXIT"):
            self.assertIn(part,SMOKE)
        for part in ("NoExternalRedirect","code_challenge_method","HttpOnly",
                     "call(url,cookie=cookie)[0]==403","/v1/tenant/devices"):
            self.assertIn(part,HTTP)
        for part in ("test_r86_contract.py","cargo test --locked -p identity-core",
                     "cargo test --locked -p control-api",
                     "IPAT_R86_BROWSER_TEST=YES"):
            self.assertIn(part,CI)
if __name__=="__main__":unittest.main()
