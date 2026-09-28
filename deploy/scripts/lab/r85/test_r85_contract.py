"""R8.5 independent real-OIDC signed claim preflight: fail closed by default."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[4]
BIN = (ROOT/"crates/identity-core/src/bin/oidc-mfa-preflight.rs").read_text()
TEST = (ROOT/"crates/identity-core/tests/oidc_cli.rs").read_text()
CI = (ROOT/".github/workflows/ci.yml").read_text()
COMPACT = ''.join(BIN.split())
SEC = (ROOT/"docs/SECURITY.md").read_text()
class R85OriginalOidcContract(unittest.TestCase):
    def test_real_preflight_is_not_a_new_login_session_or_role_minter(self):
        for needle in (
            'IPAT_R85_REAL_IDP_PREFLIGHT',
            'IPAT_R85_ISSUER','IPAT_R85_AUDIENCE',
            'IPAT_R85_KID','IPAT_R85_PINNED_PEM_FILE',
            'verifier.verify_access_token(token)',
            'subject.signed_mfa_claim()',
            'PRODUCTION_DEVICE_OR_BUSINESS_ACCESS=DENIED',
            'ACTUAL_HUMAN_MFA_ENROLLMENT_AND_BROWSER_SESSION=NOT_VERIFIED',
        ): self.assertIn(''.join(needle.split()),COMPACT)
        for unsafe in (
            "Set-Cookie","device_registry_execute","firmware_upgrade",
            "UserPassword","client_secret","bearer_token.txt","token={token}",
            "println!(\"{token}", "println!(\"{subject}"
        ): self.assertNotIn(unsafe,BIN)
    def test_anti_tty_bounded_fd_private_owner_no_symlink(self):
        for needle in (
            'libc::geteuid','libc::isatty',
            'libc::O_NOFOLLOW','0o700','0o600',
            'symlink_metadata','nlink()!=1',
            'MAX_BEARER','MAX_PUBLIC_PEM',
            'io::stdin().take(MAX_BEARER+2)',
        ): self.assertIn(''.join(needle.split()),COMPACT)
        self.assertNotIn('std::process::Command',BIN)
        self.assertNotIn('reqwest',BIN)
    def test_genuine_rsa_unprivileged_process_positive_and_negative(self):
        for needle in (
            'genpkey','rsa_keygen_bits:2048',
            'wrong_kid','signed(&attacker.signing_key',
            'amr','symlink(&f.pem','0o644','0o600',
            'R85_PINNED_SIGNED_MFA_CLAIM_PREFLIGHT=PASS',
            'PRODUCTION_DEVICE_OR_BUSINESS_ACCESS=DENIED',
        ): self.assertIn(needle,TEST)
        self.assertIn('cargo test --locked -p identity-core --test oidc_cli',CI)
        self.assertIn('test_r85_contract.py',CI)
    def test_no_unverified_provider_is_marked_as_enabled(self):
        self.assertIn('actual human',SEC.lower())
        self.assertIn('amr',SEC.lower())
        self.assertNotIn("ACTUAL_HUMAN_MFA_ENROLLMENT_AND_BROWSER_SESSION=VERIFIED",BIN)
if __name__=="__main__": unittest.main()
