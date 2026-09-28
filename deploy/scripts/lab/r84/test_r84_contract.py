"""R8.4 static anti-regression; real PostgreSQL + signed JWT tested separately."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[4]
MAIN=(ROOT/"apps/control-api/src/main.rs").read_text()
API=(ROOT/"apps/control-api/src/device_review_lab.rs").read_text()
ID=(ROOT/"crates/identity-core/src/lib.rs").read_text()
SQL=(ROOT/"deploy/db/migrations/0007_lab_device_maker_checker.sql").read_text()
CI=(ROOT/".github/workflows/ci.yml").read_text()

class R84Contract(unittest.TestCase):
    def test_explicit_separate_signed_mfa_reviewer_not_public(self):
        for required in (
            'IPAT_R84_SIMULATED_REVIEW',
            '!scoped_requested || identity.is_none() || k3s_lab',
            'device_review_lab::router',
            '/lab/auth/device-reviews',
            '/lab/auth/device-reviews/decision',
            'valid_reviewer_db',
            'Some("ipat_lab_device_reviewer")',
            'Host::Unix',
            'read_owner_file',
            'signed_mfa_claim()',
        ): self.assertIn(required,MAIN+API)
        self.assertNotIn('0.0.0.0:3001',API)
        self.assertNotIn('SetParameterValues',API)
    def test_signature_pinned_mfa_not_controlled_by_client_claims(self):
        for required in (
            'amr: Option<Vec<String>>',
            'methods.len() <= 8',
            'method == "mfa"',
            'Algorithm::RS256',
            'signed_mfa_claim: claims.amr',
        ): self.assertIn(required,ID)
        self.assertNotIn('headers.get("x-mfa")',API)
        self.assertNotIn('X-Verified-MFA',API)
        self.assertIn('verify_access_token(token)',API)
    def test_db_immutable_audit_exact_other_human_and_metadata_only(self):
        for required in (
            'security_admin', 'FORCE ROW LEVEL SECURITY',
            'ipat_device_review_owner NOLOGIN',
            'ipat_device_review_execute NOLOGIN',
            'GRANT SELECT,UPDATE(adoption_state)',
            'FOR UPDATE',
            'maker_issuer=p_issuer AND maker_subject=p_subject',
            "current_state<>'pending_review'",
            'GRANT SELECT,INSERT ON ipat_ops.device_candidate_reviews',
            'REVOKE ALL ON FUNCTION ipat_platform.review_lab_device_candidate',
            "connectivity='unknown'",
            "health='not_measured'",
            'last_verified_at IS NULL',
            'lookup_lab_device_reviewer',
        ): self.assertIn(required,SQL)
        self.assertNotIn('GRANT DELETE ON ipat_ops.device_candidate_reviews',SQL)
        self.assertNotIn('TRUNCATE ipat_ops.device_candidate_reviews',SQL)
        self.assertNotIn('UPDATE(ip_address)',SQL)
    def test_api_no_credential_data_and_forbidden_business_http(self):
        for required in (
            '"actual_idp_mfa_onboarded":false',
            '"physical_device_adopted":false',
            '"device_contacted":false',
            '"connectivity":"unknown"',
            '"health":"not_measured"',
            'WITH permit AS MATERIALIZED',
            'LEFT JOIN LATERAL',
            'StatusCode::FORBIDDEN',
            'StatusCode::UNAUTHORIZED',
        ): self.assertIn(required,API)
        self.assertNotIn('"management_ipv4"',API)
        self.assertNotIn('firmware_upgrade',API)
        self.assertNotIn('"/v1/',API.split('#[cfg(test)]',1)[0])
    def test_ci_runs_actual_postgres_and_signed_rust_http(self):
        for required in (
            'test_r84_contract.py',
            'test_device_maker_checker_integration.py',
            'r84_real_signed_mfa_claim_two_humans_actual_postgres_immutable_review',
            'IPAT_PG_EPHEMERAL_TEST',
        ): self.assertIn(required,CI)

if __name__=="__main__":unittest.main()
