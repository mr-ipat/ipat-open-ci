//! R7.6 synthetic materialized rows + actual generated RS256 signed tokens.
//! No DB lookup/HTTP endpoint, MFA, authentic approval or DNS assertion.
use authz_core::dashboard::{DashboardRole, DashboardSection};
use authz_core::verified_menu::{visible_for_verified_candidate, CandidateMembershipRow};
use identity_core::{PinnedIssuer, VerifiedSubject};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tenant_core::TenantId;
const ISSUER: &str = "https://id.synthetic.invalid/realms/lab";
const OTHER: &str = "https://other.synthetic.invalid/realms/lab";
const AUD: &str = "ipat-control-api";
const KID: &str = "private-lab";
struct Keys {
    _temp: tempfile::TempDir,
    private: Vec<u8>,
    public: Vec<u8>,
}
fn keys() -> Keys {
    let tmp = tempfile::tempdir().unwrap();
    let private = tmp.path().join("synthetic.key");
    let public = tmp.path().join("synthetic.pub");
    let result = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
        ])
        .arg(&private)
        .output()
        .unwrap();
    assert!(result.status.success());
    let result = Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(&private)
        .arg("-out")
        .arg(&public)
        .output()
        .unwrap();
    assert!(result.status.success());
    Keys {
        _temp: tmp,
        private: fs::read(private).unwrap(),
        public: fs::read(public).unwrap(),
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn verified(keys: &Keys, issuer: &str, subject: &str) -> VerifiedSubject {
    let clock = now();
    let claims = json!({
        "iss":issuer,"sub":subject,"aud":AUD,
        "iat":clock,"nbf":clock,"exp":clock+600,
        "tenant_id":"attacker-selected-other","roles":["platform_owner","super_admin"],
        "custom_domain":"hub.example.invalid"
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header.typ = Some("JWT".to_owned());
    let signed = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(&keys.private).unwrap(),
    )
    .unwrap();
    PinnedIssuer::new(issuer, AUD, KID, &keys.public)
        .unwrap()
        .verify_access_token(&signed)
        .unwrap()
}
fn row<'a>(tenant: &'a TenantId, pops: &'a [&'a str], expiry: u64) -> CandidateMembershipRow<'a> {
    CandidateMembershipRow {
        issuer: ISSUER,
        subject: "synthetic-fadly-operator",
        tenant,
        role: DashboardRole::NocEngineer,
        approved_by: "synthetic-reviewer",
        authorized_pops: pops,
        expires_at: expiry,
        revoked: false,
    }
}
#[test]
fn genuine_signed_subject_and_exact_materialized_row_restrict_noc_menu() {
    let k = keys();
    let subject = verified(&k, ISSUER, "synthetic-fadly-operator");
    assert_eq!(subject.issuer(), ISSUER);
    let fadly = TenantId::parse("fadly").unwrap();
    let nengnet = TenantId::parse("nengnet").unwrap();
    let pop = ["fadly-lab-pop"];
    let row = row(&fadly, &pop, now() + 300);
    let visible =
        visible_for_verified_candidate(&subject, &fadly, Some("fadly-lab-pop"), &row, now());
    assert!(visible.contains(&DashboardSection::OperationsOverview));
    assert!(visible.contains(&DashboardSection::OperationsInventory));
    assert!(!visible.contains(&DashboardSection::PlatformOverview));
    assert!(!visible.contains(&DashboardSection::BulkPppoeWrite));
    assert!(
        visible_for_verified_candidate(&subject, &nengnet, Some("fadly-lab-pop"), &row, now())
            .is_empty()
    );
    // Host/custom_domain claims never enter the function: no implicit tenant.
    assert!(
        !visible_for_verified_candidate(&subject, &fadly, Some("other-pop"), &row, now())
            .contains(&DashboardSection::OperationsInventory)
    );
}
#[test]
fn same_subject_in_different_issuer_never_inherits_tenant_rights() {
    let k = keys();
    let other = verified(&k, OTHER, "synthetic-fadly-operator");
    let fadly = TenantId::parse("fadly").unwrap();
    let pop = ["fadly-lab-pop"];
    let row = row(&fadly, &pop, now() + 300);
    assert!(
        visible_for_verified_candidate(&other, &fadly, Some("fadly-lab-pop"), &row, now())
            .is_empty()
    );
}
#[test]
fn unapproved_revoked_expired_wrong_subject_and_expired_token_all_deny() {
    let k = keys();
    let subject = verified(&k, ISSUER, "synthetic-fadly-operator");
    let fadly = TenantId::parse("fadly").unwrap();
    let pops = ["fadly-lab-pop"];
    let clock = now();
    let mut rec = row(&fadly, &pops, clock + 300);
    rec.approved_by = "";
    assert!(
        visible_for_verified_candidate(&subject, &fadly, Some("fadly-lab-pop"), &rec, clock)
            .is_empty()
    );
    rec.approved_by = "synthetic-reviewer";
    rec.revoked = true;
    assert!(
        visible_for_verified_candidate(&subject, &fadly, Some("fadly-lab-pop"), &rec, clock)
            .is_empty()
    );
    rec.revoked = false;
    rec.expires_at = clock;
    assert!(
        visible_for_verified_candidate(&subject, &fadly, Some("fadly-lab-pop"), &rec, clock)
            .is_empty()
    );
    rec.expires_at = clock + 300;
    rec.subject = "forged-another";
    assert!(
        visible_for_verified_candidate(&subject, &fadly, Some("fadly-lab-pop"), &rec, clock)
            .is_empty()
    );
    rec.subject = "synthetic-fadly-operator";
    assert!(visible_for_verified_candidate(
        &subject,
        &fadly,
        Some("fadly-lab-pop"),
        &rec,
        subject.expires_at()
    )
    .is_empty());
}
#[test]
fn platform_owner_cannot_be_minted_from_tenant_candidate_row() {
    let k = keys();
    let subject = verified(&k, ISSUER, "synthetic-fadly-operator");
    let fadly = TenantId::parse("fadly").unwrap();
    let no_pops: [&str; 0] = [];
    let mut rec = row(&fadly, &no_pops, now() + 300);
    for role in [
        DashboardRole::TenantAdmin,
        DashboardRole::Helpdesk,
        DashboardRole::Auditor,
    ] {
        rec.role = role;
        let visible = visible_for_verified_candidate(&subject, &fadly, None, &rec, now());
        assert!(!visible.contains(&DashboardSection::PlatformTenantCatalog));
        assert!(!visible.contains(&DashboardSection::BulkPppoeWrite));
    }
}
