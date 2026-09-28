//! Independent synthetic RSA JWT fixtures: NEVER a real human IdP session.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use identity_core::PinnedIssuer;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const ISS: &str = "https://id.example.invalid/realms/ipat";
const API: &str = "ipat-control-api";
const CLIENT: &str = "ipat-private-browser";
const KID: &str = "pinned-test-key";
const NONCE: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
struct Fixture {
    _tmp: tempfile::TempDir,
    private: Vec<u8>,
    pinned: PinnedIssuer,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let privf = dir.path().join("synthetic-private.pem");
        let pubf = dir.path().join("synthetic-public.pem");
        assert!(Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out"
            ])
            .arg(&privf)
            .output()
            .unwrap()
            .status
            .success());
        assert!(Command::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(&privf)
            .arg("-out")
            .arg(&pubf)
            .output()
            .unwrap()
            .status
            .success());
        let public = fs::read(&pubf).unwrap();
        Self {
            _tmp: dir,
            private: fs::read(&privf).unwrap(),
            pinned: PinnedIssuer::new(ISS, API, KID, &public).unwrap(),
        }
    }
    fn sign(&self, value: &Value, kid: &str, typ: &str) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.into());
        h.typ = Some(typ.into());
        encode(
            &h,
            value,
            &EncodingKey::from_rsa_pem(&self.private).unwrap(),
        )
        .unwrap()
    }
    fn access(&self) -> String {
        self.sign(&access_claims(), KID, "at+jwt")
    }
    fn id(&self, access: &str) -> Value {
        let now = clock();
        let hash = Sha256::digest(access.as_bytes());
        json!({"iss":ISS,"aud":CLIENT,"sub":"human-synthetic-only",
            "iat":now,"nbf":now,"exp":now+180,"auth_time":now,
            "nonce":NONCE,"at_hash":URL_SAFE_NO_PAD.encode(&hash[..16]),
            "amr":["pwd","mfa"],"azp":CLIENT})
    }
    fn verify(&self, c: &Value, access: &str) -> bool {
        self.pinned
            .verify_offline_browser_pair(CLIENT, NONCE, &self.sign(c, KID, "JWT"), access)
            .is_ok()
    }
}
fn clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn access_claims() -> Value {
    let n = clock();
    json!({"iss":ISS,"aud":API,"sub":"human-synthetic-only",
        "iat":n,"nbf":n,"exp":n+180,"amr":["pwd","mfa"],
        "tenant_id":"fake-escalation","realm_access":{"roles":["super_admin"]}})
}
#[test]
fn genuinely_signed_matching_pair_accepts_only_identity_not_tenant() {
    let fixture = Fixture::new();
    let access = fixture.access();
    let id = fixture.id(&access);
    let verified = fixture
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &fixture.sign(&id, KID, "JWT"), &access)
        .unwrap();
    assert_eq!(verified.subject(), "human-synthetic-only");
    assert_eq!(verified.issuer(), ISS);
    assert!(verified.expires_at() > clock());
    // The returned identity has no tenant, POP, role, approver or session field.
}
#[test]
fn nonce_access_binding_and_wrong_client_fail() {
    let fixture = Fixture::new();
    let access = fixture.access();
    let mut id = fixture.id(&access);
    assert!(!fixture
        .pinned
        .verify_offline_browser_pair(
            CLIENT,
            &"q".repeat(43),
            &fixture.sign(&id, KID, "JWT"),
            &access
        )
        .is_ok());
    id["nonce"] = json!("q".repeat(43));
    assert!(!fixture.verify(&id, &access));
    id = fixture.id(&access);
    id["at_hash"] = json!("AAAAAAAAAAAAAAAAAAAAAA");
    assert!(!fixture.verify(&id, &access));
    id = fixture.id(&access);
    id["aud"] = json!(API);
    assert!(!fixture.verify(&id, &access));
    id = fixture.id(&access);
    id["azp"] = json!("another-client");
    assert!(!fixture.verify(&id, &access));
}
#[test]
fn missing_or_bogus_mfa_and_stale_auth_time_fail() {
    let fixture = Fixture::new();
    let access = fixture.access();
    for amr in [
        json!(["pwd"]),
        json!([]),
        json!(["not_mfa"]),
        json!(["mfa".repeat(33)]),
    ] {
        let mut id = fixture.id(&access);
        id["amr"] = amr;
        assert!(!fixture.verify(&id, &access));
    }
    let mut stale = fixture.id(&access);
    stale["auth_time"] = json!(clock() - 1000);
    assert!(!fixture.verify(&stale, &access));
    let mut future = fixture.id(&access);
    future["auth_time"] = json!(clock() + 1000);
    assert!(!fixture.verify(&future, &access));
    let mut no_amr = fixture.id(&access);
    no_amr.as_object_mut().unwrap().remove("amr");
    assert!(!fixture.verify(&no_amr, &access));
}
#[test]
fn signature_header_subject_and_access_token_confusion_fail() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let access = fixture.access();
    let id = fixture.id(&access);
    let other_token = other.sign(&id, KID, "JWT");
    assert!(fixture
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &other_token, &access)
        .is_err());
    assert!(fixture
        .pinned
        .verify_offline_browser_pair(
            CLIENT,
            NONCE,
            &fixture.sign(&id, "wrong-kid", "JWT"),
            &access
        )
        .is_err());
    assert!(fixture
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &fixture.sign(&id, KID, "at+jwt"), &access)
        .is_err());
    let mut wrong = id;
    wrong["sub"] = json!("other-subject");
    assert!(!fixture.verify(&wrong, &access));
    let mut only_password = access_claims();
    only_password["amr"] = json!(["pwd"]);
    let weak_access = fixture.sign(&only_password, KID, "at+jwt");
    assert!(fixture
        .pinned
        .verify_offline_browser_pair(
            CLIENT,
            NONCE,
            &fixture.sign(&fixture.id(&weak_access), KID, "JWT"),
            &weak_access
        )
        .is_err());
}
#[test]
fn malformed_and_future_id_tokens_rejected() {
    let fixture = Fixture::new();
    let access = fixture.access();
    let mut id = fixture.id(&access);
    id["iat"] = json!(clock() + 3600);
    id["nbf"] = json!(clock() + 3600);
    id["exp"] = json!(clock() + 4000);
    assert!(!fixture.verify(&id, &access));
    let mut long = fixture.id(&access);
    long["exp"] = json!(clock() + 3600);
    assert!(!fixture.verify(&long, &access));
    let id = fixture.id(&access);
    assert!(fixture
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, "not-a-jwt", &access)
        .is_err());
    assert!(fixture
        .pinned
        .verify_offline_browser_pair(
            CLIENT,
            NONCE,
            &fixture.sign(&id, KID, "JWT"),
            "bogus-access"
        )
        .is_err());
}

#[test]
fn r88_signed_pair_issues_opaque_unprivileged_session_and_csrf_gates() {
    use identity_core::browser_session::{BrowserSessionVault, RequestKind};
    let f = Fixture::new();
    let access = f.access();
    let id = f.sign(&f.id(&access), KID, "JWT");
    let identity = f
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &id, &access)
        .unwrap();
    let expiry = identity.expires_at();
    let mut vault = BrowserSessionVault::default();
    let issued = vault
        .issue(identity, clock())
        .expect("signed identity-only");
    assert_eq!(issued.cookie_secret().len(), 43);
    assert_eq!(issued.csrf_secret().len(), 43);
    assert_ne!(issued.cookie_secret(), issued.csrf_secret());
    assert!(issued.expires_at() <= expiry);
    let policy = issued.secure_cookie_header();
    assert!(policy.contains("__Host-ipat_session="));
    assert!(policy.contains("Secure; HttpOnly; SameSite=Strict; Path=/;"));
    assert!(!policy.contains(issued.csrf_secret()));
    let max_age: u64 = policy.split("Max-Age=").last().unwrap().parse().unwrap();
    assert!(max_age > 0 && max_age <= 180);
    assert!(vault
        .authenticate(
            issued.cookie_secret(),
            None,
            RequestKind::Read,
            false,
            clock()
        )
        .is_none());
    assert!(vault
        .authenticate(
            issued.cookie_secret(),
            None,
            RequestKind::Mutation,
            true,
            clock()
        )
        .is_none());
    assert!(vault
        .authenticate(
            issued.cookie_secret(),
            Some("bogus"),
            RequestKind::Mutation,
            true,
            clock()
        )
        .is_none());
    let verified = vault
        .authenticate(
            issued.cookie_secret(),
            Some(issued.csrf_secret()),
            RequestKind::Mutation,
            true,
            clock(),
        )
        .unwrap();
    assert_eq!(verified.issuer(), ISS);
    assert_eq!(verified.subject(), "human-synthetic-only");
    assert_eq!(verified.expires_at(), issued.expires_at());
    assert!(vault.revoke(issued.cookie_secret()));
    assert!(!vault.revoke(issued.cookie_secret()));
    assert!(vault
        .authenticate(
            issued.cookie_secret(),
            Some(issued.csrf_secret()),
            RequestKind::Mutation,
            true,
            clock()
        )
        .is_none());
}
#[test]
fn r88_wrong_nonce_or_mfa_cannot_mint_session_and_expiry_revokes() {
    use identity_core::browser_session::{BrowserSessionVault, RequestKind};
    let f = Fixture::new();
    let access = f.access();
    let good = f.sign(&f.id(&access), KID, "JWT");
    assert!(f
        .pinned
        .verify_offline_browser_pair(CLIENT, &"x".repeat(43), &good, &access)
        .is_err());
    let mut weak = f.id(&access);
    weak["amr"] = json!(["pwd"]);
    assert!(f
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &f.sign(&weak, KID, "JWT"), &access)
        .is_err());
    let identity = f
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &good, &access)
        .unwrap();
    let expiry = identity.expires_at();
    let mut vault = BrowserSessionVault::default();
    let issued = vault.issue(identity, clock()).unwrap();
    let old = issued.cookie_secret().to_owned();
    assert!(vault
        .authenticate(
            &old,
            Some(issued.csrf_secret()),
            RequestKind::Mutation,
            true,
            expiry
        )
        .is_none());
    assert_eq!(vault.active_count(), 0);
    assert!(!vault.revoke(&old));
}
#[test]
fn r88_session_rotation_invalidates_prior_cookie_and_csrf() {
    use identity_core::browser_session::{BrowserSessionVault, RequestKind};
    let f = Fixture::new();
    let access = f.access();
    let id = f.sign(&f.id(&access), KID, "JWT");
    let mut vault = BrowserSessionVault::default();
    let first = vault
        .issue(
            f.pinned
                .verify_offline_browser_pair(CLIENT, NONCE, &id, &access)
                .unwrap(),
            clock(),
        )
        .unwrap();
    assert!(vault.revoke(first.cookie_secret()));
    let next = vault
        .issue(
            f.pinned
                .verify_offline_browser_pair(CLIENT, NONCE, &id, &access)
                .unwrap(),
            clock(),
        )
        .unwrap();
    assert_ne!(first.cookie_secret(), next.cookie_secret());
    assert_ne!(first.csrf_secret(), next.csrf_secret());
    assert!(vault
        .authenticate(
            first.cookie_secret(),
            Some(first.csrf_secret()),
            RequestKind::Mutation,
            true,
            clock()
        )
        .is_none());
    assert!(vault
        .authenticate(
            next.cookie_secret(),
            Some(first.csrf_secret()),
            RequestKind::Mutation,
            true,
            clock()
        )
        .is_none());
    assert!(vault
        .authenticate(
            next.cookie_secret(),
            Some(next.csrf_secret()),
            RequestKind::Mutation,
            true,
            clock()
        )
        .is_some());
}

#[test]
fn r88_capacity_timing_malformed_cookies_and_missing_origin_fail_closed() {
    use identity_core::browser_session::{BrowserSessionVault, RequestKind};
    let f = Fixture::new();
    let access = f.access();
    let signed_id = f.sign(&f.id(&access), KID, "JWT");
    let mut vault = BrowserSessionVault::default();
    let first = vault
        .issue(
            f.pinned
                .verify_offline_browser_pair(CLIENT, NONCE, &signed_id, &access)
                .unwrap(),
            clock(),
        )
        .unwrap();
    assert!(vault
        .authenticate(
            "q".repeat(43).as_str(),
            None,
            RequestKind::Read,
            true,
            clock()
        )
        .is_none());
    assert!(vault
        .authenticate("invalid!", None, RequestKind::Read, true, clock())
        .is_none());
    assert!(vault
        .authenticate(
            first.cookie_secret(),
            None,
            RequestKind::Mutation,
            false,
            clock()
        )
        .is_none());
    assert!(vault
        .authenticate(
            first.cookie_secret(),
            None,
            RequestKind::Read,
            true,
            clock()
        )
        .is_some());
    for _ in 1..64 {
        let identity = f
            .pinned
            .verify_offline_browser_pair(CLIENT, NONCE, &signed_id, &access)
            .unwrap();
        assert!(vault.issue(identity, clock()).is_some());
    }
    assert_eq!(vault.active_count(), 64);
    let overflow = f
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &signed_id, &access)
        .unwrap();
    assert!(vault.issue(overflow, clock()).is_none());
    assert!(vault
        .authenticate(
            first.cookie_secret(),
            None,
            RequestKind::Read,
            true,
            first.expires_at()
        )
        .is_none());
    vault.prune(first.expires_at());
    assert_eq!(vault.active_count(), 0);
    let too_late = f
        .pinned
        .verify_offline_browser_pair(CLIENT, NONCE, &signed_id, &access)
        .unwrap();
    assert!(vault.issue(too_late, first.expires_at()).is_none());
}
