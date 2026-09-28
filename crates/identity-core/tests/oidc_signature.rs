//! A dynamically generated, never checked-in RSA key proves actual RS256
//! signature verification. This is not a live IdP, database or MFA test.
use identity_core::{IdentityError, PinnedIssuer};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const ISSUER: &str = "https://id.example.invalid/realms/ipat";
const AUD: &str = "ipat-control-api";
const KID: &str = "test-pinned-key";
struct Keys {
    _temp: tempfile::TempDir,
    private: Vec<u8>,
    public: Vec<u8>,
}
fn keys() -> Keys {
    let temp = tempfile::tempdir().unwrap();
    let private = temp.path().join("synthetic-private.pem");
    let public = temp.path().join("synthetic-public.pem");
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
    assert!(
        result.status.success(),
        "temporary synthetic openssl generation failed"
    );
    let result = Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(&private)
        .arg("-out")
        .arg(&public)
        .output()
        .unwrap();
    assert!(result.status.success());
    Keys {
        private: fs::read(private).unwrap(),
        public: fs::read(public).unwrap(),
        _temp: temp,
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn claims() -> Value {
    let t = now();
    json!({"iss":ISSUER,"aud":AUD,"sub":"operator-123","iat":t,
        "nbf":t,"exp":t+600,"tenant_id":"evil-other-tenant",
        "realm_access":{"roles":["platform_owner","super_admin"]}})
}
fn verifier(key: &[u8]) -> PinnedIssuer {
    PinnedIssuer::new(ISSUER, AUD, KID, key).unwrap()
}
fn sign(c: &Value, pem: &[u8], kid: &str) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(kid.to_owned());
    h.typ = Some("JWT".to_owned());
    encode(&h, c, &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
}
#[test]
fn real_signed_token_is_accepted_but_untrusted_role_and_tenant_claims_are_ignored() {
    let k = keys();
    let token = sign(&claims(), &k.private, KID);
    let who = verifier(&k.public).verify_access_token(&token).unwrap();
    assert_eq!(who.issuer(), ISSUER);
    assert_eq!(who.subject(), "operator-123");
    assert!(who.expires_at() > now());
    // VerifiedSubject has NO membership, role or tenant accessor;
    // the only claims passed across this boundary are sub and expiry.
}
#[test]
fn independent_rsa_key_and_mutated_signature_cannot_impersonate_user() {
    let k = keys();
    let attacker = keys();
    let verifier = verifier(&k.public);
    assert!(matches!(
        verifier.verify_access_token(&sign(&claims(), &attacker.private, KID)),
        Err(IdentityError::InvalidSignatureOrClaims)
    ));
    let signed = sign(&claims(), &k.private, KID);
    let mut parts: Vec<_> = signed.split('.').map(str::to_owned).collect();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(0..1, replacement);
    assert!(verifier.verify_access_token(&parts.join(".")).is_err());
}
#[test]
fn mismatched_kid_missing_kid_and_hs256_alg_confusion_denied() {
    let k = keys();
    let v = verifier(&k.public);
    assert_eq!(
        v.verify_access_token(&sign(&claims(), &k.private, "untrusted-kid"))
            .err(),
        Some(IdentityError::InvalidToken)
    );
    let mut h = Header::new(Algorithm::RS256);
    h.typ = Some("JWT".into());
    let no_kid = encode(
        &h,
        &claims(),
        &EncodingKey::from_rsa_pem(&k.private).unwrap(),
    )
    .unwrap();
    assert_eq!(
        v.verify_access_token(&no_kid).err(),
        Some(IdentityError::InvalidToken)
    );
    let mut h = Header::new(Algorithm::HS256);
    h.kid = Some(KID.to_owned());
    h.typ = Some("JWT".into());
    let hs = encode(&h, &claims(), &EncodingKey::from_secret(&k.public)).unwrap();
    assert_eq!(
        v.verify_access_token(&hs).err(),
        Some(IdentityError::InvalidToken)
    );
}
#[test]
fn issuer_audience_and_missing_time_claims_are_checked_not_from_http_headers() {
    let k = keys();
    let v = verifier(&k.public);
    for (key, value) in [
        ("iss", json!("https://attacker.invalid/realms/ipat")),
        ("aud", json!("different-service")),
        ("sub", json!("line\nsecret")),
    ] {
        let mut c = claims();
        c[key] = value;
        assert!(
            v.verify_access_token(&sign(&c, &k.private, KID)).is_err(),
            "{key}"
        );
    }
    for key in ["iss", "aud", "sub", "nbf", "iat", "exp"] {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(key);
        assert!(
            v.verify_access_token(&sign(&c, &k.private, KID)).is_err(),
            "{key}"
        );
    }
}
#[test]
fn exp_nbf_future_issued_and_overlong_access_tokens_are_denied() {
    let k = keys();
    let v = verifier(&k.public);
    let mut expired = claims();
    expired["iat"] = json!(now() - 1200);
    expired["nbf"] = json!(now() - 1200);
    expired["exp"] = json!(now() - 1000);
    assert!(v
        .verify_access_token(&sign(&expired, &k.private, KID))
        .is_err());
    let mut future = claims();
    future["iat"] = json!(now() + 1800);
    future["nbf"] = json!(now() + 1800);
    future["exp"] = json!(now() + 1850);
    assert!(v
        .verify_access_token(&sign(&future, &k.private, KID))
        .is_err());
    let mut excessive = claims();
    excessive["exp"] = json!(now() + 3600);
    assert_eq!(
        v.verify_access_token(&sign(&excessive, &k.private, KID))
            .err(),
        Some(IdentityError::TokenLifetimeExceeded)
    );
    assert_eq!(
        v.verify_access_token(&"A".repeat(8193)).err(),
        Some(IdentityError::InvalidToken)
    );
}
#[test]
fn audience_array_from_wrong_target_is_rejected_and_no_implicit_key_discovery() {
    let k = keys();
    let v = verifier(&k.public);
    let mut c = claims();
    c["aud"] = json!([AUD, "malicious-other-client"]);
    assert!(v.verify_access_token(&sign(&c, &k.private, KID)).is_err());
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(KID.to_owned());
    h.typ = Some("at+jwt".into());
    h.jku = Some("https://attacker.invalid/keys".into());
    let signed = encode(
        &h,
        &claims(),
        &EncodingKey::from_rsa_pem(&k.private).unwrap(),
    )
    .unwrap();
    assert_eq!(
        v.verify_access_token(&signed).err(),
        Some(IdentityError::InvalidToken)
    );
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(KID.to_owned());
    h.typ = Some("JWT".into());
    h.x5u = Some("https://attacker.invalid/rogue-cert".into());
    let signed = encode(
        &h,
        &claims(),
        &EncodingKey::from_rsa_pem(&k.private).unwrap(),
    )
    .unwrap();
    assert_eq!(
        v.verify_access_token(&signed).err(),
        Some(IdentityError::InvalidToken)
    );
}
