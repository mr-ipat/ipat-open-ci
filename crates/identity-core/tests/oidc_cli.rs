//! Real ORIGINAL Rust binary test using independently generated synthetic RSA.
//! This only validates signed AMR preflight, NOT a real enrolled human IdP.
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
const ISS: &str = "https://synthetic.invalid/realms/ipat";
const AUD: &str = "ipat-control-api";
const KID: &str = "synthetic-only-pinned-rsa";
const BIN: &str = env!("CARGO_BIN_EXE_oidc-mfa-preflight");
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
struct Fixture {
    _tmp: tempfile::TempDir,
    pem: std::path::PathBuf,
    signing_key: Vec<u8>,
}
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let priv_path = tmp.path().join("synthetic.key");
    let pub_path = tmp.path().join("pinned.pem");
    assert!(Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out"
        ])
        .arg(&priv_path)
        .output()
        .unwrap()
        .status
        .success());
    assert!(Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(&priv_path)
        .arg("-out")
        .arg(&pub_path)
        .output()
        .unwrap()
        .status
        .success());
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o600)).unwrap();
    Fixture {
        signing_key: fs::read(priv_path).unwrap(),
        pem: pub_path,
        _tmp: tmp,
    }
}
fn signed(key: &[u8], kid: &str, mfa: bool) -> String {
    let time = unix_now();
    let mut claims: Value = json!({"iss":ISS,"aud":AUD,"sub":"synthetic-reviewer",
        "iat":time,"nbf":time,"exp":time+300,
        "tenant_id":"forge-other-company",
        "realm_access":{"roles":["superadmin"]}});
    if mfa {
        claims["amr"] = json!(["pwd", "mfa"]);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    header.typ = Some("JWT".to_owned());
    encode(&header, &claims, &EncodingKey::from_rsa_pem(key).unwrap()).unwrap()
}
fn invoke(pem: &Path, token: &str, enabled: bool) -> Output {
    let mut child = Command::new(BIN)
        .arg("--verify")
        .env("IPAT_R85_ISSUER", ISS)
        .env("IPAT_R85_AUDIENCE", AUD)
        .env("IPAT_R85_KID", KID)
        .env("IPAT_R85_PINNED_PEM_FILE", pem)
        .env(
            "IPAT_R85_REAL_IDP_PREFLIGHT",
            if enabled { "YES" } else { "NO" },
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Intentionally default-denied child may exit BEFORE stdin is written.
    // BrokenPipe is the expected scheduler-dependent early-denial outcome,
    // not a reason to fail the regression suite on faster CI runners.
    let result = child.stdin.take().unwrap().write_all(token.as_bytes());
    // Any NEGATIVE prerequisite (disabled, unsafe key, symlink, etc.)
    // may close stdin before the parent finishes writing on fast CI.
    // Only BrokenPipe is tolerated; EACH caller still checks the child
    // exit code, so valid positive checks MUST finish successfully.
    if let Err(e) = result {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}
#[test]
fn preflight_is_default_denied_and_requirements_have_no_user_secrets() {
    let help = Command::new(BIN).arg("--requirements").output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("R85_REQUIRES_REAL_OPERATOR_CONTROLLED_OIDC_IDP"));
    assert!(text.contains("human") || text.contains("operator"));
    let f = fixture();
    let signed = signed(&f.signing_key, KID, true);
    let denied = invoke(&f.pem, &signed, false);
    assert_eq!(denied.status.code(), Some(4));
    assert!(denied.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&denied.stderr).contains(&signed));
}
#[test]
fn valid_pinned_signed_mfa_passes_but_never_grants_role_or_claims_human_enrollment() {
    let f = fixture();
    let token = signed(&f.signing_key, KID, true);
    let result = invoke(&f.pem, &format!("{token}\n"), true);
    assert!(result.status.success(), "{:?}", result.stderr);
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("R85_PINNED_SIGNED_MFA_CLAIM_PREFLIGHT=PASS"));
    assert!(output.contains("ACTUAL_HUMAN_MFA_ENROLLMENT_AND_BROWSER_SESSION=NOT_VERIFIED"));
    assert!(output.contains("PRODUCTION_DEVICE_OR_BUSINESS_ACCESS=DENIED"));
    assert!(!output.contains("synthetic-reviewer"));
    assert!(!output.contains(&token));
    assert!(!output.contains("forge-other-company"));
}
#[test]
fn missing_mfa_wrong_kid_and_forged_rsa_identity_fail_closed() {
    let f = fixture();
    let unsigned_mfa = signed(&f.signing_key, KID, false);
    assert_eq!(invoke(&f.pem, &unsigned_mfa, true).status.code(), Some(4));
    assert_eq!(
        invoke(&f.pem, &signed(&f.signing_key, "other-kid", true), true)
            .status
            .code(),
        Some(4)
    );
    let attacker = fixture();
    assert_eq!(
        invoke(&f.pem, &signed(&attacker.signing_key, KID, true), true)
            .status
            .code(),
        Some(4)
    );
    assert_eq!(
        invoke(&f.pem, "not-three-jwt-parts", true).status.code(),
        Some(4)
    );
    assert_eq!(
        invoke(&f.pem, &"x".repeat(8300), true).status.code(),
        Some(4)
    );
}
#[test]
fn rejects_key_world_readable_and_symlinked_even_with_valid_token() {
    let f = fixture();
    let token = signed(&f.signing_key, KID, true);
    fs::set_permissions(&f.pem, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(invoke(&f.pem, &token, true).status.code(), Some(4));
    fs::set_permissions(&f.pem, fs::Permissions::from_mode(0o600)).unwrap();
    let link = f.pem.with_file_name("insecure-symlink.pem");
    symlink(&f.pem, &link).unwrap();
    assert_eq!(invoke(&link, &token, true).status.code(), Some(4));
    assert!(invoke(&f.pem, &token, true).status.success());
}
