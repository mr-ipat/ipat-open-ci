//! Explicitly private OIDC *signature-only* laboratory probe.
//! Verified JWT subject != verified tenant membership, POP scope, MFA or role.
//! This route NEVER constructs a business principal or unlocks business APIs.
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::get,
    Router,
};
use identity_core::PinnedIssuer;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt},
    path::PathBuf,
    sync::Arc,
};
const MAX_KEY_BYTES: u64 = 16 * 1024;
const VERIFIED_NO_MEMBERSHIP: &str = r#"{"jwt_signature_verified":true,"tenant_membership_verified":false,"business_access_enabled":false,"roles_verified":false}"#;
fn private_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h
}
async fn verify_only(
    State(verifier): State<Arc<PinnedIssuer>>,
    headers: HeaderMap,
) -> (StatusCode, HeaderMap, &'static str) {
    let h = private_headers();
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return (StatusCode::UNAUTHORIZED, h, "");
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.contains(' ') && !value.contains(','));
    let Some(token) = token else {
        return (StatusCode::UNAUTHORIZED, h, "");
    };
    if verifier.verify_access_token(token).is_err() {
        return (StatusCode::UNAUTHORIZED, h, "");
    }
    // No tenant or role entitlement can be inferred from JWT signature.
    // The subject is neither printed nor returned to an untrusted client.
    (StatusCode::OK, h, VERIFIED_NO_MEMBERSHIP)
}
pub(super) fn router(verifier: Arc<PinnedIssuer>) -> Router {
    Router::new()
        .route("/lab/auth/verify", get(verify_only))
        .with_state(verifier)
}
/// Only called for explicit opt-in on owner-controlled *loopback* lab.
/// The signing key itself is NOT accepted from an HTTP header or JWKS URL.
pub(super) fn from_owner_environment() -> Result<Arc<PinnedIssuer>, &'static str> {
    if std::env::var("IPAT_LAB_OIDC_VERIFY").as_deref() != Ok("YES")
        || unsafe { libc::geteuid() } == 0
    {
        return Err("not an explicit nonroot owner laboratory");
    }
    let path = PathBuf::from(
        std::env::var("IPAT_LAB_OIDC_PUBLIC_KEY_FILE")
            .map_err(|_| "missing private pinned public key path")?,
    );
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("pinned key must be an absolute safe path");
    }
    let parent = path.parent().ok_or("missing owner private directory")?;
    for (point, required) in [(parent, 0o700), (path.as_path(), 0o600)] {
        let m = std::fs::symlink_metadata(point).map_err(|_| "untrusted file")?;
        if m.file_type().is_symlink()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != required
        {
            return Err("unsafe file ownership or permissions");
        }
    }
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot open pinned public key")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect pinned public key")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_KEY_BYTES
    {
        return Err("unsafe pinned public key");
    }
    let mut key = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut key)
        .map_err(|_| "cannot read pinned public key")?;
    if key.len() as u64 > MAX_KEY_BYTES {
        return Err("oversized pinned public key");
    }
    let issuer = std::env::var("IPAT_LAB_OIDC_ISSUER").map_err(|_| "missing trusted issuer")?;
    let audience =
        std::env::var("IPAT_LAB_OIDC_AUDIENCE").map_err(|_| "missing trusted audience")?;
    let kid = std::env::var("IPAT_LAB_OIDC_KID").map_err(|_| "missing trusted key ID")?;
    Ok(Arc::new(
        PinnedIssuer::new(&issuer, &audience, &kid, &key)
            .map_err(|_| "invalid trusted issuer or key config")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::{
        fs,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tower::ServiceExt;

    struct SyntheticIdentity {
        _dir: tempfile::TempDir,
        pem: Vec<u8>,
        verifier: Arc<PinnedIssuer>,
    }
    fn synthetic_identity() -> SyntheticIdentity {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("test-only.key");
        let public = dir.path().join("test-only.pub");
        let generate = Command::new("openssl")
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
        assert!(generate.status.success());
        let derive = Command::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(&private)
            .arg("-out")
            .arg(&public)
            .output()
            .unwrap();
        assert!(derive.status.success());
        let pubkey = fs::read(public).unwrap();
        let verifier = Arc::new(
            PinnedIssuer::new(
                "https://id.example.invalid/realms/lab",
                "ipat-control-api",
                "private-lab",
                &pubkey,
            )
            .unwrap(),
        );
        SyntheticIdentity {
            _dir: dir,
            pem: fs::read(private).unwrap(),
            verifier,
        }
    }
    fn token(key: &[u8]) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("private-lab".into());
        h.typ = Some("JWT".into());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claim = json!({"iss":"https://id.example.invalid/realms/lab",
            "aud":"ipat-control-api","sub":"synthetic-operator",
            "iat":now,"nbf":now,"exp":now+300,
            "roles":["platform_owner"],"tenant_id":"forged-synthetic-other"});
        encode(&h, &claim, &EncodingKey::from_rsa_pem(key).unwrap()).unwrap()
    }
    async fn call(
        router: Router,
        path: &str,
        method: &str,
        auth: Option<&str>,
        forged_identity: bool,
    ) -> axum::response::Response {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(value) = auth {
            b = b.header(header::AUTHORIZATION, value);
        }
        if forged_identity {
            b = b
                .header("x-tenant-id", "synthetic-other")
                .header("x-role", "platform_owner")
                .header("x-client-cert-verified", "true");
        }
        router
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn signed_private_lab_probe_does_not_authorize_any_business_endpoint() {
        let id = synthetic_identity();
        let signed = format!("Bearer {}", token(&id.pem));
        let app = crate::app_with_lab_identity(true, Some(id.verifier.clone()));
        let res = call(app.clone(), "/lab/auth/verify", "GET", Some(&signed), true).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(res.into_body(), 512).await.unwrap();
        assert_eq!(body.as_ref(), VERIFIED_NO_MEMBERSHIP.as_bytes());
        assert!(!body
            .windows("synthetic-operator".len())
            .any(|bytes| bytes == b"synthetic-operator"));
        for path in [
            "/v1/platform/tenants",
            "/v1/tenant/members",
            "/v1/operations/alerts",
            "/v1/devices/FAKE",
        ] {
            assert_eq!(
                call(app.clone(), path, "GET", Some(&signed), true)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
    }
    #[tokio::test]
    async fn invalid_unpinned_missing_or_forged_bearer_denied_in_real_router() {
        let id = synthetic_identity();
        let app = crate::app_with_lab_identity(true, Some(id.verifier.clone()));
        for auth in [
            None,
            Some(""),
            Some("Bearer "),
            Some("bearer fake"),
            Some("Basic dGVzdA=="),
            Some("Bearer x.y.z"),
            Some("Bearer x.y.z, Bearer fake"),
        ] {
            assert_eq!(
                call(app.clone(), "/lab/auth/verify", "GET", auth, true)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let signed = format!("Bearer {}", token(&id.pem));
        assert_eq!(
            call(app.clone(), "/lab/auth/verify", "POST", Some(&signed), true)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            call(
                crate::app_with_lab(false),
                "/lab/auth/verify",
                "GET",
                Some(&signed),
                false
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                crate::app_with_lab(true),
                "/lab/auth/verify",
                "GET",
                Some(&signed),
                false
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
}
