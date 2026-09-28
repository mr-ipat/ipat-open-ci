//! Strict private-only *incomplete* provider-owned browser OIDC PKCE start.
//! Callback consumes state and ALWAYS denies login until independently pinned
//! server-side code exchange, nonce-checked ID token and DB principal exist.
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::get,
    Router,
};
use identity_core::browser_pkce::Challenge;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const CALLBACK: &str = "http://127.0.0.1:48765/lab/auth/browser/callback";
const MAX_PENDING: usize = 16;
const MAX_AGE: Duration = Duration::from_secs(300);
struct Pending {
    started: Instant,
    _proof: Challenge,
}
pub(super) struct Config {
    endpoint: String,
    client_id: String,
    pending: Mutex<HashMap<String, Pending>>,
}
impl Config {
    fn validated(issuer: &str, endpoint: &str, client: &str) -> Option<Self> {
        let authority = issuer.strip_prefix("https://")?.split('/').next()?;
        let (host, port) = authority.split_once(':').unwrap_or((authority, "443"));
        if host.is_empty()
            || !host.is_ascii()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || v == b'-')
            })
            || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
            || issuer.ends_with('/')
            || !issuer.starts_with("https://")
            || issuer.contains(['?', '#', '@', '\\'])
            || issuer.chars().any(char::is_whitespace)
            || endpoint != format!("{issuer}/protocol/openid-connect/auth")
            || Challenge::random()
                .ok()?
                .authorize_url(endpoint, client, CALLBACK)
                .is_none()
        {
            return None;
        }
        Some(Self {
            endpoint: endpoint.into(),
            client_id: client.into(),
            pending: Mutex::new(HashMap::new()),
        })
    }
}
pub(super) fn from_owner_environment() -> Result<Arc<Config>, &'static str> {
    if unsafe { libc::geteuid() } == 0
        || std::env::var("IPAT_LAB_OIDC_VERIFY").as_deref() != Ok("YES")
        || std::env::var("IPAT_R86_BROWSER_FLOW").as_deref() != Ok("YES")
    {
        return Err("private independently signed browser preflight not enabled");
    }
    let issuer =
        std::env::var("IPAT_LAB_OIDC_ISSUER").map_err(|_| "missing owner pinned issuer")?;
    let endpoint = std::env::var("IPAT_R86_KEYCLOAK_AUTH_ENDPOINT")
        .map_err(|_| "missing owner approved endpoint")?;
    let client = std::env::var("IPAT_R86_PUBLIC_CLIENT_ID")
        .map_err(|_| "missing owner registered BFF client")?;
    Config::validated(&issuer, &endpoint, &client)
        .map(Arc::new)
        .ok_or("untrusted or malformed browser OIDC config")
}
fn safe_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h
}
fn deny(code: StatusCode) -> (StatusCode, HeaderMap, &'static str) {
    (
        code,
        safe_headers(),
        r#"{"authenticated":false,"lab_only":true}"#,
    )
}
async fn start(
    State(config): State<Arc<Config>>,
    headers: HeaderMap,
) -> (StatusCode, HeaderMap, &'static str) {
    // Never issue a browser state for an unknown/external Host or duplicate Host.
    if headers.get_all(header::HOST).iter().count() != 1
        || headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some("127.0.0.1:48765")
    {
        return deny(StatusCode::FORBIDDEN);
    }
    let mut pending = config.pending.lock().unwrap_or_else(|e| e.into_inner());
    pending.retain(|_, p| p.started.elapsed() < MAX_AGE);
    if pending.len() >= MAX_PENDING {
        return deny(StatusCode::TOO_MANY_REQUESTS);
    }
    let Ok(proof) = Challenge::random() else {
        return deny(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(url) = proof.authorize_url(&config.endpoint, &config.client_id, CALLBACK) else {
        return deny(StatusCode::SERVICE_UNAVAILABLE);
    };
    let state = proof.state().to_owned();
    pending.insert(
        state.clone(),
        Pending {
            started: Instant::now(),
            _proof: proof,
        },
    );
    let mut h = headers_for_redirect();
    let Ok(location) = HeaderValue::from_str(&url) else {
        return deny(StatusCode::SERVICE_UNAVAILABLE);
    };
    h.insert(header::LOCATION, location);
    let cookie=format!("ipat_lab_oidc_state={state}; HttpOnly; SameSite=Lax; Path=/lab/auth/browser/callback; Max-Age=300");
    let Ok(cookie) = HeaderValue::from_str(&cookie) else {
        return deny(StatusCode::SERVICE_UNAVAILABLE);
    };
    h.insert(header::SET_COOKIE, cookie);
    (StatusCode::SEE_OTHER, h, "")
}
fn headers_for_redirect() -> HeaderMap {
    let mut h = safe_headers();
    h.remove(header::CONTENT_TYPE);
    h
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
}
fn state_cookie(headers: &HeaderMap) -> Option<&str> {
    if headers.get_all(header::COOKIE).iter().count() != 1 {
        return None;
    }
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut found = None;
    for cookie in raw.split(';') {
        if let Some(state) = cookie.trim().strip_prefix("ipat_lab_oidc_state=") {
            if found.is_some() || !Challenge::valid_state(state) {
                return None;
            }
            found = Some(state);
        }
    }
    found
}
async fn callback(
    State(config): State<Arc<Config>>,
    headers: HeaderMap,
    Query(q): Query<Callback>,
) -> (StatusCode, HeaderMap, &'static str) {
    if headers.get_all(header::HOST).iter().count() != 1
        || headers.get(header::HOST).and_then(|v| v.to_str().ok()) != Some("127.0.0.1:48765")
    {
        return deny(StatusCode::FORBIDDEN);
    }
    if !Challenge::valid_state(&q.state)
        || !q.code.as_deref().is_some_and(|c| {
            !c.is_empty()
                && c.len() <= 1024
                && c.bytes()
                    .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_' | b'.' | b'~'))
        })
        || q.error.is_some()
    {
        return deny(StatusCode::BAD_REQUEST);
    }
    let Some(cookie) = state_cookie(&headers) else {
        return deny(StatusCode::FORBIDDEN);
    };
    if !bool::from(cookie.as_bytes().ct_eq(q.state.as_bytes())) {
        return deny(StatusCode::FORBIDDEN);
    }
    let mut pending = config.pending.lock().unwrap_or_else(|e| e.into_inner());
    let Some(proof) = pending.remove(&q.state) else {
        return deny(StatusCode::FORBIDDEN);
    };
    if proof.started.elapsed() >= MAX_AGE {
        return deny(StatusCode::FORBIDDEN);
    }
    // No OAuth token exchange or fake login. Consume-once, clear lab cookie,
    // and always deny until an independently validated confidential BFF exists.
    let mut h = safe_headers();
    h.insert(header::SET_COOKIE,HeaderValue::from_static(
       "ipat_lab_oidc_state=; HttpOnly; SameSite=Lax; Path=/lab/auth/browser/callback; Max-Age=0"));
    (
        StatusCode::SERVICE_UNAVAILABLE,
        h,
        r#"{"authenticated":false,"lab_only":true,"authorization_code_discarded":true}"#,
    )
}
pub(super) fn router(config: Arc<Config>) -> Router {
    Router::new()
        .route("/lab/auth/browser/start", get(start))
        .route("/lab/auth/browser/callback", get(callback))
        .with_state(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    fn config() -> Arc<Config> {
        Arc::new(
            Config::validated(
                "https://id.example.invalid/realms/lab",
                "https://id.example.invalid/realms/lab/protocol/openid-connect/auth",
                "ipat-browser-lab",
            )
            .unwrap(),
        )
    }
    fn req(path: &str, host: &str, cookie: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().uri(path).header("Host", host);
        if let Some(value) = cookie {
            b = b.header("Cookie", value)
        }
        b.body(Body::empty()).unwrap()
    }
    #[tokio::test]
    async fn actual_router_redirects_with_fresh_crypto_and_strict_loopback_cookie() {
        let router = router(config());
        let r = router
            .clone()
            .oneshot(req("/lab/auth/browser/start", "evil.invalid", None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = router
            .clone()
            .oneshot(req("/lab/auth/browser/start", "127.0.0.1:48765", None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()["referrer-policy"], "no-referrer");
        let cookie = r.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("HttpOnly; SameSite=Lax"));
        assert!(!cookie.contains("PRIVATE"));
        let state = cookie.split('=').nth(1).unwrap().split(';').next().unwrap();
        assert!(Challenge::valid_state(state));
        let loc = r.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            loc.starts_with("https://id.example.invalid/realms/lab/protocol/openid-connect/auth?")
        );
        assert!(loc.contains(&format!("state={state}")));
        assert!(loc.contains("code_challenge_method=S256"));
        assert!(loc.contains("nonce="));
        assert!(!loc.contains("code_verifier"));
        let r2 = router
            .clone()
            .oneshot(req("/lab/auth/browser/start", "127.0.0.1:48765", None))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::SEE_OTHER);
        assert_ne!(
            r2.headers()[header::SET_COOKIE],
            r.headers()[header::SET_COOKIE]
        );
        let forged = format!("/lab/auth/browser/callback?state={state}&code=fake-code");
        assert_eq!(
            router
                .clone()
                .oneshot(req(
                    &forged,
                    "127.0.0.1:48765",
                    Some("ipat_lab_oidc_state=another-state")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let same_cookie = format!("ipat_lab_oidc_state={state}");
        let good = router
            .clone()
            .oneshot(req(&forged, "127.0.0.1:48765", Some(&same_cookie)))
            .await
            .unwrap();
        assert_eq!(good.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(good.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
        let body = to_bytes(good.into_body(), 256).await.unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("\"authenticated\":false"));
        assert_eq!(
            router
                .clone()
                .oneshot(req(&forged, "127.0.0.1:48765", Some(&same_cookie)))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn malicious_callback_duplicate_cookie_query_and_unknown_code_never_authenticate() {
        let cfg = config();
        let app = router(cfg.clone());
        let res = app
            .clone()
            .oneshot(req("/lab/auth/browser/start", "127.0.0.1:48765", None))
            .await
            .unwrap();
        let state = res.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let cookie = format!("ipat_lab_oidc_state={state}");
        for (path, cookie) in [
            (
                format!("/lab/auth/browser/callback?state={state}&code=abc&tenant=other"),
                cookie.clone(),
            ),
            (
                format!("/lab/auth/browser/callback?state={state}&code=abc"),
                format!("{cookie}; {cookie}"),
            ),
            (
                format!("/lab/auth/browser/callback?state={state}&error=access_denied"),
                cookie.clone(),
            ),
            (
                format!("/lab/auth/browser/callback?state={state}&code=abc%20x"),
                cookie.clone(),
            ),
            (
                format!("/lab/auth/browser/callback?state={state}&code="),
                cookie.clone(),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(req(&path, "127.0.0.1:48765", Some(&cookie)))
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::OK);
            assert_ne!(response.status(), StatusCode::SEE_OTHER);
        }
        let valid = format!("/lab/auth/browser/callback?state={state}&code=opaque-code");
        assert_eq!(
            app.oneshot(req(&valid, "127.0.0.1:48765", Some(&cookie)))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn pending_state_capacity_and_expiry_refuse_without_leaking() {
        let cfg = config();
        let app = router(cfg.clone());
        for _ in 0..MAX_PENDING {
            assert_eq!(
                app.clone()
                    .oneshot(req("/lab/auth/browser/start", "127.0.0.1:48765", None))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::SEE_OTHER
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(req("/lab/auth/browser/start", "127.0.0.1:48765", None))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let state = cfg.pending.lock().unwrap().keys().next().unwrap().clone();
        cfg.pending.lock().unwrap().get_mut(&state).unwrap().started = Instant::now() - MAX_AGE;
        assert_eq!(
            app.oneshot(req("/lab/auth/browser/start", "127.0.0.1:48765", None))
                .await
                .unwrap()
                .status(),
            StatusCode::SEE_OTHER
        );
    }
    #[test]
    fn malicious_provider_config_is_denied() {
        for (issuer,endpoint) in [
            ("http://id.example.invalid/realms/lab","http://id.example.invalid/realms/lab/protocol/openid-connect/auth"),
            ("https://id.example.invalid/realms/lab","https://evil.example.invalid/realms/lab/protocol/openid-connect/auth"),
            ("https://id.example.invalid/realms/lab","https://id.example.invalid/realms/lab/protocol/openid-connect/auth?redirect=https://evil.invalid")
        ] {assert!(Config::validated(issuer,endpoint,"ipat-browser-lab").is_none());}
    }
}
