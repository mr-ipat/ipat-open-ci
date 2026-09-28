//! Rust Control API laboratory bootstrap.
//! R5.9 adds an explicitly opted-in, read-only LOCAL web preview.
//! This is NOT an authenticated tenant dashboard or a production/public UI.

mod browser_session_lab;
mod device_review_lab;
mod device_workbench_lab;
mod oidc_browser_lab;
mod oidc_lab;
mod site_a_pairing_lab;
mod tenant_membership_lab;

use identity_core::PinnedIssuer;
use std::sync::Arc;

use axum::{
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Html,
    routing::get,
    Router,
};

const LAB_INDEX: &str = include_str!("../../../web/lab/index.html");
const LAB_CSS: &str = include_str!("../../../web/lab/style.css");
const LAB_JS: &str = include_str!("../../../web/lab/app.js");
const LAB_DASHBOARD_PREVIEW: &str = include_str!("../../../web/lab/dashboard-preview.html");
const LAB_DASHBOARD_CSS: &str = include_str!("../../../web/lab/dashboard-preview.css");
const LAB_DASHBOARD_JS: &str = include_str!("../../../web/lab/dashboard-preview.js");
// Public project target taxonomy only. Not an enrollment record or real device data.
const LAB_DEVICE_TARGETS: &str = include_str!("../../../web/lab/device-targets.json");
// Product-owner approved rollout SEQUENCING, not a trusted entitlement or
// authority for actual devices. Runtime never learns a tenant from Host.
const LAB_ROLLOUT_PHASE: &str = include_str!("../../../web/lab/rollout-phase.json");
const LAB_STATUS: &str = r#"{"mode":"ssh-loopback-only","production_access":false,"authentication_enabled":false,"device_operations_enabled":false,"backend":"online"}"#;

fn bind_address(k3s_lab: bool) -> &'static str {
    if k3s_lab {
        "0.0.0.0:3000"
    } else {
        "127.0.0.1:3000"
    }
}

/// Separate strictly loopback-only private canary: NEVER alter the
/// existing :3000 lab or :3001 identity listener and never serve in K3s.
fn private_canary_bind(k3s_lab: bool, lab: bool, identity: bool, requested: bool) -> &'static str {
    if requested && lab && !identity && !k3s_lab {
        "127.0.0.1:3002"
    } else {
        identity_lab_bind_address(k3s_lab, identity)
    }
}

fn lab_web_enabled(k3s_lab: bool, lab_requested: bool) -> bool {
    lab_requested && !k3s_lab
}

fn identity_lab_bind_address(k3s_lab: bool, enabled: bool) -> &'static str {
    if !k3s_lab && enabled {
        "127.0.0.1:3001"
    } else {
        bind_address(k3s_lab)
    }
}

fn private_lab_headers(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers
}

async fn lab_index() -> (HeaderMap, Html<&'static str>) {
    (
        private_lab_headers("text/html; charset=utf-8"),
        Html(LAB_INDEX),
    )
}

async fn lab_css() -> (HeaderMap, &'static str) {
    (private_lab_headers("text/css; charset=utf-8"), LAB_CSS)
}

async fn lab_js() -> (HeaderMap, &'static str) {
    (
        private_lab_headers("text/javascript; charset=utf-8"),
        LAB_JS,
    )
}

async fn lab_dashboard_preview() -> (HeaderMap, Html<&'static str>) {
    (
        private_lab_headers("text/html; charset=utf-8"),
        Html(LAB_DASHBOARD_PREVIEW),
    )
}

async fn lab_dashboard_css() -> (HeaderMap, &'static str) {
    (
        private_lab_headers("text/css; charset=utf-8"),
        LAB_DASHBOARD_CSS,
    )
}

async fn lab_dashboard_js() -> (HeaderMap, &'static str) {
    (
        private_lab_headers("text/javascript; charset=utf-8"),
        LAB_DASHBOARD_JS,
    )
}

async fn lab_status() -> (HeaderMap, &'static str) {
    (
        private_lab_headers("application/json; charset=utf-8"),
        LAB_STATUS,
    )
}

async fn lab_device_targets() -> (HeaderMap, &'static str) {
    (
        private_lab_headers("application/json; charset=utf-8"),
        LAB_DEVICE_TARGETS,
    )
}

async fn lab_rollout_phase() -> (HeaderMap, &'static str) {
    (
        private_lab_headers("application/json; charset=utf-8"),
        LAB_ROLLOUT_PHASE,
    )
}

async fn unauthenticated_business_api() -> (HeaderMap, StatusCode) {
    // No OIDC verifier, verified tenant membership, or permission to reveal
    // even aggregate business information yet. NEVER trust role/tenant headers.
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (h, StatusCode::UNAUTHORIZED)
}

#[cfg(test)]
fn app_with_lab(lab_web_enabled: bool) -> Router {
    app_with_lab_identity(lab_web_enabled, None)
}

fn app_with_lab_identity(lab_web_enabled: bool, verifier: Option<Arc<PinnedIssuer>>) -> Router {
    app_with_lab_identity_and_store(lab_web_enabled, verifier, None)
}

fn app_with_lab_identity_and_store(
    lab_web_enabled: bool,
    verifier: Option<Arc<PinnedIssuer>>,
    store: Option<Arc<tenant_membership_lab::Store>>,
) -> Router {
    let api = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/v1/platform/{*path}",
            axum::routing::any(unauthenticated_business_api),
        )
        .route(
            "/v1/tenant/{*path}",
            axum::routing::any(unauthenticated_business_api),
        )
        .route(
            "/v1/operations/{*path}",
            axum::routing::any(unauthenticated_business_api),
        )
        .route(
            "/v1/devices/{device_id}",
            get(|| async {
                // Trusted OIDC/tenant binding is not implemented. No ID enumeration.
                StatusCode::UNAUTHORIZED
            }),
        );
    if lab_web_enabled {
        let mut private = api
            .route("/lab", get(lab_index))
            .route("/lab/", get(lab_index))
            .route("/lab/style.css", get(lab_css))
            .route("/lab/app.js", get(lab_js))
            .route("/lab/status", get(lab_status))
            .route("/lab/device-targets", get(lab_device_targets))
            .route("/lab/rollout-phase", get(lab_rollout_phase))
            .route("/lab/dashboard-preview", get(lab_dashboard_preview))
            .route("/lab/dashboard-preview.css", get(lab_dashboard_css))
            .route("/lab/dashboard-preview.js", get(lab_dashboard_js))
            .merge(device_workbench_lab::router());
        if let Some(verifier) = verifier {
            private = private.merge(oidc_lab::router(verifier));
            if let Some(store) = store {
                private = private.merge(tenant_membership_lab::router(store));
            }
        }
        private
    } else {
        api
    }
}

#[cfg(test)]
fn app() -> Router {
    app_with_lab(false)
}

#[tokio::main]
async fn main() {
    let k3s_lab = std::env::var("IPAT_RUN_K3S_LAB").as_deref() == Ok("1");
    let lab_requested = std::env::var("IPAT_LAB_WEB").as_deref() == Ok("1");
    // Fail closed: never expose unauthenticated lab HTML through the K3s pod bind.
    let lab_web_enabled = lab_web_enabled(k3s_lab, lab_requested);
    let identity =
        if lab_web_enabled && std::env::var("IPAT_LAB_OIDC_VERIFY").as_deref() == Ok("YES") {
            Some(
                oidc_lab::from_owner_environment()
                    .expect("invalid owner-controlled OIDC signature lab prerequisites"),
            )
        } else {
            None
        };
    // A database-backed membership lab MUST be both explicit and identity
    // verified; it cannot be silently enabled on the public K3s bind.
    let scoped_requested = std::env::var("IPAT_LAB_SCOPED_MEMBERSHIP").as_deref() == Ok("YES");
    if scoped_requested && identity.is_none() {
        panic!("private membership lab requires an opted-in pinned OIDC verifier");
    }
    let store = if scoped_requested {
        Some(
            tenant_membership_lab::from_owner_environment(
                identity.clone().expect("verified issuer required"),
            )
            .expect("invalid owner-provisioned restricted PostgreSQL lab prerequisites"),
        )
    } else {
        None
    };
    // R8.3 is a SEPARATE explicitly requested registrar identity,
    // NEVER the old read-only PostgreSQL service account, and NEVER K3s.
    let registry_requested = std::env::var("IPAT_R83_REGISTRY_WRITE").as_deref() == Ok("YES");
    if registry_requested && (!scoped_requested || identity.is_none() || k3s_lab) {
        panic!("registry drafts require opted-in private signed OIDC and scoped SQL");
    }
    // R8.4 separate security_admin maker-checker metadata reviewer.
    // No real-human MFA enrollment, physical adoption or public gateway.
    let review_requested = std::env::var("IPAT_R84_SIMULATED_REVIEW").as_deref() == Ok("YES");
    if review_requested && (!scoped_requested || identity.is_none() || k3s_lab) {
        panic!("simulated review requires private signed identity and SQL");
    }
    let review = if review_requested {
        Some(
            device_review_lab::from_owner_environment(
                identity.clone().expect("pinned reviewer issuer required"),
            )
            .expect("reviewer needs independently restricted private PostgreSQL identity"),
        )
    } else {
        None
    };
    let registry = if registry_requested {
        Some(
            tenant_membership_lab::registration_from_owner_environment(
                identity.clone().expect("pinned issuer needed"),
            )
            .expect("invalid dedicated private registrar prerequisites"),
        )
    } else {
        None
    };
    // Never serve restricted identity proof from the public K3s interface.
    let private_canary = std::env::var("IPAT_R911_PRIVATE_CANARY").as_deref() == Ok("YES");
    if private_canary
        && (!lab_web_enabled
            || identity.is_some()
            || scoped_requested
            || registry_requested
            || review_requested
            || k3s_lab)
    {
        panic!("private no-identity canary requires explicit isolated non-K3s lab");
    }
    let address = private_canary_bind(k3s_lab, lab_web_enabled, identity.is_some(), private_canary);
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind isolated identity/dashboard lab listener");
    let mut app = app_with_lab_identity_and_store(lab_web_enabled, identity, store);
    if let Some(registry) = registry {
        app = app.merge(tenant_membership_lab::registry_router(registry));
    }
    if let Some(reviewer) = review {
        app = app.merge(device_review_lab::router(reviewer));
    }
    // Distinct opt-in private browser START/CALLBACK proof only; never a
    // public IdP callback, token exchange or login entitlement.
    let browser_requested = std::env::var("IPAT_R86_BROWSER_FLOW").as_deref() == Ok("YES");
    if browser_requested {
        if !lab_web_enabled || std::env::var("IPAT_LAB_OIDC_VERIFY").as_deref() != Ok("YES") {
            panic!("browser flow requires independently verified private OIDC laboratory");
        }
        app = app.merge(oidc_browser_lab::router(
            oidc_browser_lab::from_owner_environment()
                .expect("unsafe or missing explicitly approved browser provider configuration"),
        ));
    }
    axum::serve(listener, app).await.expect("serve API");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    async fn get_path(router: Router, uri: &str) -> axum::response::Response {
        router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[test]
    fn network_bind_is_loopback_unless_explicit_k3s_lab() {
        assert_eq!(bind_address(false), "127.0.0.1:3000");
        assert_eq!(bind_address(true), "0.0.0.0:3000");
        assert_eq!(identity_lab_bind_address(false, true), "127.0.0.1:3001");
        assert_eq!(identity_lab_bind_address(false, false), "127.0.0.1:3000");
        assert_eq!(identity_lab_bind_address(true, true), "0.0.0.0:3000");
    }

    #[test]
    fn private_canary_has_strict_loopback_only_and_never_changes_live_ports() {
        assert_eq!(
            private_canary_bind(false, true, false, true),
            "127.0.0.1:3002"
        );
        assert_eq!(
            private_canary_bind(false, true, false, false),
            "127.0.0.1:3000"
        );
        assert_eq!(
            private_canary_bind(false, true, true, true),
            "127.0.0.1:3001"
        );
        assert_eq!(
            private_canary_bind(true, false, false, true),
            "0.0.0.0:3000"
        );
        assert!(!lab_web_enabled(true, true));
    }

    #[tokio::test]
    async fn health_endpoint_responds() {
        let response = get_path(app(), "/healthz").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn data_endpoint_denies_anonymous_requests_even_with_tenant_header() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/v1/devices/123")
                    .header("X-Tenant-Id", "kangnet")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lab_routes_are_missing_by_default_and_on_k3s_router() {
        for uri in [
            "/lab",
            "/lab/",
            "/lab/style.css",
            "/lab/app.js",
            "/lab/status",
            "/lab/device-targets",
            "/lab/rollout-phase",
            "/lab/dashboard-preview",
            "/lab/dashboard-preview.css",
            "/lab/dashboard-preview.js",
        ] {
            let response = get_path(app(), uri).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        assert!(!lab_web_enabled(false, false));
        assert!(lab_web_enabled(false, true));
        assert!(!lab_web_enabled(true, false));
        assert!(!lab_web_enabled(true, true));
    }

    #[tokio::test]
    async fn private_lab_has_browser_content_and_restrictive_headers() {
        let response = get_path(app_with_lab(true), "/lab").await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert!(headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'"));
        assert!(LAB_INDEX.contains("Mode terbatas"));
        assert!(LAB_INDEX.contains("Mr. iPat"));
        assert!(!LAB_INDEX.contains("type=\"password\""));
    }

    #[tokio::test]
    async fn r911_physical_evidence_is_never_mounted_in_public_or_k3s_mode() {
        let path = "/lab/device-physical-evidence";
        assert_eq!(get_path(app(), path).await.status(), StatusCode::NOT_FOUND);
        assert!(!lab_web_enabled(true, true));
        let response = get_path(app_with_lab(true), path).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["device_adopted"], false);
        assert_eq!(data["out_of_band_host_key_verified"], false);
        assert_eq!(data["olt_commands_executed"], 0);
    }

    #[tokio::test]
    async fn planned_device_targets_are_private_preview_only_and_not_enrollment() {
        let response = get_path(app_with_lab(true), "/lab/device-targets").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert!(LAB_DEVICE_TARGETS.contains("\"catalog_mode\": \"planned_targets_only\""));
        assert!(LAB_DEVICE_TARGETS.contains("\"physical_devices_enrolled\": 0"));
        assert!(LAB_DEVICE_TARGETS.contains("\"network_discovery_enabled\": false"));
        assert!(LAB_DEVICE_TARGETS.contains("\"access_gate\": \"ssh_host_key_changed_unverified\""));
        let response = get_path(app_with_lab(false), "/lab/device-targets").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn private_phase_may_defer_domains_but_never_tenant_isolation() {
        let response = get_path(app_with_lab(true), "/lab/rollout-phase").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let policy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(policy["phase"], "private_single_endpoint_device_lab");
        assert_eq!(policy["domain_verification_deferred"], true);
        assert_eq!(policy["custom_domains_enabled"], false);
        assert_eq!(policy["public_tenant_hostnames_enabled"], false);
        assert_eq!(policy["tenant_isolation_mandatory"], true);
        assert_eq!(policy["tenant_isolation_end_to_end_verified"], false);
        assert_eq!(policy["authenticated_tenant_data_apis_enabled"], false);
        assert_eq!(policy["physical_device_connected"], false);
        assert_eq!(policy["device_reads_approved"], false);
        assert_eq!(policy["firmware_updates_enabled"], false);
        assert_eq!(
            get_path(app(), "/lab/rollout-phase").await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn rollout_status_cannot_be_mutated_to_enable_domains_or_device_access() {
        for method in ["POST", "PUT", "DELETE"] {
            let response = app_with_lab(true)
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/lab/rollout-phase")
                        .header("Host", "forged.customer.invalid")
                        .header("X-Tenant-Id", "synthetic-b")
                        .header("X-Verified-Role", "platform_owner")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    #[tokio::test]
    async fn private_catalog_rejects_mutation_without_fake_authentication() {
        let response = app_with_lab(true)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/lab/device-targets")
                    .header("X-Tenant-Id", "kangnet")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn all_real_business_api_calls_deny_even_with_forged_tenant_role_and_host() {
        for path in [
            "/v1/platform/overview",
            "/v1/platform/tenants",
            "/v1/tenant/overview",
            "/v1/tenant/subscribers",
            "/v1/operations/overview",
            "/v1/operations/devices",
        ] {
            for method in ["GET", "POST", "DELETE"] {
                let response = app_with_lab(true)
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .header("Authorization", "Bearer forged.lab.identity")
                            .header("X-Tenant-Id", "wrong-tenant")
                            .header("X-Verified-Role", "platform_owner")
                            .header("Host", "other-tenant.invalid")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{method} {path}"
                );
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            }
        }
    }

    #[tokio::test]
    async fn all_three_preview_assets_are_private_and_never_enable_real_api() {
        for (uri, mime) in [
            ("/lab/dashboard-preview", "text/html; charset=utf-8"),
            ("/lab/dashboard-preview.css", "text/css; charset=utf-8"),
            (
                "/lab/dashboard-preview.js",
                "text/javascript; charset=utf-8",
            ),
        ] {
            let response = get_path(app_with_lab(true), uri).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], mime);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("default-src 'none'"));
            assert_eq!(
                get_path(app_with_lab(false), uri).await.status(),
                StatusCode::NOT_FOUND
            );
        }
        assert!(LAB_DASHBOARD_PREVIEW.contains("Pengalih ini hanya mengganti tampilan"));
        assert!(!LAB_DASHBOARD_JS.contains("document.cookie"));
        assert!(!LAB_DASHBOARD_JS.contains("localStorage"));
        assert!(!LAB_DASHBOARD_PREVIEW.contains("type=\"password\""));
    }

    #[tokio::test]
    async fn private_lab_assets_and_status_are_read_only() {
        for (uri, mime) in [
            ("/lab/style.css", "text/css; charset=utf-8"),
            ("/lab/app.js", "text/javascript; charset=utf-8"),
            ("/lab/status", "application/json; charset=utf-8"),
        ] {
            let response = get_path(app_with_lab(true), uri).await;
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], mime);
        }
        assert!(LAB_STATUS.contains("\"production_access\":false"));
        assert!(LAB_STATUS.contains("\"authentication_enabled\":false"));
    }
}
