//! BBF USP v1.4 genuine protobuf STRICT STRUCTURAL-ONLY private parser.
//! NO trusted device identity or USP MQTT MTP has been implemented.
//! Real controller access remains UNAVAILABLE; the local parser never
//! queues, enrolls, transmits or replies to a real USP agent.

use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use usp_core::wire14::{inspect_no_session_get_response, MAX_RECORD_BYTES};

fn bind_address(k3s_lab: bool) -> &'static str {
    if k3s_lab {
        "0.0.0.0:3100"
    } else {
        "127.0.0.1:3100"
    }
}

fn health_only() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "synthetic-usp-lab-only" }))
        .fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })
}
fn app() -> Router {
    // Even structurally valid unauthenticated protobuf can NEVER enter
    // the real USP/tenant/device domain or receive a USP response.
    health_only()
        .route("/lab/inspect-usp14", post(lab_inspect))
        .layer(DefaultBodyLimit::max(MAX_RECORD_BYTES))
}
async fn lab_inspect(
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<serde_json::Value>), StatusCode> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let inspected = inspect_no_session_get_response(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut result_headers = HeaderMap::new();
    result_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    result_headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    result_headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    result_headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'"),
    );
    // NEVER expose the claimed sender/destination or parameters to HTTP.
    Ok((
        result_headers,
        Json(json!({
            "wire_schema": "BBF-USP-1.4",
            "record_structurally_valid": true,
            "message_type": "GetResp",
            "requested_paths": inspected.requested_paths,
            "resolved_paths": inspected.resolved_paths,
            "parameter_values": inspected.parameter_values,
            "peer_authenticated": false,
            "tenant_bound": false,
            "usp_session_established": false,
            "device_operations_enabled": false,
            "lab_only": true
        })),
    ))
}

#[tokio::main]
async fn main() {
    if std::env::var("IPAT_RUN_OFFLINE_USP_LAB").as_deref() != Ok("1") {
        eprintln!("USP network/MTP not implemented. Set IPAT_RUN_OFFLINE_USP_LAB=1 only for local health checks.");
        std::process::exit(2);
    }
    let k3s_lab = std::env::var("IPAT_RUN_K3S_LAB").as_deref() == Ok("1");
    let listener = tokio::net::TcpListener::bind(bind_address(k3s_lab))
        .await
        .expect("bind synthetic USP laboratory health listener");
    // Public/K3s lab may expose only non-operational health; the parser
    // is exclusively bound to opted-in non-K3s localhost.
    let router = if k3s_lab { health_only() } else { app() };
    axum::serve(listener, router)
        .await
        .expect("serve private parser or non-operational health only");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn network_bind_is_loopback_unless_explicit_k3s_lab() {
        assert_eq!(bind_address(false), "127.0.0.1:3100");
        assert_eq!(bind_address(true), "0.0.0.0:3100");
    }

    #[tokio::test]
    async fn private_lab_health_is_available() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn no_usp_transport_route_accepts_untrusted_agent_messages() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usp")
                    .header("X-Tenant-Id", "kangnet")
                    .header("X-Agent-Id", "synthetic-agent-a")
                    .body(Body::from("fake-USP"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn no_tenant_or_controller_data_endpoint_enabled() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/v1/tenants")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod usp_wire_http_tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    const GOLDEN: &[u8] =
        include_bytes!("../../../crates/usp-core/tests/fixtures/usp14_get_response.bin");
    async fn post(router: Router, raw: Vec<u8>, ct: &str) -> axum::response::Response {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/lab/inspect-usp14")
                    .header("content-type", ct)
                    .header("x-tenant-id", "fake-company")
                    .header("x-agent-id", "usp::sim-agent-a")
                    .body(Body::from(raw))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn private_real_http_parser_accepts_only_protobuf_structure_not_identity() {
        let result = post(app(), GOLDEN.to_vec(), "application/octet-stream").await;
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(result.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(result.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["wire_schema"], "BBF-USP-1.4");
        assert_eq!(value["message_type"], "GetResp");
        assert_eq!(value["requested_paths"], 1);
        assert_eq!(value["resolved_paths"], 1);
        assert_eq!(value["parameter_values"], 1);
        assert_eq!(value["peer_authenticated"], false);
        assert_eq!(value["tenant_bound"], false);
        assert_eq!(value["usp_session_established"], false);
        assert_eq!(value["device_operations_enabled"], false);
        assert_eq!(value["lab_only"], true);
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        for secret in [
            "sim-agent",
            "offline-controller",
            "SYNTHETIC",
            "Manufacturer",
            "fake-company",
            "Device.DeviceInfo",
        ] {
            assert!(!body.contains(secret), "{secret} leaked");
        }
    }
    #[tokio::test]
    async fn malformed_or_wrong_content_type_rejected_and_k3s_parser_absent() {
        assert_eq!(
            post(app(), GOLDEN.to_vec(), "text/xml").await.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            post(app(), b"not protobuf".to_vec(), "application/octet-stream")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut repeated = GOLDEN.to_vec();
        repeated.extend_from_slice(&[0x3a, 0]); // duplicate BBF record oneof
        assert_eq!(
            post(app(), repeated, "application/octet-stream")
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let too_large = vec![0xff; MAX_RECORD_BYTES + 1];
        assert_eq!(
            post(app(), too_large, "application/octet-stream")
                .await
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            post(health_only(), GOLDEN.to_vec(), "application/octet-stream")
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let denied = health_only()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/usp")
                    .body(Body::from(GOLDEN))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
