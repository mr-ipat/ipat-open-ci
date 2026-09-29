//! R8.3 PRIVATE DEMO DEVICE WORKBENCH, deliberately NOT tenant or CPE admission.
//! Live candidates belong to the separately signed JWT/PostgreSQL path.
//! This in-memory demo has no actual IP/serial/password input and never probes.
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    routing::{delete, get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

const HTML: &str = include_str!("../../../web/lab/device-workbench.html");
const CSS: &str = include_str!("../../../web/lab/device-workbench.css");
const JS: &str = include_str!("../../../web/lab/device-workbench.js");
const C320_FIRST_REAL_JS: &str = include_str!("../../../web/lab/c320-first-real-inventory.js");
const PHYSICAL_EVIDENCE: &str = include_str!("../../../web/lab/physical-intake-evidence.json");
const MAX_DEMO_CANDIDATES: usize = 24;

#[derive(Clone, Serialize)]
struct DemoDevice {
    id: String,
    display_name: String,
    pop_id: String,
    device_kind: String,
    vendor: String,
    exact_model: String,
    adoption_state: &'static str,
    connectivity: &'static str,
    health: &'static str,
    last_verified_at: Option<String>,
    lab_only: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DemoInput {
    display_name: String,
    pop_id: String,
    device_kind: String,
    vendor: String,
    exact_model: String,
}
// R9.6 strictly synthetic server-side connection plan. No endpoint, CIDR,
// keys or actual device fields are accepted; it never creates a job.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabConnectionPlan {
    method: String,
    gateway: String,
    device_profile: String,
}
async fn preview_connection_plan(
    headers: HeaderMap,
    Json(plan): Json<LabConnectionPlan>,
) -> Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !demo_csrf(&headers) {
        return Err(reject(StatusCode::FORBIDDEN));
    }
    if ![
        "direct_secure",
        "wireguard",
        "ipsec",
        "agent",
        "public_telnet",
    ]
    .contains(&plan.method.as_str())
        || !["routeros7", "routeros6", "linux", "none"].contains(&plan.gateway.as_str())
        || !["VIRTUAL-SECURE-MANAGED", "VIRTUAL-TELNET-ONLY"]
            .contains(&plan.device_profile.as_str())
    {
        return Err(reject(StatusCode::BAD_REQUEST));
    }
    let (eligible_for_review, reason) = match (
        plan.method.as_str(),
        plan.gateway.as_str(),
        plan.device_profile.as_str(),
    ) {
        ("public_telnet", _, _) => (false, "PUBLIC_TELNET_CREDENTIALS_FORBIDDEN"),
        ("direct_secure", _, "VIRTUAL-TELNET-ONLY") => {
            (false, "DEVICE_HAS_NO_SECURE_NATIVE_PROTOCOL")
        }
        ("wireguard", "routeros6", _) => (false, "ROUTEROS6_NO_BUILTIN_WIREGUARD"),
        ("wireguard" | "ipsec", "none", _) => (false, "SITE_GATEWAY_REQUIRED"),
        ("agent", _, _) => (false, "SITE_AGENT_NOT_IMPLEMENTED"),
        ("direct_secure", _, _) => (true, "VERIFY_REAL_SSH_OR_SNMPV3_IDENTITY"),
        ("wireguard" | "ipsec", _, _) => (true, "VERIFY_ISOLATED_LAST_HOP_AND_RECOVERY"),
        _ => (false, "UNSUPPORTED"),
    };
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({
            "lab_only":true,"plan_only":true,"eligible_for_separate_review":eligible_for_review,
            "reason":reason,"tenant_verified":false,"device_identity_verified":false,
            "device_adopted":false,"credentials_used":false,"network_actions":0,
            "worker_dispatch_enabled":false,"health":"NOT_MEASURED"
        })),
    ))
}

// R9.12 strictly synthetic tenant wizard UX. Never accepts networks,
// credentials, keys or real devices; a reviewer cannot activate a tunnel here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticTunnelReview {
    gateway: String,
    segmentation: String,
    recovery: String,
    service_baseline: String,
}
async fn preview_tunnel_review(
    headers: HeaderMap,
    Json(plan): Json<SyntheticTunnelReview>,
) -> Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !demo_csrf(&headers) {
        return Err(reject(StatusCode::FORBIDDEN));
    }
    if !["routeros7_x86", "routeros6", "other"].contains(&plan.gateway.as_str())
        || !["verified_isolated", "same_shared_lan", "unknown"]
            .contains(&plan.segmentation.as_str())
        || ![
            "console_restore_tested",
            "console_available_untested",
            "unknown",
        ]
        .contains(&plan.recovery.as_str())
        || !["approved_measured", "unmeasured"].contains(&plan.service_baseline.as_str())
    {
        return Err(reject(StatusCode::BAD_REQUEST));
    }
    let mut missing = Vec::new();
    if plan.gateway != "routeros7_x86" {
        missing.push("BUILTIN_WIREGUARD_GATEWAY_NOT_VERIFIED");
    }
    if plan.segmentation != "verified_isolated" {
        missing.push("MANAGEMENT_LAST_HOP_ISOLATION_NOT_VERIFIED");
    }
    if plan.recovery != "console_restore_tested" {
        missing.push("CONSOLE_RECOVERY_NOT_REHEARSED");
    }
    if plan.service_baseline != "approved_measured" {
        missing.push("LIVE_DISTRIBUTION_BASELINE_NOT_APPROVED");
    }
    // Even with every synthetic value checked, real MFA, host identity,
    // approved address plan, crypto, device privilege and maker/checker absent.
    missing.extend([
        "REAL_IDENTITY_AND_MFA_REQUIRED",
        "REAL_NETWORK_PLAN_REVIEW_REQUIRED",
        "INDEPENDENT_APPROVAL_REQUIRED",
        "DEVICE_HOST_KEY_NOT_PINNED",
    ]);
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({
            "lab_only":true,"synthetic_only":true,"preflight_status":"BLOCKED_PENDING_REAL_REVIEW",
            "missing_evidence":missing,"config_generated":false,"secrets_accepted":false,
            "tunnel_created":false,"network_actions":0,"worker_dispatch_enabled":false,
            "device_adopted":false,"service_impact_measured":false
        })),
    ))
}

// R9.15: Site A centrally planned, site B self-configures. LAB only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HubSpokePreview {
    method: String,
    hub_address_scope: String,
    site_b_path: String,
    site_b_gateway: String,
}
async fn preview_site_a_plan(
    headers: HeaderMap,
    Json(value): Json<HubSpokePreview>,
) -> Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !demo_csrf(&headers) {
        return Err(reject(StatusCode::FORBIDDEN));
    }
    if !["direct_private", "wireguard", "ipsec"].contains(&value.method.as_str())
        || !["private", "public"].contains(&value.hub_address_scope.as_str())
        || !["verified_private", "external", "unverified"].contains(&value.site_b_path.as_str())
        || !["routeros7", "linux"].contains(&value.site_b_gateway.as_str())
    {
        return Err(reject(StatusCode::BAD_REQUEST));
    }
    let topology_candidate = match (
        value.method.as_str(),
        value.hub_address_scope.as_str(),
        value.site_b_path.as_str(),
    ) {
        ("direct_private", "private", "verified_private") => "DIRECT_PRIVATE_NO_TUNNEL_REQUIRED",
        ("wireguard", "private", "verified_private") => "PRIVATE_HUB_WG_SITE_B_INITIATES",
        ("wireguard", "public", "external") => "PUBLIC_HUB_WG_SITE_B_INITIATES",
        ("ipsec", _, _) => "IPSEC_NOT_YET_IMPLEMENTED",
        ("direct_private", _, _) => "VERIFIED_PRIVATE_ROUTE_REQUIRED",
        _ => "HUB_ENDPOINT_REACHABILITY_UNVERIFIED",
    };
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({
            "lab_only":true,"topology_candidate":topology_candidate,
            "site_a_role":"IPAT_CENTRAL_CONFIGURATION_AUTHORITY",
            "site_b_role":"SITE_OPERATOR_SELF_CONFIGURES_NO_PUSH",
            "config_generated":false,"secrets_accepted":false,
            "router_push_enabled":false,"network_actions":0,
            "site_path_independently_verified":false,
            "real_mfa_verified":false,"device_adopted":false,
            "state":"REVIEW_ONLY_NOT_DEPLOYABLE"
        })),
    ))
}
// R9.17: direct-first protocol selector, private LAB only. No real device
// address, account, certificate, SNMP community or worker can be submitted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectProtocolReview {
    device_profile: String,
    candidate_protocol: String,
    network_evidence: String,
}
async fn preview_direct_protocol(
    headers: HeaderMap,
    Json(input): Json<DirectProtocolReview>,
) -> Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !demo_csrf(&headers) {
        return Err(reject(StatusCode::FORBIDDEN));
    }
    let protocols: &[&str] = match input.device_profile.as_str() {
        "zte_c320" => &["ssh_pinned", "snmpv3_authpriv"],
        "cdata_olt" => &["ssh_pinned", "snmpv3_authpriv", "https_vendor_verified"],
        "mikrotik_routeros7" => &[
            "routeros_api_ssl",
            "routeros_rest_https",
            "ssh_pinned",
            "snmpv3_authpriv",
        ],
        "ont_tr069" => &["cwmp_https", "usp_authenticated"],
        "ont_usp" => &["usp_authenticated", "cwmp_https"],
        _ => return Err(reject(StatusCode::BAD_REQUEST)),
    };
    if !protocols.contains(&input.candidate_protocol.as_str())
        || !["observed_private", "unverified"].contains(&input.network_evidence.as_str())
    {
        return Err(reject(StatusCode::BAD_REQUEST));
    }
    let required = match input.candidate_protocol.as_str() {
        "ssh_pinned" => "INDEPENDENT_PINNED_HOST_KEY_AND_RESTRICTED_LOGIN_REQUIRED",
        "snmpv3_authpriv" => "SNMPV3_AUTH_PRIV_ENGINE_ID_AND_READONLY_ACL_REQUIRED",
        "routeros_api_ssl" | "routeros_rest_https" | "https_vendor_verified" | "cwmp_https" => {
            "REAL_TLS_CERTIFICATE_AND_EXACT_FIRMWARE_SERVICE_REQUIRED"
        }
        "usp_authenticated" => "REAL_USP_CONTROLLER_AGENT_AUTHENTICATION_REQUIRED",
        _ => return Err(reject(StatusCode::BAD_REQUEST)),
    };
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({
            "mode":"DIRECT_MANAGEMENT_PROTOCOL_REVIEW_ONLY",
            "device_profile":input.device_profile,
            "candidate_protocol":input.candidate_protocol,
            "available_candidate_protocols":protocols,
            "preferred_path":"DIRECT_OVER_EXISTING_NETWORK",
            "wireguard_required":false,
            "management_segment_isolation_verified":false,
            "actual_protocol_compatibility_verified":false,
            "exact_device_identity_verified":false,
            "restricted_account_verified":false,
            "owner_baseline_approved":false,
            "real_tenant_mfa_verified":false,
            "next_gate":required,
            "network_transport_observed_historically":
                input.device_profile=="zte_c320" &&
                    input.candidate_protocol=="ssh_pinned" &&
                    input.network_evidence=="observed_private",
            "authentication_attempted":false,
            "device_adopted":false,
            "network_actions":0,
            "credentials_accepted":false,
        })),
    ))
}

#[derive(Default)]
struct DemoState {
    next: u32,
    devices: Vec<DemoDevice>,
}
type Shared = Arc<Mutex<DemoState>>;

fn safe_text(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.is_ascii()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | b'.'))
}
fn valid_input(v: &DemoInput) -> bool {
    v.display_name.starts_with("LAB-")
        && safe_text(&v.display_name, 80)
        && !v.pop_id.is_empty()
        && v.pop_id.len() <= 32
        && v.pop_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && ["olt", "ont", "router"].contains(&v.device_kind.as_str())
        && ["ZTE", "C-DATA", "VSOL", "MikroTik", "Other"].contains(&v.vendor.as_str())
        && v.exact_model.starts_with("VIRTUAL-")
        && safe_text(&v.exact_model, 80)
}
pub(super) fn demo_csrf_read(headers: &HeaderMap) -> bool {
    if headers.get_all(header::HOST).iter().count() != 1 {
        return false;
    }
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("127.0.0.1:"))
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port > 0)
}

pub(super) fn demo_csrf(headers: &HeaderMap) -> bool {
    if headers.get_all(header::HOST).iter().count() != 1
        || headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get_all("x-ipat-demo-only").iter().count() != 1
    {
        return false;
    }
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(port) = host
        .strip_prefix("127.0.0.1:")
        .and_then(|p| p.parse::<u16>().ok())
    else {
        return false;
    };
    if port == 0 {
        return false;
    }
    headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        == Some(format!("http://{host}").as_str())
        && headers
            .get("x-ipat-demo-only")
            .and_then(|v| v.to_str().ok())
            == Some("1")
}
fn reject(status: StatusCode) -> (StatusCode, HeaderMap, Json<Value>) {
    (
        status,
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({"accepted":false,"lab_only":true})),
    )
}
async fn list_demo(State(state): State<Shared>) -> (HeaderMap, Json<Value>) {
    let devices = state.lock().await.devices.clone();
    (
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({"lab_only":true,"source":"volatile-in-memory-demo",
            "real_device_count":0,"physical_connection_checked":false,
            "count":devices.len(),"limit":MAX_DEMO_CANDIDATES,"devices":devices})),
    )
}
async fn add_demo(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(input): Json<DemoInput>,
) -> Result<(StatusCode, HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !demo_csrf(&headers) {
        return Err(reject(StatusCode::FORBIDDEN));
    }
    if !valid_input(&input) {
        return Err(reject(StatusCode::BAD_REQUEST));
    }
    let mut state = state.lock().await;
    if state.devices.len() >= MAX_DEMO_CANDIDATES {
        return Err(reject(StatusCode::CONFLICT));
    }
    // Duplicate fake lab identity cannot accidentally add another row.
    if state
        .devices
        .iter()
        .any(|d| d.display_name == input.display_name && d.pop_id == input.pop_id)
    {
        return Err(reject(StatusCode::CONFLICT));
    }
    state.next += 1;
    let d = DemoDevice {
        id: format!("LAB-DEMO-{:04}", state.next),
        display_name: input.display_name,
        pop_id: input.pop_id,
        device_kind: input.device_kind,
        vendor: input.vendor,
        exact_model: input.exact_model,
        adoption_state: "PENDING_REVIEW",
        connectivity: "UNKNOWN",
        health: "NOT_MEASURED",
        last_verified_at: None,
        lab_only: true,
    };
    state.devices.push(d.clone());
    Ok((
        StatusCode::CREATED,
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({"accepted":true,"lab_only":true,"device":d})),
    ))
}
async fn remove_demo(
    State(state): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(HeaderMap, Json<Value>), (StatusCode, HeaderMap, Json<Value>)> {
    if !demo_csrf(&headers) {
        return Err(reject(StatusCode::FORBIDDEN));
    }
    let mut state = state.lock().await;
    let before = state.devices.len();
    state.devices.retain(|d| d.id != id);
    if state.devices.len() == before {
        return Err(reject(StatusCode::NOT_FOUND));
    }
    Ok((
        super::private_lab_headers("application/json; charset=utf-8"),
        Json(json!({"lab_only":true,"removed":true})),
    ))
}
async fn html() -> (HeaderMap, axum::response::Html<&'static str>) {
    (
        super::private_lab_headers("text/html; charset=utf-8"),
        axum::response::Html(HTML),
    )
}
async fn css() -> (HeaderMap, &'static str) {
    (super::private_lab_headers("text/css; charset=utf-8"), CSS)
}
async fn js() -> (HeaderMap, &'static str) {
    (
        super::private_lab_headers("text/javascript; charset=utf-8"),
        JS,
    )
}
async fn first_real_inventory_js() -> (HeaderMap, &'static str) {
    (
        super::private_lab_headers("text/javascript; charset=utf-8"),
        C320_FIRST_REAL_JS,
    )
}
async fn physical_evidence() -> (HeaderMap, &'static str) {
    (
        super::private_lab_headers("application/json; charset=utf-8"),
        PHYSICAL_EVIDENCE,
    )
}
pub(super) fn router() -> Router {
    let state = Arc::new(Mutex::new(DemoState::default()));
    Router::new()
        .route("/lab/device-workbench", get(html))
        .route("/lab/device-workbench.css", get(css))
        .route("/lab/device-workbench.js", get(js))
        .route(
            "/lab/c320-first-real-inventory.js",
            get(first_real_inventory_js),
        )
        .route("/lab/device-physical-evidence", get(physical_evidence))
        .route(
            "/lab/c320-action-readiness",
            get(super::c320_actions_lab::list),
        )
        .route(
            "/lab/c320-first-real-inventory",
            get(super::c320_actions_lab::first_read),
        )
        .route(
            "/lab/c320-actions/{action}",
            axum::routing::post(super::c320_actions_lab::reject_execute),
        )
        .route(
            "/lab/demo/connection-plan",
            axum::routing::post(preview_connection_plan),
        )
        .route(
            "/lab/demo/tunnel-review",
            axum::routing::post(preview_tunnel_review),
        )
        .route(
            "/lab/demo/site-a-plan",
            axum::routing::post(preview_site_a_plan),
        )
        .route(
            "/lab/demo/direct-protocol-review",
            axum::routing::post(preview_direct_protocol),
        )
        .route(
            "/lab/dev-site-a-public-key",
            get(super::site_a_pairing_lab::show_public),
        )
        .route(
            "/lab/demo/site-a-manual-pairing",
            axum::routing::post(super::site_a_pairing_lab::manual_pairing),
        )
        .route("/lab/demo/device-candidates", get(list_demo).post(add_demo))
        .route("/lab/demo/device-candidates/{id}", delete(remove_demo))
        .layer(DefaultBodyLimit::max(2048))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    async fn request(
        app: Router,
        method: &str,
        path: &str,
        body: &str,
        authenticated_demo_origin: bool,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "127.0.0.1:48765")
            .header("content-type", "application/json");
        if authenticated_demo_origin {
            req = req
                .header("Origin", "http://127.0.0.1:48765")
                .header("X-IPAT-Demo-Only", "1");
        }
        app.oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    const PROPOSAL: &str = r#"{"display_name":"LAB-OLT-01","pop_id":"lab-pop-a",
       "device_kind":"olt","vendor":"ZTE","exact_model":"VIRTUAL-C320"}"#;
    #[tokio::test]
    async fn real_axum_volatile_add_list_delete_never_claims_connectivity() {
        let app = router();
        let initial = request(app.clone(), "GET", "/lab/demo/device-candidates", "", false).await;
        assert_eq!(initial.status(), StatusCode::OK);
        let data = to_bytes(initial.into_body(), 4096).await.unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&data).unwrap()["count"], 0);
        let created = request(
            app.clone(),
            "POST",
            "/lab/demo/device-candidates",
            PROPOSAL,
            true,
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(created.headers()[header::CACHE_CONTROL], "no-store");
        let data = to_bytes(created.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(body["device"]["id"], "LAB-DEMO-0001");
        assert_eq!(body["device"]["adoption_state"], "PENDING_REVIEW");
        assert_eq!(body["device"]["connectivity"], "UNKNOWN");
        assert_eq!(body["device"]["health"], "NOT_MEASURED");
        assert!(body["device"]["last_verified_at"].is_null());
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/device-candidates",
                PROPOSAL,
                true
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let list = request(app.clone(), "GET", "/lab/demo/device-candidates", "", false).await;
        let data = to_bytes(list.into_body(), 4096).await.unwrap();
        let body: Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(body["count"], 1);
        assert_eq!(body["real_device_count"], 0);
        assert_eq!(body["physical_connection_checked"], false);
        assert_eq!(
            request(
                app.clone(),
                "DELETE",
                "/lab/demo/device-candidates/LAB-DEMO-0001",
                "",
                true
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(
                app.clone(),
                "DELETE",
                "/lab/demo/device-candidates/LAB-DEMO-0001",
                "",
                true
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn deny_cross_site_post_foreign_header_unexpected_actual_ip() {
        let app = router();
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/device-candidates",
                PROPOSAL,
                false
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(
                app.clone(),
                "DELETE",
                "/lab/demo/device-candidates/LAB-DEMO-0001",
                "",
                false
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        for bad in [
            PROPOSAL.replace("LAB-OLT-01", "REAL-ZTE-C320"),
            PROPOSAL.replace("VIRTUAL-C320", "ZXA10 C320"),
            PROPOSAL.replace("ZTE", "UNKNOWN"),
            PROPOSAL.replace("lab-pop-a", "0/../../admin"),
            PROPOSAL.replace("VIRTUAL-C320", "VIRTUAL-<script>"),
            PROPOSAL.replace("}", r#","management_ip":"10.0.0.2"}"#),
        ] {
            let rejected = request(
                app.clone(),
                "POST",
                "/lab/demo/device-candidates",
                &bad,
                true,
            )
            .await
            .status();
            assert!(
                rejected == StatusCode::BAD_REQUEST || rejected == StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        let oversize = " ".repeat(2200) + PROPOSAL;
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/device-candidates",
                &oversize,
                true
            )
            .await
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            request(app.clone(), "GET", "/lab/demo/device-candidates", "", false)
                .await
                .status(),
            StatusCode::OK
        );
    }
    #[tokio::test]
    async fn demo_workspace_is_private_html_without_login_or_real_device_credentials() {
        let page = request(router(), "GET", "/lab/device-workbench", "", false).await;
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(page.into_body(), 65536).await.unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(html.contains("Tambah kandidat perangkat"));
        assert!(html.contains("Daftar kandidat"));
        assert!(html.contains("PERINGATAN PRD"));
        assert!(!html.contains("type=\"password\""));
        assert!(!html.contains("10.0.0.2"));
    }
    #[tokio::test]
    async fn c320_live_actions_are_explicitly_off_and_post_is_unmounted() {
        let app = router();
        let reply = request(app.clone(), "GET", "/lab/c320-action-readiness", "", false).await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "no-store");
        let json: Value =
            serde_json::from_slice(&to_bytes(reply.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(
            json["adoption_state"],
            "AUTHENTICATED_LAB_READ_OBSERVED_ADOPTION_PENDING"
        );
        assert_eq!(
            json["preferred_connection"],
            "ENCRYPTED_LEGACY_SSH_OBSERVED_NETWORK_KEY_LAB_ONLY"
        );
        assert_eq!(
            json["transport"],
            "OWNER_APPROVED_AUTHENTICATED_LAB_SSH_AND_TELNET_FIRST_READ"
        );
        assert_eq!(
            json["tested_legacy_ssh_profile"],
            "RSA_AES128CBC_GROUP14SHA256_ONLY"
        );
        assert_eq!(json["actual_transport_authentication_stage_reached"], true);
        assert_eq!(json["credentials_sent_during_transport_test"], false);
        assert_eq!(json["olt_commands_during_transport_test"], 0);
        assert_eq!(
            json["observed_test_account_ssh_auth_methods"],
            serde_json::json!(["password"])
        );
        assert_eq!(json["publickey_offer_observed_for_test_account"], false);
        assert_eq!(json["password_sent_to_physical_olt"], true);
        assert_eq!(json["alternate_telnet323_passive_tcp_reachable"], true);
        assert_eq!(json["alternate_telnet323_real_telnet_iac_observed"], true);
        assert_eq!(json["alternate_telnet323_observed_inbound_bytes"], 15);
        assert_eq!(
            json["alternate_telnet323_unencrypted_not_approved_for_login"],
            false
        );
        assert_eq!(
            json["observed_lab_ssh_password_session_authenticated"],
            true
        );
        assert_eq!(
            json["observed_lab_telnet_password_session_authenticated"],
            true
        );
        assert_eq!(json["real_device_authenticated"], true);
        assert_eq!(json["model_and_firmware_read_from_real_hardware"], true);
        assert_eq!(json["actual_firmware_filetype_alias_unresolved"], true);
        assert_eq!(json["production_auto_adoption_approved"], false);
        assert_eq!(json["independent_oob_olt_host_key_verified"], false);
        assert_eq!(
            json["verified_off_vps_encrypted_running_cli_reference_backup"],
            true
        );
        assert_eq!(
            json["verified_mac_restic_isolated_byte_identical_restore"],
            true
        );
        assert_eq!(json["vendor_native_startup_config_restore_tested"], false);
        assert_eq!(json["actual_local_account_privilege15_count"], 2);
        assert_eq!(json["actual_local_restricted_account_proven"], false);
        let reply = request(
            app.clone(),
            "GET",
            "/lab/c320-first-real-inventory",
            "",
            false,
        )
        .await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "no-store");
        let first: Value =
            serde_json::from_slice(&to_bytes(reply.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(
            first["mode"],
            "ACTUAL_HISTORICAL_OWNER_LAB_PHYSICAL_READ_NO_WORKER"
        );
        assert_eq!(first["observation_is_live"], false);
        assert_eq!(first["cards"].as_array().unwrap().len(), 3);
        assert_eq!(first["real_saas_device_adopted"], false);
        assert_eq!(
            first["owner_restic_isolated_byte_identical_restore_verified"],
            true
        );
        assert_eq!(
            request(
                app.clone(),
                "GET",
                "/lab/c320-first-real-inventory.js",
                "",
                false
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(json["actual_cards_reported"], 3);
        assert_eq!(json["network_actions"], 0);
        assert_eq!(json["worker_enabled"], false);
        for capability in json["capabilities"].as_array().unwrap() {
            assert_eq!(capability["enabled"], false);
            assert_eq!(capability["can_run_on_live_device"], false);
        }
        for action in [
            "READ_CARD_INVENTORY",
            "READ_RUNNING_FIRMWARE",
            "LIST_ONTS",
            "UPGRADE_OLT_FIRMWARE",
            "unknown",
        ] {
            let response = request(
                app.clone(),
                "POST",
                &format!("/lab/c320-actions/{action}"),
                "{}",
                true,
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let result: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 2048).await.unwrap())
                    .unwrap();
            assert_eq!(result["network_actions"], 0);
            assert_eq!(result["device_adopted"], false);
        }
        assert_eq!(
            request(app.clone(), "GET", "/lab/c320-action-readiness", "", true)
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn private_evidence_route_never_promotes_untrusted_host_to_adopted() {
        let reply = request(router(), "GET", "/lab/device-physical-evidence", "", false).await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(reply.into_body(), 8192).await.unwrap();
        let evidence: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(evidence["private_ssh_transport_observed"], true);
        assert_eq!(evidence["out_of_band_host_key_verified"], false);
        assert_eq!(evidence["dedicated_readonly_account_verified"], false);
        assert_eq!(evidence["actual_worker_private_route_verified"], false);
        assert_eq!(evidence["worker_route_observation"], "DEFAULT_ROUTE_ONLY");
        assert_eq!(evidence["direct_private_vps_ssh_transport_observed"], true);
        assert_eq!(evidence["direct_private_vps_ssh_olt_commands_executed"], 0);
        assert_eq!(evidence["direct_private_vps_ssh_credentials_sent"], false);
        assert_eq!(
            evidence["direct_private_vps_ssh_host_identity_verified"],
            false
        );
        assert_eq!(
            evidence["direct_private_vps_ssh_last_hop_isolation_verified"],
            false
        );
        assert_eq!(evidence["temporary_owner_mac_vps_ssh_relay_observed"], true);
        assert_eq!(evidence["temporary_owner_mac_vps_ssh_relay_closed"], true);
        assert_eq!(evidence["temporary_relay_olt_commands_executed"], 0);
        assert_eq!(evidence["temporary_relay_trusted_last_hop_verified"], false);
        assert_eq!(
            evidence["direct_private_vps_group14_auth_stage_observed_on"],
            "2026-09-29"
        );
        assert_eq!(
            evidence["direct_private_vps_group14_kex"],
            "diffie-hellman-group14-sha256"
        );
        assert_eq!(
            evidence["direct_private_vps_group14_server_hostkey_packet_received"],
            true
        );
        assert_eq!(
            evidence["direct_private_vps_group14_auth_methods_advertised"],
            true
        );
        assert_eq!(
            evidence["direct_private_vps_group14_credentials_sent"],
            false
        );
        assert_eq!(
            evidence["direct_private_vps_group14_olt_commands_executed"],
            0
        );
        assert_eq!(
            evidence["direct_private_vps_group14_hostkey_oob_verified"],
            false
        );
        assert_eq!(
            evidence["direct_private_vps_group14_actual_login_verified"],
            false
        );
        assert_eq!(evidence["direct_private_vps_tls443_noauth_checked"], true);
        assert_eq!(evidence["direct_private_vps_tls443_tcp_reachable"], false);
        assert_eq!(evidence["direct_private_vps_tls443_api_supported"], false);
        assert_eq!(
            evidence["direct_private_vps_tls443_credentials_sent"],
            false
        );
        assert_eq!(evidence["direct_private_vps_tls443_http_requests_sent"], 0);
        assert_eq!(
            evidence["candidate_inventory_state"],
            "OBSERVED_NOT_ADOPTED"
        );
        assert_eq!(evidence["owner_reported_pop"], "UNVERIFIED");
        assert_eq!(evidence["credentials_sent"], false);
        assert_eq!(evidence["olt_commands_executed"], 0);
        assert_eq!(evidence["device_adopted"], false);
        assert_eq!(evidence["physical_read_test"], "NOT_RUN");
        assert_eq!(evidence["health"], "NOT_MEASURED");
    }
    const HUB_PLAN: &str = r#"{"method":"wireguard","hub_address_scope":"private","site_b_path":"verified_private","site_b_gateway":"routeros7"}"#;
    #[tokio::test]
    async fn r917_direct_first_and_api_ssl_only_for_mikrotik_not_assumed_on_c320() {
        let app = router();
        let c320 = r#"{"device_profile":"zte_c320","candidate_protocol":"ssh_pinned","network_evidence":"observed_private"}"#;
        let reply = request(
            app.clone(),
            "POST",
            "/lab/demo/direct-protocol-review",
            c320,
            true,
        )
        .await;
        assert_eq!(reply.status(), StatusCode::OK);
        let body = to_bytes(reply.into_body(), 4096).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["preferred_path"], "DIRECT_OVER_EXISTING_NETWORK");
        assert_eq!(json["wireguard_required"], false);
        assert_eq!(json["network_transport_observed_historically"], true);
        assert_eq!(json["actual_protocol_compatibility_verified"], false);
        assert_eq!(json["authentication_attempted"], false);
        assert_eq!(json["device_adopted"], false);
        assert_eq!(json["network_actions"], 0);
        assert!(!json["available_candidate_protocols"]
            .as_array()
            .unwrap()
            .contains(&json!("routeros_api_ssl")));
        let bad = c320.replace("ssh_pinned", "routeros_api_ssl");
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/direct-protocol-review",
                &bad,
                true
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let router = r#"{"device_profile":"mikrotik_routeros7","candidate_protocol":"routeros_api_ssl","network_evidence":"unverified"}"#;
        let approved = request(
            app.clone(),
            "POST",
            "/lab/demo/direct-protocol-review",
            router,
            true,
        )
        .await;
        assert_eq!(approved.status(), StatusCode::OK);
        let payload: Value =
            serde_json::from_slice(&to_bytes(approved.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(
            payload["next_gate"],
            "REAL_TLS_CERTIFICATE_AND_EXACT_FIRMWARE_SERVICE_REQUIRED"
        );
        assert_eq!(payload["network_transport_observed_historically"], false);
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/direct-protocol-review",
                c320,
                false
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/direct-protocol-review",
                &c320.replacen("{", "{\"password\":\"forbidden\",", 1),
                true
            )
            .await
            .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn r915_hub_is_site_a_and_never_pushes_to_site_b() {
        let app = router();
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/site-a-plan",
                HUB_PLAN,
                false
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let reply = request(app.clone(), "POST", "/lab/demo/site-a-plan", HUB_PLAN, true).await;
        assert_eq!(reply.status(), StatusCode::OK);
        let data: Value =
            serde_json::from_slice(&to_bytes(reply.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(data["site_a_role"], "IPAT_CENTRAL_CONFIGURATION_AUTHORITY");
        assert_eq!(data["site_b_role"], "SITE_OPERATOR_SELF_CONFIGURES_NO_PUSH");
        assert_eq!(
            data["topology_candidate"],
            "PRIVATE_HUB_WG_SITE_B_INITIATES"
        );
        for field in [
            "router_push_enabled",
            "config_generated",
            "secrets_accepted",
            "site_path_independently_verified",
            "real_mfa_verified",
            "device_adopted",
        ] {
            assert_eq!(data[field], false, "{field}");
        }
        assert_eq!(data["network_actions"], 0);
        let external = r#"{"method":"wireguard","hub_address_scope":"public","site_b_path":"external","site_b_gateway":"routeros7"}"#;
        let resp = request(app.clone(), "POST", "/lab/demo/site-a-plan", external, true).await;
        let data: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(data["topology_candidate"], "PUBLIC_HUB_WG_SITE_B_INITIATES");
        for injected in [
            r#"{"method":"wireguard","hub_address_scope":"public","site_b_path":"external","site_b_gateway":"routeros7","password":"never"}"#,
            r#"{"method":"wireguard","hub_address_scope":"public","site_b_path":"external","site_b_gateway":"routeros7","endpoint":"10.77.13.233"}"#,
        ] {
            let denied =
                request(app.clone(), "POST", "/lab/demo/site-a-plan", injected, true).await;
            assert!(matches!(
                denied.status(),
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ));
        }
    }
    const SYNTHETIC_WG: &str = r#"{"gateway":"routeros7_x86","segmentation":"same_shared_lan","recovery":"console_available_untested","service_baseline":"unmeasured"}"#;
    #[tokio::test]
    async fn synthetic_wireguard_wizard_never_accepts_secrets_or_activates() {
        let app = router();
        assert_eq!(
            request(
                app.clone(),
                "POST",
                "/lab/demo/tunnel-review",
                SYNTHETIC_WG,
                false
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let safe = request(
            app.clone(),
            "POST",
            "/lab/demo/tunnel-review",
            SYNTHETIC_WG,
            true,
        )
        .await;
        assert_eq!(safe.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(safe.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(body["preflight_status"], "BLOCKED_PENDING_REAL_REVIEW");
        for flag in [
            "config_generated",
            "secrets_accepted",
            "tunnel_created",
            "worker_dispatch_enabled",
            "device_adopted",
            "service_impact_measured",
        ] {
            assert_eq!(body[flag], false, "{flag}");
        }
        assert_eq!(body["network_actions"], 0);
        assert!(body["missing_evidence"].as_array().unwrap().len() >= 5);
        let ideal = r#"{"gateway":"routeros7_x86","segmentation":"verified_isolated","recovery":"console_restore_tested","service_baseline":"approved_measured"}"#;
        let resp = request(app.clone(), "POST", "/lab/demo/tunnel-review", ideal, true).await;
        let data: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(data["tunnel_created"], false);
        assert_eq!(data["missing_evidence"].as_array().unwrap().len(), 4);
        for injected in [
            r#"{"gateway":"routeros7_x86","segmentation":"verified_isolated","recovery":"console_restore_tested","service_baseline":"approved_measured","private_key":"DO_NOT_ACCEPT"}"#,
            r#"{"gateway":"routeros7_x86","segmentation":"verified_isolated","recovery":"console_restore_tested","service_baseline":"approved_measured","endpoint":"10.77.13.233"}"#,
            r#"{"gateway":"routeros6","segmentation":"verified_isolated","recovery":"wrong","service_baseline":"approved_measured"}"#,
        ] {
            let denied = request(
                app.clone(),
                "POST",
                "/lab/demo/tunnel-review",
                injected,
                true,
            )
            .await;
            assert!(matches!(
                denied.status(),
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ));
        }
    }
    const LAB_PLAN: &str =
        r#"{"method":"wireguard","gateway":"routeros7","device_profile":"VIRTUAL-TELNET-ONLY"}"#;
    #[tokio::test]
    async fn actual_axum_lab_plan_never_deploys_or_adopts() {
        let app = router();
        let missing_origin = request(
            app.clone(),
            "POST",
            "/lab/demo/connection-plan",
            LAB_PLAN,
            false,
        )
        .await;
        assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);
        let allowed = request(
            app.clone(),
            "POST",
            "/lab/demo/connection-plan",
            LAB_PLAN,
            true,
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(allowed.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["eligible_for_separate_review"], true);
        assert_eq!(body["network_actions"], 0);
        assert_eq!(body["device_adopted"], false);
        assert_eq!(body["worker_dispatch_enabled"], false);
        assert_eq!(body["tenant_verified"], false);
        for bad in [
            r#"{"method":"public_telnet","gateway":"none","device_profile":"VIRTUAL-TELNET-ONLY"}"#,
            r#"{"method":"wireguard","gateway":"routeros6","device_profile":"VIRTUAL-TELNET-ONLY"}"#,
            r#"{"method":"direct_secure","gateway":"none","device_profile":"VIRTUAL-TELNET-ONLY"}"#,
        ] {
            let resp = request(app.clone(), "POST", "/lab/demo/connection-plan", bad, true).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
            assert_eq!(body["eligible_for_separate_review"], false);
            assert_eq!(body["network_actions"], 0);
        }
        for unsafe_payload in [
            r#"{"method":"wireguard","gateway":"routeros7","device_profile":"VIRTUAL-TELNET-ONLY","password":"sensitive"}"#,
            r#"{"method":"telnet","gateway":"routeros7","device_profile":"VIRTUAL-TELNET-ONLY"}"#,
        ] {
            let resp = request(
                app.clone(),
                "POST",
                "/lab/demo/connection-plan",
                unsafe_payload,
                true,
            )
            .await;
            assert!(matches!(
                resp.status(),
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ));
        }
    }
}
