//! Original IPAT CWMP Rust HTTP boundary, deliberately LAB ONLY.
//! Only accepts synthetic parser exercise on *Mac/VPS loopback*; real
//! /cwmp always denies until verified mTLS + tenant + durable sessions exist.
use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    routing::{any, get, post},
    Router,
};
const LAB_BIND: &str = "127.0.0.1:3300";
const SAFE_LAB_REPLY: &str = r#"{"parser":"valid","peer_authenticated":false,"tenant_bound":false,"device_enrolled":false,"cwmp_response_sent":false}"#;
#[cfg(test)]
fn app() -> Router {
    app_with_virtual_ont(false)
}
// R8.2 fixed VIRTUAL-ONT proof ONLY; not CPE admission or a CWMP ACS
// device session. Absolutely no actual OLT/ONT identity may be enrolled here.
const VIRTUAL_CWMP_ID: &str = "ipat-synthetic-rpc-01";
const VIRTUAL_SOAP_TYPE: &str = "text/xml; charset=utf-8";
fn virtual_fixture(inform: &cwmp_protocol::Inform) -> bool {
    inform.manufacturer == "SYNTHETIC"
        && inform.oui == "001122"
        && inform.product_class == "FAKE-ONT"
        && inform.serial_number == "FAKE-NOT-PHYSICAL"
        && inform.cwmp_id.as_deref() == Some("synthetic-only")
        && inform.event_codes == ["0 BOOTSTRAP"]
}
fn virtual_soap_headers() -> HeaderMap {
    let mut h = protected_lab_headers();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(VIRTUAL_SOAP_TYPE),
    );
    h
}
fn fixed_xml<'a>(headers: &HeaderMap, body: &'a Bytes) -> Result<&'a str, StatusCode> {
    // Never infer trust from SOAP headers, Host or spoofable reverse-proxy
    // mTLS headers. This is a strict loopback-only simulator test harness.
    let ct = headers.get_all(header::CONTENT_TYPE);
    if ct.iter().count() != 1 || ct.iter().next().and_then(|v| v.to_str().ok()) != Some("text/xml")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    std::str::from_utf8(body).map_err(|_| StatusCode::BAD_REQUEST)
}
async fn virtual_inform(
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, String), StatusCode> {
    let inform = cwmp_protocol::parse_inform(fixed_xml(&headers, &body)?)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !virtual_fixture(&inform) {
        return Err(StatusCode::FORBIDDEN);
    }
    // Real original Rust SOAP 1.1 InformResponse serialization, but only
    // fixed fake identities and never the production /cwmp listener.
    Ok((
        virtual_soap_headers(),
        cwmp_protocol::inform_response(&inform),
    ))
}
async fn virtual_read_request() -> (HeaderMap, String) {
    let rpc = cwmp_protocol::rpc::read_request(VIRTUAL_CWMP_ID, cwmp_protocol::rpc::LAB_PARAMETER)
        .expect("constant read-only synthetic RPC plan must be valid");
    (virtual_soap_headers(), rpc)
}
async fn virtual_read_reply(
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, &'static str), StatusCode> {
    let reply = cwmp_protocol::rpc::parse_read_reply(
        fixed_xml(&headers, &body)?,
        VIRTUAL_CWMP_ID,
        cwmp_protocol::rpc::LAB_PARAMETER,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    // No device-supplied value/fault strings can leak into logs or responses.
    let safe = match reply {
        cwmp_protocol::rpc::RpcReply::Values(v) if v.count() == 1 => {
            r#"{"lab_only":true,"peer_authenticated":false,"tenant_bound":false,"session_established":false,"parameter_count":1,"fault":false}"#
        }
        cwmp_protocol::rpc::RpcReply::Fault(_) => {
            r#"{"lab_only":true,"peer_authenticated":false,"tenant_bound":false,"session_established":false,"parameter_count":0,"fault":true}"#
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    Ok((protected_lab_headers(), safe))
}
fn app_with_virtual_ont(enabled: bool) -> Router {
    let base = Router::new()
        .route("/healthz", get(|| async { "cwmp-parser-lab-only" }))
        .route("/lab/parse-inform", post(parse_only))
        .route("/cwmp", any(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        .fallback(|| async { StatusCode::SERVICE_UNAVAILABLE });
    let routes = if enabled {
        base.route("/lab/virtual-ont/inform", post(virtual_inform))
            .route("/lab/virtual-ont/read-request", get(virtual_read_request))
            .route("/lab/virtual-ont/read-reply", post(virtual_read_reply))
    } else {
        base
    };
    routes.layer(DefaultBodyLimit::max(cwmp_protocol::MAX_XML_BYTES))
}

fn protected_lab_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h
}
async fn parse_only(
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, &'static str), StatusCode> {
    // SOAPAction is deliberately ignored because validation MUST NOT
    // authorize or schedule any device session, RPC or enrollment.
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("text/xml")
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let xml = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    cwmp_protocol::parse_inform(xml).map_err(|_| StatusCode::BAD_REQUEST)?;
    // No serial/OUI or supplied XML is ever echoed or logged.
    Ok((protected_lab_headers(), SAFE_LAB_REPLY))
}
#[tokio::main]
async fn main() {
    if std::env::var("IPAT_RUN_OFFLINE_CWMP_LAB").as_deref() != Ok("1") {
        eprintln!("Real ACS HTTPS/mTLS not enabled; opt-in local parser lab only.");
        std::process::exit(2);
    }
    // Never allow 0.0.0.0 or configurable public binds for this binary.
    let listener = tokio::net::TcpListener::bind(LAB_BIND)
        .await
        .expect("bind loopback-only parser laboratory");
    let virtual_ont = std::env::var("IPAT_R82_ENABLE_VIRTUAL_ONT").as_deref() == Ok("YES")
        && std::env::var("IPAT_RUN_K3S_LAB").as_deref() != Ok("1");
    axum::serve(listener, app_with_virtual_ont(virtual_ont))
        .await
        .expect("serve loopback-only synthetic CWMP parser lab");
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    const INFORM: &str = r#"<soap:Envelope
     xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
     xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
     <soap:Header><cwmp:ID soap:mustUnderstand="1">synthetic-only</cwmp:ID></soap:Header>
     <soap:Body><cwmp:Inform>
       <DeviceId><Manufacturer>SYNTHETIC</Manufacturer><OUI>001122</OUI>
       <ProductClass>FAKE-ONT</ProductClass><SerialNumber>FAKE-NOT-PHYSICAL</SerialNumber></DeviceId>
       <Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode><CommandKey/></EventStruct></Event>
       <MaxEnvelopes>1</MaxEnvelopes><CurrentTime>2026-09-26T12:00:00Z</CurrentTime>
       <RetryCount>0</RetryCount><ParameterList/>
     </cwmp:Inform></soap:Body></soap:Envelope>"#;
    async fn call(path: &str, content_type: Option<&str>, body: &str) -> StatusCode {
        let mut b = Request::builder().method("POST").uri(path);
        if let Some(ct) = content_type {
            b = b.header("content-type", ct);
        }
        app()
            .oneshot(b.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
            .status()
    }
    const REPLY: &str = r#"<soap:Envelope
     xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
     xmlns:cwmp="urn:dslforum-org:cwmp-1-0"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xmlns:xsd="http://www.w3.org/2001/XMLSchema">
       <soap:Header><cwmp:ID soap:mustUnderstand="1">ipat-synthetic-rpc-01</cwmp:ID></soap:Header>
       <soap:Body><cwmp:GetParameterValuesResponse><ParameterList>
       <ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name>
       <Value xsi:type="xsd:string">PRIVATE-SIMULATED-VERSION</Value>
       </ParameterValueStruct></ParameterList>
       </cwmp:GetParameterValuesResponse></soap:Body></soap:Envelope>"#;
    async fn virtual_post(path: &str, xml: &str, content_type: &str) -> axum::response::Response {
        app_with_virtual_ont(true)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", content_type)
                    .header("Host", "customer.example.invalid")
                    .header("x-tenant-id", "attacker")
                    .header("x-client-cert-verified", "true")
                    .body(Body::from(xml.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn real_rust_http_virtual_inform_serializes_actual_soap_not_authentication() {
        let res = virtual_post("/lab/virtual-ont/inform", INFORM, "text/xml").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CONTENT_TYPE], VIRTUAL_SOAP_TYPE);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = axum::body::to_bytes(res.into_body(), 2048).await.unwrap();
        let xml = std::str::from_utf8(&bytes).unwrap();
        assert!(xml.contains("<cwmp:InformResponse>"));
        assert!(xml.contains("<cwmp:ID soap:mustUnderstand=\"1\">synthetic-only</cwmp:ID>"));
        assert!(!xml.contains("FAKE-NOT-PHYSICAL"));
        assert!(!xml.contains("customer.example.invalid"));
    }
    #[tokio::test]
    async fn virtual_inform_cannot_enroll_other_cpe_or_device_identity() {
        for payload in [
            INFORM.replace("FAKE-NOT-PHYSICAL", "REAL-CUSTOMER-SERIAL"),
            INFORM.replace("SYNTHETIC", "ACTUAL-VENDOR"),
            INFORM.replace("0 BOOTSTRAP", "1 BOOT"),
            INFORM.replace("synthetic-only", "different-id"),
        ] {
            assert_eq!(
                virtual_post("/lab/virtual-ont/inform", &payload, "text/xml")
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            virtual_post("/lab/virtual-ont/inform", INFORM, "application/xml")
                .await
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            virtual_post(
                "/lab/virtual-ont/inform",
                &INFORM.replace("<soap:Envelope", "<!DOCTYPE x []><soap:Envelope"),
                "text/xml"
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn virtual_ont_real_soap_read_roundtrip_returns_count_not_secret() {
        let response = app_with_virtual_ont(true)
            .oneshot(
                Request::builder()
                    .uri("/lab/virtual-ont/read-request")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], VIRTUAL_SOAP_TYPE);
        let request = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let xml = String::from_utf8(request.to_vec()).unwrap();
        assert!(xml.contains("Device.DeviceInfo.SoftwareVersion"));
        assert!(xml.contains("<cwmp:GetParameterValues>"));
        assert!(!xml.contains("SetParameterValues"));
        assert!(!xml.contains("ManagementServer.Password"));
        let reply = virtual_post("/lab/virtual-ont/read-reply", REPLY, "text/xml").await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "no-store");
        let body = axum::body::to_bytes(reply.into_body(), 2048).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("\"parameter_count\":1"));
        assert!(text.contains("\"peer_authenticated\":false"));
        assert!(!text.contains("PRIVATE-SIMULATED-VERSION"));
    }
    #[tokio::test]
    async fn virtual_read_rejects_replay_id_mismatch_duplicate_and_write() {
        for data in [
            REPLY.replace("ipat-synthetic-rpc-01", "forged-rpc-id"),
            REPLY.replace("GetParameterValuesResponse", "SetParameterValues"),
            REPLY.replace("</ParameterList>",
                "<ParameterValueStruct><Name>Device.DeviceInfo.SoftwareVersion</Name><Value xsi:type=\"xsd:string\">2</Value></ParameterValueStruct></ParameterList>"),
            REPLY.replace("Device.DeviceInfo.SoftwareVersion", "Device.ManagementServer.Password"),
            REPLY.replace("<soap:Envelope", "<!DOCTYPE x []><soap:Envelope")
        ] {
            assert_eq!(virtual_post("/lab/virtual-ont/read-reply", &data, "text/xml")
                .await.status(), StatusCode::BAD_REQUEST);
        }
        assert_eq!(
            virtual_post("/lab/virtual-ont/read-reply", REPLY, "application/xml")
                .await
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            virtual_post("/cwmp", INFORM, "text/xml").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            virtual_post(
                "/lab/virtual-ont/read-reply",
                &"x".repeat(65537),
                "text/xml"
            )
            .await
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    #[tokio::test]
    async fn virtual_endpoints_are_absent_in_default_gateway() {
        for path in ["/lab/virtual-ont/inform", "/lab/virtual-ont/read-reply"] {
            let res = app()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[test]
    fn fixed_loopback_only_no_public_bind_parameter() {
        assert_eq!(LAB_BIND, "127.0.0.1:3300");
    }
    #[tokio::test]
    async fn real_cwmp_denies_even_valid_inform_and_forged_headers() {
        let req = Request::builder()
            .method("POST")
            .uri("/cwmp")
            .header("x-tenant-id", "kangnet")
            .header("x-client-cert-verified", "true")
            .header("content-type", "text/xml")
            .body(Body::from(INFORM))
            .unwrap();
        assert_eq!(
            app().oneshot(req).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[tokio::test]
    async fn lab_parser_accepts_but_does_not_enroll_or_issue_soap_response() {
        let req = Request::builder()
            .method("POST")
            .uri("/lab/parse-inform")
            .header("content-type", "text/xml")
            .header("x-tenant-id", "kangnet")
            .body(Body::from(INFORM))
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let data = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let text = std::str::from_utf8(&data).unwrap();
        assert_eq!(text, SAFE_LAB_REPLY);
        assert!(!text.contains("FAKE-NOT-PHYSICAL"));
        assert!(text.contains("\"peer_authenticated\":false"));
    }
    #[tokio::test]
    async fn refuses_wrong_type_malformed_xml_unsafe_xml_and_rpc_write() {
        assert_eq!(
            call("/lab/parse-inform", None, INFORM).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            call("/lab/parse-inform", Some("application/xml"), INFORM).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            call("/lab/parse-inform", Some("text/xml"), "<wrong/>").await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                "/lab/parse-inform",
                Some("text/xml"),
                &INFORM.replace("<soap:Envelope", "<!DOCTYPE x []><soap:Envelope")
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                "/lab/parse-inform",
                Some("text/xml"),
                &INFORM.replace("cwmp:Inform", "cwmp:SetParameterValues")
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn strict_body_bound_and_unrecognized_paths() {
        assert_eq!(
            call("/lab/parse-inform", Some("text/xml"), &"x".repeat(65537)).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            call("/v1/tenants", Some("text/xml"), INFORM).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
