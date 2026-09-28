use crate::read::ValidEmptyPost;
use crate::{AdmissionRegistry, AuthenticatedPeer, Enrollment, Error};
use tenant_core::TenantId;
const INFORM: &str = r#"<s:Envelope
 xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<s:Header><cwmp:ID s:mustUnderstand="1">lab-1</cwmp:ID></s:Header>
<s:Body><cwmp:Inform>
<DeviceId><Manufacturer>LAB ONLY</Manufacturer><OUI>001122</OUI>
<ProductClass>SYNTHETIC-ONT</ProductClass><SerialNumber>TEST-NOT-PHYSICAL</SerialNumber></DeviceId>
<Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode><CommandKey/></EventStruct></Event>
<MaxEnvelopes>1</MaxEnvelopes><CurrentTime>2026-09-26T12:00:00Z</CurrentTime>
<RetryCount>0</RetryCount><ParameterList/>
</cwmp:Inform></s:Body></s:Envelope>"#;
fn peer(id: u8) -> AuthenticatedPeer {
    AuthenticatedPeer {
        client_spki_sha256: [id; 32],
    }
}
fn tenant(text: &str) -> TenantId {
    TenantId::parse(text).unwrap()
}
fn enrolled() -> AdmissionRegistry {
    let mut r = AdmissionRegistry::default();
    r.register(
        Enrollment::new(
            tenant("kangnet"),
            "001122",
            "SYNTHETIC-ONT",
            "TEST-NOT-PHYSICAL",
            [9; 32],
        )
        .unwrap(),
    )
    .unwrap();
    r
}
fn reply(id: &str, name: &str, value: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:cwmp="urn:dslforum-org:cwmp-1-0"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header><cwmp:ID soap:mustUnderstand="1">{id}</cwmp:ID></soap:Header>
<soap:Body><cwmp:GetParameterValuesResponse>
<ParameterList><ParameterValueStruct><Name>{name}</Name>
<Value xsi:type="xsd:string">{value}</Value></ParameterValueStruct></ParameterList>
</cwmp:GetParameterValuesResponse></soap:Body></soap:Envelope>"#
    )
}
fn valid_reply(id: &str) -> String {
    reply(
        id,
        cwmp_protocol::rpc::LAB_PARAMETER,
        "LAB-NOT-ACTUAL-FIRMWARE",
    )
}
fn id(xml: &str) -> String {
    let doc = roxmltree::Document::parse(xml).unwrap();
    doc.descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some("urn:dslforum-org:cwmp-1-0")
                && n.tag_name().name() == "ID"
        })
        .unwrap()
        .text()
        .unwrap()
        .to_owned()
}
#[test]
fn full_synthetic_inform_empty_post_read_response_and_close() {
    let mut r = enrolled();
    let a = r.begin(&peer(9), &tenant("kangnet"), INFORM).unwrap();
    assert!(a.response_xml.contains("InformResponse"));
    let post = ValidEmptyPost::validate(b"", None, None).unwrap();
    let outbound = r.issue_one_read(&peer(9), &a.lease, post).unwrap();
    assert!(outbound.xml.contains("<cwmp:GetParameterValues>"));
    let proof = r
        .accept_one_read(&peer(9), &a.lease, &valid_reply(&id(&outbound.xml)))
        .unwrap();
    assert_eq!(proof.returned_parameter_count, 1);
    assert_eq!(proof.fault_code, None);
    assert!(!proof.operator_reviewed && !proof.physical_device_verified);
    assert!(!proof.tenant_approved_for_live_provisioning);
    r.finish(&peer(9), a.lease).unwrap();
    assert_eq!(r.active_count(), 0);
}
#[test]
fn empty_post_requires_no_soapaction_no_content_type_no_body() {
    assert!(ValidEmptyPost::validate(b"", None, None).is_ok());
    for (body, soap, content) in [
        (&b"x"[..], None, None),
        (b"" as &[u8], Some(""), None),
        (b"" as &[u8], None, Some("text/xml")),
    ] {
        assert!(matches!(
            ValidEmptyPost::validate(body, soap, content),
            Err(Error::InvalidEmptyPost)
        ));
    }
}
#[test]
fn wrong_peer_cannot_issue_or_complete_existing_tenant_bound_lease() {
    let mut r = enrolled();
    assert_eq!(
        r.begin(&peer(9), &tenant("nengnet"), INFORM).err(),
        Some(Error::WrongTenant)
    );
    let a = r.begin(&peer(9), &tenant("kangnet"), INFORM).unwrap();
    assert!(matches!(
        r.issue_one_read(
            &peer(7),
            &a.lease,
            ValidEmptyPost::validate(b"", None, None).unwrap()
        ),
        Err(Error::InvalidLease)
    ));
    let rpc = r
        .issue_one_read(
            &peer(9),
            &a.lease,
            ValidEmptyPost::validate(b"", None, None).unwrap(),
        )
        .unwrap();
    assert_eq!(
        r.accept_one_read(&peer(7), &a.lease, &valid_reply(&id(&rpc.xml)))
            .err(),
        Some(Error::InvalidLease)
    );
    assert_eq!(
        r.abort_session(&peer(7), &a.lease),
        Err(Error::InvalidLease)
    );
    r.abort_session(&peer(9), &a.lease).unwrap();
}
#[test]
fn concurrent_and_duplicate_rpc_issue_are_denied() {
    let mut r = enrolled();
    let a = r.begin(&peer(9), &tenant("kangnet"), INFORM).unwrap();
    assert_eq!(
        r.begin(
            &peer(9),
            &tenant("kangnet"),
            &INFORM.replace("lab-1", "lab-2")
        )
        .err(),
        Some(Error::Busy)
    );
    let first = r
        .issue_one_read(
            &peer(9),
            &a.lease,
            ValidEmptyPost::validate(b"", None, None).unwrap(),
        )
        .unwrap();
    assert!(first.xml.contains("Device.DeviceInfo.SoftwareVersion"));
    assert!(matches!(
        r.issue_one_read(
            &peer(9),
            &a.lease,
            ValidEmptyPost::validate(b"", None, None).unwrap()
        ),
        Err(Error::InvalidReadState)
    ));
    r.abort_session(&peer(9), &a.lease).unwrap();
}
#[test]
fn malformed_wrong_id_and_write_response_leave_session_pending() {
    let mut r = enrolled();
    let a = r.begin(&peer(9), &tenant("kangnet"), INFORM).unwrap();
    let rpc = r
        .issue_one_read(
            &peer(9),
            &a.lease,
            ValidEmptyPost::validate(b"", None, None).unwrap(),
        )
        .unwrap();
    let expected = id(&rpc.xml);
    assert_eq!(
        r.accept_one_read(&peer(9), &a.lease, &valid_reply("forged"))
            .err(),
        Some(Error::InvalidRpc)
    );
    let unapproved = reply(
        &expected,
        "Device.ManagementServer.Password",
        "FAKE-DO-NOT-STORE",
    );
    assert_eq!(
        r.accept_one_read(&peer(9), &a.lease, &unapproved).err(),
        Some(Error::InvalidRpc)
    );
    assert_eq!(
        r.accept_one_read(
            &peer(9),
            &a.lease,
            &valid_reply(&expected).replace("GetParameterValuesResponse", "SetParameterValues")
        )
        .err(),
        Some(Error::InvalidRpc)
    );
    assert_eq!(r.active_count(), 1);
    r.abort_session(&peer(9), &a.lease).unwrap();
    assert_eq!(
        r.begin(&peer(9), &tenant("kangnet"), INFORM).err(),
        Some(Error::Replay)
    );
}
#[test]
fn valid_fault_is_sanitized_and_cannot_be_replayed() {
    let mut r = enrolled();
    let a = r.begin(&peer(9), &tenant("kangnet"), INFORM).unwrap();
    let rpc = r
        .issue_one_read(
            &peer(9),
            &a.lease,
            ValidEmptyPost::validate(b"", None, None).unwrap(),
        )
        .unwrap();
    let payload = format!(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<s:Header><cwmp:ID s:mustUnderstand="1">{}</cwmp:ID></s:Header>
<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>REDACTED</faultstring>
<detail><cwmp:Fault><FaultCode>9005</FaultCode><FaultString>SECRET</FaultString></cwmp:Fault></detail>
</s:Fault></s:Body></s:Envelope>"#,
        id(&rpc.xml)
    );
    let e = r.accept_one_read(&peer(9), &a.lease, &payload).unwrap();
    assert_eq!(e.fault_code, Some(9005));
    assert_eq!(e.returned_parameter_count, 0);
    assert!(!e.physical_device_verified);
    assert_eq!(
        r.accept_one_read(&peer(9), &a.lease, &payload).err(),
        Some(Error::InvalidReadState)
    );
    r.finish(&peer(9), a.lease).unwrap();
}
#[test]
fn pending_read_must_not_be_silently_finished() {
    let mut r = enrolled();
    let a = r.begin(&peer(9), &tenant("kangnet"), INFORM).unwrap();
    r.issue_one_read(
        &peer(9),
        &a.lease,
        ValidEmptyPost::validate(b"", None, None).unwrap(),
    )
    .unwrap();
    assert_eq!(r.finish(&peer(9), a.lease), Err(Error::InvalidReadState));
    assert_eq!(r.active_count(), 1);
}
