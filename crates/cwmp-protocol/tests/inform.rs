use cwmp_protocol::{inform_response, parse_inform, ParseError, MAX_XML_BYTES};

const VALID: &str = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <soap:Header>
    <cwmp:ID soap:mustUnderstand="1">corr-1</cwmp:ID>
  </soap:Header>
  <soap:Body>
    <cwmp:Inform>
      <DeviceId>
        <Manufacturer>Synthetic Lab</Manufacturer>
        <OUI>001122</OUI>
        <ProductClass>LAB-ONT</ProductClass>
        <SerialNumber>SN-TEST</SerialNumber>
      </DeviceId>
      <Event>
        <EventStruct>
          <EventCode>0 BOOTSTRAP</EventCode>
          <CommandKey/>
        </EventStruct>
      </Event>
      <MaxEnvelopes>1</MaxEnvelopes>
      <CurrentTime>2026-09-25T10:00:00Z</CurrentTime>
      <RetryCount>0</RetryCount>
      <ParameterList/>
    </cwmp:Inform>
  </soap:Body>
</soap:Envelope>"#;

#[test]
fn parses_synthetic_inform_without_implicitly_authenticating_device() {
    let msg = parse_inform(VALID).unwrap();
    assert_eq!(msg.manufacturer, "Synthetic Lab");
    assert_eq!(msg.oui, "001122");
    assert_eq!(msg.serial_number, "SN-TEST");
    assert_eq!(msg.event_codes, vec!["0 BOOTSTRAP"]);
    assert_eq!(msg.cwmp_id.as_deref(), Some("corr-1"));
}

#[test]
fn generates_namespaced_inform_response_and_preserves_correlation_id() {
    let parsed = parse_inform(VALID).unwrap();
    let response = inform_response(&parsed);
    let doc = roxmltree::Document::parse(&response).unwrap();
    assert!(doc.descendants().any(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some("urn:dslforum-org:cwmp-1-0")
            && n.tag_name().name() == "InformResponse"
    }));
    assert!(response.contains("<cwmp:ID soap:mustUnderstand=\"1\">corr-1</cwmp:ID>"));
}

#[test]
fn escapes_correlation_id_in_response() {
    let input = VALID.replace("corr-1</cwmp:ID>", "corr&amp;&lt;admin&gt;</cwmp:ID>");
    let parsed = parse_inform(&input).unwrap();
    assert_eq!(parsed.cwmp_id.as_deref(), Some("corr&<admin>"));
    let response = inform_response(&parsed);
    assert!(response.contains("corr&amp;&lt;admin&gt;</cwmp:ID>"));
    assert!(!response.contains("corr&<admin>"));
}

#[test]
fn rejects_doctype_even_if_empty() {
    let input = VALID.replace(
        "<?xml version=\"1.0\"?>",
        "<?xml version=\"1.0\"?><!DOCTYPE soap:Envelope[]>",
    );
    assert_eq!(parse_inform(&input), Err(ParseError::UnsafeXml));
}

#[test]
fn rejects_oversized_input_before_parse() {
    let input = format!("{VALID}{}", " ".repeat(MAX_XML_BYTES));
    assert_eq!(parse_inform(&input), Err(ParseError::Oversize));
}

#[test]
fn rejects_other_soap_namespace() {
    let input = VALID.replace(
        "http://schemas.xmlsoap.org/soap/envelope/",
        "http://www.w3.org/2003/05/soap-envelope",
    );
    assert_eq!(parse_inform(&input), Err(ParseError::WrongEnvelope));
}

#[test]
fn rejects_unnegotiated_cwmp_version() {
    let input = VALID.replace("urn:dslforum-org:cwmp-1-0", "urn:dslforum-org:cwmp-1-2");
    // This limited parser rejects the unsupported version; the exact error
    // can depend on whether its header or method is examined first.
    assert!(parse_inform(&input).is_err());
}

#[test]
fn rejects_duplicate_device_identity() {
    let input = VALID.replace("</DeviceId>", "</DeviceId><DeviceId/>");
    assert_eq!(parse_inform(&input), Err(ParseError::Duplicate("DeviceId")));
}

#[test]
fn rejects_missing_serial_number() {
    let input = VALID.replace("<SerialNumber>SN-TEST</SerialNumber>", "");
    assert_eq!(
        parse_inform(&input),
        Err(ParseError::Missing("SerialNumber"))
    );
}

#[test]
fn rejects_unknown_mandatory_header() {
    let input = VALID.replace(
        "</soap:Header>",
        "<unknown:Other xmlns:unknown=\"urn:test\" soap:mustUnderstand=\"1\"/></soap:Header>",
    );
    assert_eq!(parse_inform(&input), Err(ParseError::UnsupportedHeader));
}

#[test]
fn rejects_deeply_nested_xml() {
    let input = VALID.replace(
        "<ParameterList/>",
        &format!(
            "<ParameterList>{}{}</ParameterList>",
            "<a>".repeat(40),
            "</a>".repeat(40)
        ),
    );
    assert_eq!(parse_inform(&input), Err(ParseError::TooDeep));
}

#[test]
fn rejects_invalid_retry_count() {
    let input = VALID.replace("<RetryCount>0</RetryCount>", "<RetryCount>-1</RetryCount>");
    assert_eq!(
        parse_inform(&input),
        Err(ParseError::InvalidField("RetryCount"))
    );
}

#[test]
fn retains_unrecognized_event_code_as_untrusted_data() {
    let input = VALID.replace("0 BOOTSTRAP", "X VENDOR EVENT");
    let parsed = parse_inform(&input).unwrap();
    assert_eq!(parsed.event_codes, vec!["X VENDOR EVENT"]);
}

#[test]
fn rejects_invalid_oui() {
    let input = VALID.replace("<OUI>001122</OUI>", "<OUI>NOTHEX</OUI>");
    assert_eq!(parse_inform(&input), Err(ParseError::InvalidField("OUI")));
}

#[test]
fn rejects_duplicate_soap_body_methods() {
    let input = VALID.replace("</soap:Body>", "<cwmp:Inform/></soap:Body>");
    assert_eq!(parse_inform(&input), Err(ParseError::WrongMethod));
}
