use cwmp_protocol::rpc::{
    parse_read_reply, read_request, CwmpFault, RpcError, RpcReply, LAB_PARAMETER,
};
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const CWMP: &str = "urn:dslforum-org:cwmp-1-0";
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const XSD: &str = "http://www.w3.org/2001/XMLSchema";
fn response(id: &str, name: &str, value: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="{SOAP}" xmlns:cwmp="{CWMP}"
 xmlns:xsi="{XSI}" xmlns:xsd="{XSD}">
<soap:Header><cwmp:ID soap:mustUnderstand="1">{id}</cwmp:ID></soap:Header>
<soap:Body><cwmp:GetParameterValuesResponse>
<ParameterList><ParameterValueStruct>
<Name>{name}</Name><Value xsi:type="xsd:string">{value}</Value>
</ParameterValueStruct></ParameterList>
</cwmp:GetParameterValuesResponse></soap:Body></soap:Envelope>"#
    )
}
const ID: &str = "ipat-read-1";
#[test]
fn creates_exact_one_read_rpc_without_any_write_methods() {
    let xml = read_request(ID, LAB_PARAMETER).unwrap();
    assert!(xml.contains("<cwmp:GetParameterValues>"));
    assert!(!xml.contains("<cwmp:SetParameterValues>"));
    assert!(xml.contains("<string>Device.DeviceInfo.SoftwareVersion</string>"));
    assert_eq!(xml.matches("<string>").count(), 1);
}
#[test]
fn blocks_arbitrary_parameter_names_and_unsafe_correlation_ids() {
    for path in [
        "",
        "InternetGatewayDevice.ManagementServer.Password",
        "Device.Users.User.1.Password",
        "Device.DeviceInfo.SoftwareVersion&x",
    ] {
        assert!(matches!(
            read_request(ID, path),
            Err(RpcError::InvalidRequest)
        ));
    }
    for id in ["", "line\nbreak", "\u{0000}", &"z".repeat(129)] {
        assert!(matches!(
            read_request(id, LAB_PARAMETER),
            Err(RpcError::InvalidRequest)
        ));
    }
}
#[test]
fn accepts_exact_one_correlated_synthetic_software_version_value() {
    match parse_read_reply(&response(ID, LAB_PARAMETER, "7.23.7"), ID, LAB_PARAMETER).unwrap() {
        RpcReply::Values(values) => {
            assert_eq!(values.count(), 1);
            assert_eq!(values.get(LAB_PARAMETER), Some("7.23.7"));
            assert_eq!(values.get("other"), None);
        }
        _ => panic!("must parse value"),
    }
}
#[test]
fn disallows_response_spoofing_correlation_and_duplicate_id() {
    let valid = response(ID, LAB_PARAMETER, "1.0");
    for xml in [
        valid.replace(ID, "forged-id"),
        valid.replace("mustUnderstand=\"1\"", "mustUnderstand=\"0\""),
        valid.replace(
            "</soap:Header>",
            &format!("<cwmp:ID soap:mustUnderstand=\"1\">{ID}</cwmp:ID></soap:Header>"),
        ),
        valid.replace("<soap:Header>", "<soap:Header><UntrustedHeader/>"),
    ] {
        assert!(matches!(
            parse_read_reply(&xml, ID, LAB_PARAMETER),
            Err(RpcError::InvalidCorrelation)
        ));
    }
}
#[test]
fn rejects_unexpected_method_and_soap_namespace() {
    let valid = response(ID, LAB_PARAMETER, "1.0");
    let write = valid.replace("GetParameterValuesResponse", "SetParameterValues");
    assert!(matches!(
        parse_read_reply(&write, ID, LAB_PARAMETER),
        Err(RpcError::UnexpectedMethod)
    ));
    let wrong_soap = valid.replace(SOAP, "http://www.w3.org/2003/05/soap-envelope");
    assert!(matches!(
        parse_read_reply(&wrong_soap, ID, LAB_PARAMETER),
        Err(RpcError::UnexpectedEnvelope)
    ));
}
#[test]
fn rejects_dtd_oversize_deep_and_malformed_xml() {
    let valid = response(ID, LAB_PARAMETER, "1.0");
    let dtd = valid.replace(
        "<?xml version=\"1.0\"?>",
        "<?xml version=\"1.0\"?><!DOCTYPE x[]>",
    );
    assert!(matches!(
        parse_read_reply(&dtd, ID, LAB_PARAMETER),
        Err(RpcError::UnsafeXml)
    ));
    let oversized = format!("{}{}", valid, " ".repeat(65536));
    assert!(matches!(
        parse_read_reply(&oversized, ID, LAB_PARAMETER),
        Err(RpcError::Oversize)
    ));
    assert!(parse_read_reply("<soap:Envelope>", ID, LAB_PARAMETER).is_err());
}
#[test]
fn rejects_secret_unrequested_duplicate_and_oversize_parameter_values() {
    let valid = response(ID, LAB_PARAMETER, "1.0");
    let wrong = valid.replace(LAB_PARAMETER, "Device.ManagementServer.Password");
    assert!(matches!(
        parse_read_reply(&wrong, ID, LAB_PARAMETER),
        Err(RpcError::InvalidParameter)
    ));
    let duplicate = valid.replace("</ParameterList>",
        &format!("<ParameterValueStruct><Name>{LAB_PARAMETER}</Name><Value xsi:type=\"xsd:string\">2</Value></ParameterValueStruct></ParameterList>"));
    assert!(parse_read_reply(&duplicate, ID, LAB_PARAMETER).is_err());
    let too_large = response(ID, LAB_PARAMETER, &"x".repeat(257));
    assert!(matches!(
        parse_read_reply(&too_large, ID, LAB_PARAMETER),
        Err(RpcError::InvalidParameter)
    ));
    let bogus_xsd = valid.replace(XSD, "https://attacker.invalid/schema");
    assert!(matches!(
        parse_read_reply(&bogus_xsd, ID, LAB_PARAMETER),
        Err(RpcError::InvalidParameter)
    ));
    let wrong_type = valid.replace("xsd:string", "xsd:base64Binary");
    assert!(matches!(
        parse_read_reply(&wrong_type, ID, LAB_PARAMETER),
        Err(RpcError::InvalidParameter)
    ));
}
fn fault(id: &str, code: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="{SOAP}" xmlns:cwmp="{CWMP}">
<soap:Header><cwmp:ID soap:mustUnderstand="1">{id}</cwmp:ID></soap:Header>
<soap:Body><soap:Fault>
<faultcode>soap:Client</faultcode><faultstring>Private details are never returned</faultstring>
<detail><cwmp:Fault><FaultCode>{code}</FaultCode>
<FaultString>Potentially sensitive detail</FaultString></cwmp:Fault></detail>
</soap:Fault></soap:Body></soap:Envelope>"#
    )
}
#[test]
fn maps_correlated_standard_cwmp_fault_to_numeric_only() {
    match parse_read_reply(&fault(ID, "9005"), ID, LAB_PARAMETER).unwrap() {
        RpcReply::Fault(CwmpFault { code: 9005 }) => {}
        _ => panic!("expected sanitized CWMP fault"),
    }
    assert!(parse_read_reply(&fault("bad-id", "9005"), ID, LAB_PARAMETER).is_err());
}
#[test]
fn rejects_invalid_numeric_fault_or_duplicate_detail() {
    for code in ["", "abc", "8999", "9999", "900512345"] {
        assert!(parse_read_reply(&fault(ID, code), ID, LAB_PARAMETER).is_err());
    }
    let extra = fault(ID, "9005").replace(
        "</detail>",
        "<cwmp:Fault><FaultCode>9005</FaultCode></cwmp:Fault></detail>",
    );
    assert!(parse_read_reply(&extra, ID, LAB_PARAMETER).is_err());
}
