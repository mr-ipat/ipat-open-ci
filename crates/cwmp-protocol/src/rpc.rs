//! Strict, offline CWMP 1.0 ONE read-only GetParameterValues RPC.
//! The network adapter must first authenticate and bind the peer/tenant.
//! No generic RPC names or write operations are accepted.
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::HashSet;
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const CWMP: &str = "urn:dslforum-org:cwmp-1-0";
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
pub const LAB_PARAMETER: &str = "Device.DeviceInfo.SoftwareVersion";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    InvalidRequest,
    Oversize,
    UnsafeXml,
    InvalidXml,
    UnexpectedEnvelope,
    InvalidCorrelation,
    UnexpectedMethod,
    InvalidParameter,
    DuplicateParameter,
    MissingParameter,
    InvalidFault,
}
/// Values are sensitive device-supplied data. Deliberately NOT Debug.
pub struct ReadValues {
    entries: Vec<(String, String)>,
}
impl ReadValues {
    pub fn count(&self) -> usize {
        self.entries.len()
    }
    pub fn get(&self, requested: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _)| n == requested)
            .map(|(_, v)| v.as_str())
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct CwmpFault {
    /// CWMP-defined numeric fault only; never retain its freeform string.
    pub code: u16,
}
pub enum RpcReply {
    Values(ReadValues),
    Fault(CwmpFault),
}

fn single<'a, 'i>(
    parent: Node<'a, 'i>,
    namespace: Option<&str>,
    local: &str,
) -> Result<Node<'a, 'i>, RpcError> {
    let mut iter = parent.children().filter(|n| {
        n.is_element() && n.tag_name().namespace() == namespace && n.tag_name().name() == local
    });
    let first = iter.next().ok_or(RpcError::InvalidXml)?;
    if iter.next().is_some() {
        return Err(RpcError::InvalidXml);
    }
    Ok(first)
}
fn bounded_text<'a, 'input>(node: Node<'a, 'input>, max: usize) -> Result<&'a str, RpcError> {
    if node.children().any(|n| n.is_element()) {
        return Err(RpcError::InvalidXml);
    }
    let s = node.text().unwrap_or_default();
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(RpcError::InvalidXml);
    }
    Ok(s)
}
fn escape(s: &str) -> String {
    let mut result = String::new();
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&apos;"),
            _ => result.push(ch),
        }
    }
    result
}
fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn valid_plan(path: &str) -> bool {
    path == LAB_PARAMETER
}

/// Only the immutable lab-approved parameter, never arbitrary device paths.
pub fn read_request(id: &str, path: &str) -> Result<String, RpcError> {
    if !valid_id(id) || !valid_plan(path) {
        return Err(RpcError::InvalidRequest);
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:soap=\"{SOAP}\" xmlns:cwmp=\"{CWMP}\" xmlns:soap-enc=\"http://schemas.xmlsoap.org/soap/encoding/\"><soap:Header><cwmp:ID soap:mustUnderstand=\"1\">{}</cwmp:ID></soap:Header><soap:Body><cwmp:GetParameterValues><ParameterNames soap-enc:arrayType=\"xsd:string[1]\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><string>{}</string></ParameterNames></cwmp:GetParameterValues></soap:Body></soap:Envelope>",
        escape(id), escape(path)
    ))
}
/// Parse one correlated response or fault; unknown/malformed methods fail.
pub fn parse_read_reply(
    xml: &str,
    expected_id: &str,
    parameter: &str,
) -> Result<RpcReply, RpcError> {
    if !valid_id(expected_id) || !valid_plan(parameter) {
        return Err(RpcError::InvalidRequest);
    }
    if xml.len() > crate::MAX_XML_BYTES {
        return Err(RpcError::Oversize);
    }
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err(RpcError::UnsafeXml);
    }
    let doc = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 2048,
            entity_resolver: None,
        },
    )
    .map_err(|_| RpcError::InvalidXml)?;
    if doc
        .descendants()
        .filter(|n| n.is_element())
        .any(|n| n.ancestors().filter(|x| x.is_element()).count() > 32)
    {
        return Err(RpcError::InvalidXml);
    }
    let env = doc.root_element();
    if env.tag_name().namespace() != Some(SOAP) || env.tag_name().name() != "Envelope" {
        return Err(RpcError::UnexpectedEnvelope);
    }
    let header = single(env, Some(SOAP), "Header").map_err(|_| RpcError::InvalidCorrelation)?;
    if header.children().filter(|n| n.is_element()).count() != 1 {
        return Err(RpcError::InvalidCorrelation);
    }
    let id = single(header, Some(CWMP), "ID").map_err(|_| RpcError::InvalidCorrelation)?;
    if id.attribute((SOAP, "mustUnderstand")) != Some("1")
        || bounded_text(id, 128).ok() != Some(expected_id)
    {
        return Err(RpcError::InvalidCorrelation);
    }
    let body = single(env, Some(SOAP), "Body")?;
    if env.children().filter(|n| n.is_element()).count() != 2
        || body.children().filter(|n| n.is_element()).count() != 1
    {
        return Err(RpcError::UnexpectedMethod);
    }
    let method = body
        .children()
        .find(|n| n.is_element())
        .ok_or(RpcError::UnexpectedMethod)?;
    match (method.tag_name().namespace(), method.tag_name().name()) {
        (Some(CWMP), "GetParameterValuesResponse") => {
            let list = single(method, None, "ParameterList")?;
            if method.children().filter(|n| n.is_element()).count() != 1 {
                return Err(RpcError::InvalidParameter);
            }
            let items: Vec<_> = list.children().filter(|n| n.is_element()).collect();
            if items.len() != 1 {
                return Err(RpcError::MissingParameter);
            }
            let item = items[0];
            if item.tag_name().namespace().is_some()
                || item.tag_name().name() != "ParameterValueStruct"
                || item.children().filter(|n| n.is_element()).count() != 2
            {
                return Err(RpcError::InvalidParameter);
            }
            let name = single(item, None, "Name")?;
            let found = bounded_text(name, 128).map_err(|_| RpcError::InvalidParameter)?;
            if found != parameter {
                return Err(RpcError::InvalidParameter);
            }
            let value = single(item, None, "Value")?;
            if value.children().any(|n| n.is_element()) {
                return Err(RpcError::InvalidParameter);
            }
            if value.attribute((XSI, "type")) != Some("xsd:string")
                || value.lookup_namespace_uri(Some("xsd"))
                    != Some("http://www.w3.org/2001/XMLSchema")
            {
                return Err(RpcError::InvalidParameter);
            }
            let val = value.text().unwrap_or_default();
            if val.len() > 256 || val.chars().any(char::is_control) {
                return Err(RpcError::InvalidParameter);
            }
            let mut seen = HashSet::new();
            if !seen.insert(found) {
                return Err(RpcError::DuplicateParameter);
            }
            Ok(RpcReply::Values(ReadValues {
                entries: vec![(found.to_owned(), val.to_owned())],
            }))
        }
        (Some(SOAP), "Fault") => {
            let detail = single(method, None, "detail").map_err(|_| RpcError::InvalidFault)?;
            let fault = single(detail, Some(CWMP), "Fault").map_err(|_| RpcError::InvalidFault)?;
            let raw = bounded_text(single(fault, None, "FaultCode")?, 4)
                .map_err(|_| RpcError::InvalidFault)?;
            if detail.children().filter(|n| n.is_element()).count() != 1 {
                return Err(RpcError::InvalidFault);
            }
            let code = raw.parse::<u16>().map_err(|_| RpcError::InvalidFault)?;
            if !(9000..=9899).contains(&code) {
                return Err(RpcError::InvalidFault);
            }
            Ok(RpcReply::Fault(CwmpFault { code }))
        }
        _ => Err(RpcError::UnexpectedMethod),
    }
}
