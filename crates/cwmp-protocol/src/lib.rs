//! Offline, untrusted-input CWMP 1.0 Inform parsing; **not** an ACS listener.
//! The transport adapter MUST authenticate and bind CPE identity to a tenant
//! before queuing work or returning this module's response XML.

pub mod rpc;

use roxmltree::{Document, Node, ParsingOptions};

const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const CWMP_10_NS: &str = "urn:dslforum-org:cwmp-1-0";
pub const MAX_XML_BYTES: usize = 64 * 1024;
const MAX_XML_NODES: u32 = 2048;
const MAX_XML_DEPTH: usize = 32;
const MAX_EVENTS: usize = 32;
const MAX_FIELD_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Oversize,
    UnsafeXml,
    InvalidXml,
    TooDeep,
    WrongEnvelope,
    WrongMethod,
    UnsupportedHeader,
    Missing(&'static str),
    Duplicate(&'static str),
    InvalidField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inform {
    pub manufacturer: String,
    pub oui: String,
    pub product_class: String,
    pub serial_number: String,
    pub event_codes: Vec<String>,
    /// SOAP correlation token is not an authenticated device or tenant identity.
    pub cwmp_id: Option<String>,
}

fn optional_child<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: Option<&str>,
    local: &'static str,
) -> Result<Option<Node<'a, 'input>>, ParseError> {
    let mut matches = parent.children().filter(|n| {
        n.is_element() && n.tag_name().namespace() == namespace && n.tag_name().name() == local
    });
    let first = matches.next();
    if matches.next().is_some() {
        return Err(ParseError::Duplicate(local));
    }
    Ok(first)
}

fn required_child<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: Option<&str>,
    local: &'static str,
) -> Result<Node<'a, 'input>, ParseError> {
    optional_child(parent, namespace, local)?.ok_or(ParseError::Missing(local))
}

fn text_field(
    parent: Node<'_, '_>,
    namespace: Option<&str>,
    local: &'static str,
    allow_empty: bool,
) -> Result<String, ParseError> {
    let node = required_child(parent, namespace, local)?;
    if node.children().any(|child| child.is_element()) {
        return Err(ParseError::InvalidField(local));
    }
    let value = node.text().unwrap_or_default().trim();
    if value.len() > MAX_FIELD_BYTES || (!allow_empty && value.is_empty()) {
        return Err(ParseError::InvalidField(local));
    }
    Ok(value.to_owned())
}

/// Parse only a bounded, structurally checked SOAP 1.1 / CWMP 1.0 Inform.
/// Version negotiation, cryptographic device authentication and sessions are
/// intentionally absent, so this must not be wired to the public ACS gateway.
pub fn parse_inform(xml: &str) -> Result<Inform, ParseError> {
    if xml.len() > MAX_XML_BYTES {
        return Err(ParseError::Oversize);
    }
    // roxmltree rejects nonempty DTD when allow_dtd=false; also reject empty DTD.
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return Err(ParseError::UnsafeXml);
    }
    let doc = Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_XML_NODES,
            entity_resolver: None,
        },
    )
    .map_err(|_| ParseError::InvalidXml)?;
    for node in doc.descendants().filter(|n| n.is_element()) {
        if node.ancestors().filter(|n| n.is_element()).count() > MAX_XML_DEPTH {
            return Err(ParseError::TooDeep);
        }
    }

    let envelope = doc.root_element();
    if envelope.tag_name().namespace() != Some(SOAP_NS) || envelope.tag_name().name() != "Envelope"
    {
        return Err(ParseError::WrongEnvelope);
    }

    let cwmp_id = match optional_child(envelope, Some(SOAP_NS), "Header")? {
        None => None,
        Some(header) => {
            if header.children().filter(|n| n.is_element()).any(|n| {
                n.tag_name().namespace() != Some(CWMP_10_NS) || n.tag_name().name() != "ID"
            }) {
                return Err(ParseError::UnsupportedHeader);
            }
            match optional_child(header, Some(CWMP_10_NS), "ID")? {
                None => None,
                Some(id) => {
                    if id.attribute((SOAP_NS, "mustUnderstand")) != Some("1")
                        || id.children().any(|n| n.is_element())
                    {
                        return Err(ParseError::InvalidField("cwmp:ID"));
                    }
                    let value = id.text().unwrap_or_default().trim();
                    if value.is_empty()
                        || value.len() > MAX_FIELD_BYTES
                        || value.chars().any(char::is_control)
                    {
                        return Err(ParseError::InvalidField("cwmp:ID"));
                    }
                    Some(value.to_owned())
                }
            }
        }
    };

    let body = required_child(envelope, Some(SOAP_NS), "Body")?;
    if body.children().filter(|n| n.is_element()).count() != 1 {
        return Err(ParseError::WrongMethod);
    }
    let inform =
        optional_child(body, Some(CWMP_10_NS), "Inform")?.ok_or(ParseError::WrongMethod)?;

    let device_id = required_child(inform, None, "DeviceId")?;
    let manufacturer = text_field(device_id, None, "Manufacturer", false)?;
    let oui = text_field(device_id, None, "OUI", false)?;
    if oui.len() != 6 || !oui.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ParseError::InvalidField("OUI"));
    }
    let product_class = text_field(device_id, None, "ProductClass", true)?;
    let serial_number = text_field(device_id, None, "SerialNumber", false)?;
    let event = required_child(inform, None, "Event")?;
    let mut event_codes = Vec::new();
    for item in event.children().filter(|n| n.is_element()) {
        if item.tag_name().namespace().is_some() || item.tag_name().name() != "EventStruct" {
            return Err(ParseError::InvalidField("Event"));
        }
        event_codes.push(text_field(item, None, "EventCode", false)?);
        text_field(item, None, "CommandKey", true)?;
        if event_codes.len() > MAX_EVENTS {
            return Err(ParseError::InvalidField("Event"));
        }
    }
    if event_codes.is_empty() {
        return Err(ParseError::Missing("EventStruct"));
    }

    if text_field(inform, None, "MaxEnvelopes", false)? != "1" {
        return Err(ParseError::InvalidField("MaxEnvelopes"));
    }
    text_field(inform, None, "CurrentTime", false)?;
    let retry_count = text_field(inform, None, "RetryCount", false)?;
    if retry_count.parse::<u32>().is_err() {
        return Err(ParseError::InvalidField("RetryCount"));
    }
    required_child(inform, None, "ParameterList")?;
    Ok(Inform {
        manufacturer,
        oui,
        product_class,
        serial_number,
        event_codes,
        cwmp_id,
    })
}

fn escape_xml(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Pure response serializer; the calling gateway MUST verify CPE identity
/// and establish a CWMP session before sending this response on the network.
pub fn inform_response(inform: &Inform) -> String {
    let header = inform.cwmp_id.as_deref().map_or_else(String::new, |id| {
        format!(
            "<soap:Header><cwmp:ID soap:mustUnderstand=\"1\">{}</cwmp:ID></soap:Header>",
            escape_xml(id)
        )
    });
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:soap=\"{SOAP_NS}\" xmlns:cwmp=\"{CWMP_10_NS}\">{header}<soap:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></soap:Body></soap:Envelope>"
    )
}
