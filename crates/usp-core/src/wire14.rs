//! Original IPAT *subset* of BBF USP v1.4 protobuf wire schema.
//! Mapping manually derived from BroadbandForum/usp official
//! specification/usp-{record,msg}-1-4.proto (exact pinned digests in docs).
//! Only bounded offline no-session Get request and GetResp inspection.
//! NOT trusted agent enrollment, MQTT transport, session crypto or USP compliance.
use prost::Message;
use std::collections::{HashMap, HashSet};

pub const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_MSG_BYTES: usize = 48 * 1024;
const MAX_RESULTS: usize = 32;
const MAX_RESOLVED: usize = 64;
const MAX_PARAMS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Oversize,
    Malformed,
    UnknownOrDuplicateField,
    UnsupportedRecord,
    UnsupportedMessage,
    InvalidIdentifier,
    InvalidPath,
    InvalidResult,
}

#[derive(Clone, PartialEq, Message)]
struct Record {
    #[prost(string, tag = "1")]
    version: String,
    #[prost(string, tag = "2")]
    to_id: String,
    #[prost(string, tag = "3")]
    from_id: String,
    #[prost(int32, tag = "4")]
    payload_security: i32,
    #[prost(bytes, tag = "5")]
    mac_signature: Vec<u8>,
    #[prost(bytes, tag = "6")]
    sender_cert: Vec<u8>,
    #[prost(message, optional, tag = "7")]
    no_session_context: Option<NoSessionContextRecord>,
}
#[derive(Clone, PartialEq, Message)]
struct NoSessionContextRecord {
    #[prost(bytes, tag = "2")]
    payload: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct Msg {
    #[prost(message, optional, tag = "1")]
    header: Option<Header>,
    #[prost(message, optional, tag = "2")]
    body: Option<Body>,
}
#[derive(Clone, PartialEq, Message)]
struct Header {
    #[prost(string, tag = "1")]
    msg_id: String,
    #[prost(int32, tag = "2")]
    msg_type: i32,
}
#[derive(Clone, PartialEq, Message)]
struct Body {
    #[prost(message, optional, tag = "1")]
    request: Option<Request>,
    #[prost(message, optional, tag = "2")]
    response: Option<Response>,
}
#[derive(Clone, PartialEq, Message)]
struct Request {
    #[prost(message, optional, tag = "1")]
    get: Option<Get>,
}
#[derive(Clone, PartialEq, Message)]
struct Get {
    #[prost(string, repeated, tag = "1")]
    param_paths: Vec<String>,
    #[prost(fixed32, tag = "2")]
    max_depth: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Response {
    #[prost(message, optional, tag = "1")]
    get_resp: Option<GetResp>,
}
#[derive(Clone, PartialEq, Message)]
struct GetResp {
    #[prost(message, repeated, tag = "1")]
    req_path_results: Vec<RequestedPathResult>,
}
#[derive(Clone, PartialEq, Message)]
struct RequestedPathResult {
    #[prost(string, tag = "1")]
    requested_path: String,
    #[prost(fixed32, tag = "2")]
    err_code: u32,
    #[prost(string, tag = "3")]
    err_msg: String,
    #[prost(message, repeated, tag = "4")]
    resolved_path_results: Vec<ResolvedPathResult>,
}
#[derive(Clone, PartialEq, Message)]
struct ResolvedPathResult {
    #[prost(string, tag = "1")]
    resolved_path: String,
    #[prost(map = "string, string", tag = "2")]
    result_params: HashMap<String, String>,
}

/// Individual field scanner before prost decoding: prost accepts duplicate
/// singular/oneof fields as last-one-wins, while USP R-ENC.3 forbids this.
#[derive(Clone, Copy)]
struct Field<'a> {
    tag: u32,
    data: &'a [u8],
}
fn varint(raw: &[u8], pos: &mut usize) -> Result<u64, WireError> {
    let mut value = 0u64;
    for i in 0..10 {
        let Some(&byte) = raw.get(*pos) else {
            return Err(WireError::Malformed);
        };
        *pos += 1;
        if i == 9 && byte > 1 {
            return Err(WireError::Malformed);
        }
        value |= u64::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WireError::Malformed)
}
fn fields<'a>(raw: &'a [u8], rules: &[(u32, u8, bool)]) -> Result<Vec<Field<'a>>, WireError> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut at = 0usize;
    while at < raw.len() {
        if out.len() >= 1024 {
            return Err(WireError::Oversize);
        }
        let key = varint(raw, &mut at)?;
        let tag = u32::try_from(key >> 3).map_err(|_| WireError::Malformed)?;
        let wt = (key & 7) as u8;
        let Some(&(_, _, repeat)) = rules.iter().find(|&&(n, w, _)| n == tag && w == wt) else {
            return Err(WireError::UnknownOrDuplicateField);
        };
        if tag == 0 || (!repeat && !seen.insert(tag)) {
            return Err(WireError::UnknownOrDuplicateField);
        }
        let begin = at;
        let end = match wt {
            0 => {
                varint(raw, &mut at)?;
                at
            }
            2 => {
                let size =
                    usize::try_from(varint(raw, &mut at)?).map_err(|_| WireError::Oversize)?;
                let start = at;
                at = at
                    .checked_add(size)
                    .filter(|end| *end <= raw.len())
                    .ok_or(WireError::Oversize)?;
                out.push(Field {
                    tag,
                    data: &raw[start..at],
                });
                continue;
            }
            5 => at
                .checked_add(4)
                .filter(|end| *end <= raw.len())
                .ok_or(WireError::Malformed)?,
            _ => return Err(WireError::Malformed),
        };
        out.push(Field {
            tag,
            data: &raw[begin..end],
        });
        at = end;
    }
    Ok(out)
}
fn one<'a>(fields: &'a [Field<'a>], tag: u32) -> Result<&'a [u8], WireError> {
    fields
        .iter()
        .find(|f| f.tag == tag)
        .map(|f| f.data)
        .ok_or(WireError::Malformed)
}
fn endpoint(s: &str) -> bool {
    (4..=128).contains(&s.len())
        && s.starts_with("usp::")
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(b))
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(b))
}
fn path(s: &str) -> bool {
    s.starts_with("Device.")
        && (8..=128).contains(&s.len())
        && !s.contains("..")
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._".contains(b))
}
fn decode<T: Message + Default>(raw: &[u8]) -> Result<T, WireError> {
    T::decode(raw).map_err(|_| WireError::Malformed)
}

pub struct InspectedGetResponse {
    /// UNTRUSTED claimed endpoint; never use for tenant/device identity.
    pub claimed_from: String,
    /// UNTRUSTED record destination; never use for controller authentication.
    pub claimed_to: String,
    pub message_id: String,
    pub requested_paths: usize,
    pub resolved_paths: usize,
    pub parameter_values: usize,
}

/// Decode actual BBF v1.4 Record/Msg/GetResp protobuf without trusting
/// the transport sender. No raw values/serial numbers are returned.
/// Reject session/fragmentation, signed-claimed fields, unknown extensions,
/// duplicate oneof fields, writes/notifications and unbounded result sets.
pub fn inspect_no_session_get_response(raw: &[u8]) -> Result<InspectedGetResponse, WireError> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(WireError::Oversize);
    }
    let rf = fields(
        raw,
        &[
            (1, 2, false),
            (2, 2, false),
            (3, 2, false),
            (4, 0, false),
            (5, 2, false),
            (6, 2, false),
            (7, 2, false),
        ],
    )?;
    let record: Record = decode(raw)?;
    if record.version != "1.4"
        || !endpoint(&record.to_id)
        || !endpoint(&record.from_id)
        || record.from_id == record.to_id
        || record.payload_security != 0
        || !record.mac_signature.is_empty()
        || !record.sender_cert.is_empty()
    {
        return Err(WireError::UnsupportedRecord);
    }
    let ns = record
        .no_session_context
        .ok_or(WireError::UnsupportedRecord)?;
    let nf = fields(one(&rf, 7)?, &[(2, 2, false)])?;
    if ns.payload.len() > MAX_MSG_BYTES || ns.payload.is_empty() || !nf.iter().any(|f| f.tag == 2) {
        return Err(WireError::UnsupportedRecord);
    }
    let mf = fields(&ns.payload, &[(1, 2, false), (2, 2, false)])?;
    let msg: Msg = decode(&ns.payload)?;
    let head = msg.header.ok_or(WireError::UnsupportedMessage)?;
    let hf = fields(one(&mf, 1)?, &[(1, 2, false), (2, 0, false)])?;
    one(&hf, 1)?;
    one(&hf, 2)?;
    if head.msg_type != 2 || !identifier(&head.msg_id) {
        return Err(WireError::UnsupportedMessage);
    }
    let body = msg.body.ok_or(WireError::UnsupportedMessage)?;
    let bf = fields(one(&mf, 2)?, &[(1, 2, false), (2, 2, false), (3, 2, false)])?;
    if bf.len() != 1 || bf[0].tag != 2 || body.request.is_some() {
        return Err(WireError::UnsupportedMessage);
    }
    let resp = body.response.ok_or(WireError::UnsupportedMessage)?;
    let re = fields(
        one(&bf, 2)?,
        &[
            (1, 2, false),
            (2, 2, false),
            (3, 2, false),
            (4, 2, false),
            (5, 2, false),
            (6, 2, false),
            (7, 2, false),
            (8, 2, false),
            (9, 2, false),
            (10, 2, false),
            (11, 2, false),
        ],
    )?;
    if re.len() != 1 || re[0].tag != 1 {
        return Err(WireError::UnsupportedMessage);
    }
    let get = resp.get_resp.ok_or(WireError::UnsupportedMessage)?;
    let gf = fields(one(&re, 1)?, &[(1, 2, true)])?;
    if gf.len() > MAX_RESULTS {
        return Err(WireError::Oversize);
    }
    if gf.len() != get.req_path_results.len() {
        return Err(WireError::Malformed);
    }
    let mut resolved = 0usize;
    let mut parameters = 0usize;
    for (r, wire) in get.req_path_results.iter().zip(gf.iter()) {
        let rf = fields(
            wire.data,
            &[(1, 2, false), (2, 5, false), (3, 2, false), (4, 2, true)],
        )?;
        one(&rf, 1)?;
        if !path(&r.requested_path) || r.err_code != 0 || !r.err_msg.is_empty() {
            return Err(WireError::InvalidResult);
        }
        if r.resolved_path_results.len() > MAX_RESOLVED {
            return Err(WireError::Oversize);
        }
        let paths = rf.iter().filter(|f| f.tag == 4).collect::<Vec<_>>();
        if paths.len() != r.resolved_path_results.len() {
            return Err(WireError::Malformed);
        }
        for (row, wire) in r.resolved_path_results.iter().zip(paths) {
            let rp = fields(wire.data, &[(1, 2, false), (2, 2, true)])?;
            one(&rp, 1)?;
            if !path(&row.resolved_path) || row.result_params.len() > MAX_PARAMS {
                return Err(WireError::InvalidResult);
            }
            let entries = rp.iter().filter(|f| f.tag == 2).collect::<Vec<_>>();
            if entries.len() != row.result_params.len() {
                return Err(WireError::UnknownOrDuplicateField);
            }
            for entry in entries {
                let kv = fields(entry.data, &[(1, 2, false), (2, 2, false)])?;
                one(&kv, 1)?;
                one(&kv, 2)?;
            }
            resolved += 1;
            parameters += row.result_params.len();
        }
    }
    Ok(InspectedGetResponse {
        claimed_from: record.from_id,
        claimed_to: record.to_id,
        message_id: head.msg_id,
        requested_paths: gf.len(),
        resolved_paths: resolved,
        parameter_values: parameters,
    })
}

/// Offline-only genuine BBF 1.4 protobuf Get payload; NEVER send to devices
/// without independently trusted OIDC operator/tenant and TLS MQTT identity.
/// No admission API is added, and this does NOT grant a USP session.
pub fn encode_offline_get(
    claimed_controller: &str,
    claimed_agent: &str,
    message_id: &str,
    param_paths: &[&str],
) -> Result<Vec<u8>, WireError> {
    if !endpoint(claimed_controller)
        || !endpoint(claimed_agent)
        || claimed_controller == claimed_agent
        || !identifier(message_id)
    {
        return Err(WireError::InvalidIdentifier);
    }
    if param_paths.is_empty()
        || param_paths.len() > MAX_RESULTS
        || param_paths.iter().any(|p| !path(p))
    {
        return Err(WireError::InvalidPath);
    }
    let msg = Msg {
        header: Some(Header {
            msg_id: message_id.to_owned(),
            msg_type: 1,
        }),
        body: Some(Body {
            request: Some(Request {
                get: Some(Get {
                    param_paths: param_paths.iter().map(|p| (*p).to_owned()).collect(),
                    max_depth: 0,
                }),
            }),
            response: None,
        }),
    };
    let bytes = msg.encode_to_vec();
    if bytes.len() > MAX_MSG_BYTES {
        return Err(WireError::Oversize);
    }
    let record = Record {
        version: "1.4".to_owned(),
        to_id: claimed_agent.to_owned(),
        from_id: claimed_controller.to_owned(),
        payload_security: 0,
        mac_signature: Vec::new(),
        sender_cert: Vec::new(),
        no_session_context: Some(NoSessionContextRecord { payload: bytes }),
    };
    let output = record.encode_to_vec();
    if output.len() > MAX_RECORD_BYTES {
        return Err(WireError::Oversize);
    }
    Ok(output)
}
