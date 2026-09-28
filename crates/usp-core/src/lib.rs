//! Native Rust USP Controller *domain-boundary* simulator.
//!
//! Domain logic below NEVER trusts unverified wire input; the separate
//! wire14 module implements a REAL, bounded BBF v1.4 OFFLINE protobuf subset,
//! NOT any USP MTP (MQTT/STOMP/WebSocket), authenticated TLS client or physical
//! agent interoperability. Domain types model synthetic read-only request
//! correlation, tenant/agent enrollment and fail-closed replay admission.
//! VerifiedAgent and TrustedOperator have NO public constructors; future
//! adapters must verify actual cryptographic identities before creating them.

pub mod wire14;

use std::collections::{HashMap, HashSet};
use tenant_core::TenantId;

const MAX_ENROLLMENTS: usize = 256;
const MAX_PENDING: usize = 64;
const MAX_REPLAYED: usize = 1024;
const MAX_ENDPOINT: usize = 128;
const MAX_PARAMETER: usize = 128;
const MAX_REPLY: usize = 4 * 1024;

pub struct AgentEnrollment {
    pub tenant: TenantId,
    endpoint_id: String,
    client_spki_sha256: [u8; 32],
}

fn endpoint_ok(endpoint: &str) -> bool {
    !endpoint.is_empty()
        && endpoint.len() <= MAX_ENDPOINT
        && endpoint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b))
}

fn message_id_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

impl AgentEnrollment {
    /// This does not authenticate enrollment. Only a future audited platform
    /// operator workflow may call this in a deployed controller.
    pub fn new(
        tenant: TenantId,
        endpoint_id: &str,
        client_spki_sha256: [u8; 32],
    ) -> Result<Self, Error> {
        if !endpoint_ok(endpoint_id) || client_spki_sha256 == [0; 32] {
            return Err(Error::InvalidEnrollment);
        }
        Ok(Self {
            tenant,
            endpoint_id: endpoint_id.to_owned(),
            client_spki_sha256,
        })
    }
}

/// Minting requires future reviewed TLS identity verification, never a
/// broker topic, a request-supplied endpoint ID or a tenant HTTP header.
pub struct VerifiedAgent {
    client_spki_sha256: [u8; 32],
}

/// Minting requires future OIDC/MFA/ABAC platform-service authorization.
pub struct TrustedOperator {
    tenant: TenantId,
}

/// A domain plan, not a TR-369 wire-format message or authorized device write.
pub struct SyntheticReadPlan {
    pub endpoint_id: String,
    pub request_id: String,
    pub parameter_path: String,
}

/// Untrusted synthetic frame fixture. NOT a USP Record or protobuf type.
pub struct SyntheticReply<'a> {
    pub claimed_endpoint_id: &'a str,
    pub message_id: &'a str,
    pub in_reply_to: &'a str,
    pub payload: &'a [u8],
}

pub struct Correlation {
    pub payload_bytes: usize,
    /// No raw device payload, credentials or tenant metadata is logged here.
    pub correlated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidEnrollment,
    DuplicateAgent,
    ReusedCertificate,
    EnrollmentFull,
    InvalidPath,
    Unenrolled,
    WrongTenant,
    WrongPeer,
    Busy,
    PendingFull,
    ReplayFull,
    Replay,
    BadReply,
    UnexpectedReply,
    TicketExhausted,
}

struct Entry {
    tenant: TenantId,
    pinned_spki: [u8; 32],
}

struct Pending {
    request_id: String,
    pinned_spki: [u8; 32],
}

pub struct SyntheticController {
    enrolled: HashMap<String, Entry>,
    pending: HashMap<String, Pending>,
    replayed: HashSet<(String, String)>,
    next_ticket: u64,
    max_pending: usize,
    max_replay: usize,
}

impl Default for SyntheticController {
    fn default() -> Self {
        Self {
            enrolled: HashMap::new(),
            pending: HashMap::new(),
            replayed: HashSet::new(),
            next_ticket: 0,
            max_pending: MAX_PENDING,
            max_replay: MAX_REPLAYED,
        }
    }
}

impl SyntheticController {
    /// Offline-only: future storage must guarantee immutable agent->tenant
    /// mapping, authorized provisioning, unique cert pin and audit.
    pub fn enroll(&mut self, agent: AgentEnrollment) -> Result<(), Error> {
        if self.enrolled.contains_key(&agent.endpoint_id) {
            return Err(Error::DuplicateAgent);
        }
        if self.enrolled.len() >= MAX_ENROLLMENTS {
            return Err(Error::EnrollmentFull);
        }
        if self
            .enrolled
            .values()
            .any(|entry| entry.pinned_spki == agent.client_spki_sha256)
        {
            return Err(Error::ReusedCertificate);
        }
        self.enrolled.insert(
            agent.endpoint_id,
            Entry {
                tenant: agent.tenant,
                pinned_spki: agent.client_spki_sha256,
            },
        );
        Ok(())
    }

    /// A synthetic READ-ONLY plan. This intentionally cannot perform
    /// Set/Add/Delete/Operate and has no real USP/MTP transport.
    pub fn plan_read(
        &mut self,
        operator: &TrustedOperator,
        endpoint_id: &str,
        parameter: &str,
    ) -> Result<SyntheticReadPlan, Error> {
        if !parameter.starts_with("Device.")
            || parameter.len() > MAX_PARAMETER
            || parameter.contains("..")
            || !parameter
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._".contains(&b))
        {
            return Err(Error::InvalidPath);
        }
        let entry = self.enrolled.get(endpoint_id).ok_or(Error::Unenrolled)?;
        if entry.tenant != operator.tenant {
            return Err(Error::WrongTenant);
        }
        if self.pending.contains_key(endpoint_id) {
            return Err(Error::Busy);
        }
        if self.pending.len() >= self.max_pending {
            return Err(Error::PendingFull);
        }
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(Error::TicketExhausted)?;
        let request_id = format!("r{}", self.next_ticket);
        self.pending.insert(
            endpoint_id.to_owned(),
            Pending {
                request_id: request_id.clone(),
                pinned_spki: entry.pinned_spki,
            },
        );
        Ok(SyntheticReadPlan {
            endpoint_id: endpoint_id.to_owned(),
            request_id,
            parameter_path: parameter.to_owned(),
        })
    }

    /// Synthetic correlation after a *future* cryptographically verified
    /// transport event, NOT a function to call on user/broker-supplied data.
    pub fn accept_reply(
        &mut self,
        verified: &VerifiedAgent,
        trusted_tenant: &TenantId,
        frame: SyntheticReply<'_>,
    ) -> Result<Correlation, Error> {
        if !endpoint_ok(frame.claimed_endpoint_id)
            || !message_id_ok(frame.message_id)
            || !message_id_ok(frame.in_reply_to)
            || frame.payload.len() > MAX_REPLY
        {
            return Err(Error::BadReply);
        }
        let entry = self
            .enrolled
            .get(frame.claimed_endpoint_id)
            .ok_or(Error::Unenrolled)?;
        if &entry.tenant != trusted_tenant {
            return Err(Error::WrongTenant);
        }
        if entry.pinned_spki != verified.client_spki_sha256 {
            return Err(Error::WrongPeer);
        }
        let replay = (
            frame.claimed_endpoint_id.to_owned(),
            frame.message_id.to_owned(),
        );
        if self.replayed.contains(&replay) {
            return Err(Error::Replay);
        }
        let pending = self
            .pending
            .get(frame.claimed_endpoint_id)
            .ok_or(Error::UnexpectedReply)?;
        if pending.request_id != frame.in_reply_to
            || pending.pinned_spki != verified.client_spki_sha256
        {
            return Err(Error::UnexpectedReply);
        }
        if self.replayed.len() >= self.max_replay {
            return Err(Error::ReplayFull);
        }
        // No raw payload storage; the future protobuf schema, record
        // integrity and data model validation must be handled elsewhere.
        let bytes = frame.payload.len();
        self.replayed.insert(replay);
        self.pending.remove(frame.claimed_endpoint_id);
        Ok(Correlation {
            payload_bytes: bytes,
            correlated: true,
        })
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(label: &str) -> TenantId {
        TenantId::parse(label).unwrap()
    }

    fn trusted_operator(label: &str) -> TrustedOperator {
        TrustedOperator {
            tenant: tenant(label),
        }
    }

    fn peer(byte: u8) -> VerifiedAgent {
        VerifiedAgent {
            client_spki_sha256: [byte; 32],
        }
    }

    fn fixture() -> SyntheticController {
        let mut c = SyntheticController::default();
        c.enroll(AgentEnrollment::new(tenant("kangnet"), "synthetic-agent-a", [1; 32]).unwrap())
            .unwrap();
        c
    }

    fn reply<'a>(message_id: &'a str, request_id: &'a str) -> SyntheticReply<'a> {
        SyntheticReply {
            claimed_endpoint_id: "synthetic-agent-a",
            message_id,
            in_reply_to: request_id,
            payload: b"synthetic non-protobuf result",
        }
    }

    #[test]
    fn synthetic_tenant_bound_read_and_correlated_reply() {
        let mut c = fixture();
        let plan = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert_eq!(plan.endpoint_id, "synthetic-agent-a");
        assert_eq!(plan.parameter_path, "Device.Info.");
        assert_eq!(c.pending_count(), 1);
        let result = c
            .accept_reply(
                &peer(1),
                &tenant("kangnet"),
                reply("msg-1", &plan.request_id),
            )
            .unwrap();
        assert!(result.correlated);
        assert!(result.payload_bytes > 0);
        assert_eq!(c.pending_count(), 0);
    }

    #[test]
    fn cross_tenant_operator_cannot_plan_or_correlate() {
        let mut c = fixture();
        assert!(matches!(
            c.plan_read(
                &trusted_operator("nengnet"),
                "synthetic-agent-a",
                "Device.Info."
            ),
            Err(Error::WrongTenant)
        ));
        let p = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert!(matches!(
            c.accept_reply(&peer(1), &tenant("nengnet"), reply("msg-1", &p.request_id)),
            Err(Error::WrongTenant)
        ));
        assert_eq!(c.pending_count(), 1);
    }

    #[test]
    fn broker_endpoint_claim_cannot_replace_verified_peer() {
        let mut c = fixture();
        let p = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert!(matches!(
            c.accept_reply(&peer(2), &tenant("kangnet"), reply("msg-1", &p.request_id)),
            Err(Error::WrongPeer)
        ));
        assert_eq!(c.pending_count(), 1);
    }

    #[test]
    fn wrong_correlation_does_not_consume_valid_pending_request() {
        let mut c = fixture();
        let p = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert!(matches!(
            c.accept_reply(&peer(1), &tenant("kangnet"), reply("msg-1", "made-up")),
            Err(Error::UnexpectedReply)
        ));
        assert_eq!(c.pending_count(), 1);
        assert!(c
            .accept_reply(&peer(1), &tenant("kangnet"), reply("msg-2", &p.request_id))
            .is_ok());
    }

    #[test]
    fn same_agent_message_id_replay_is_rejected_across_reads() {
        let mut c = fixture();
        let first = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        c.accept_reply(
            &peer(1),
            &tenant("kangnet"),
            reply("msg-1", &first.request_id),
        )
        .unwrap();
        let next = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert_eq!(
            c.accept_reply(
                &peer(1),
                &tenant("kangnet"),
                reply("msg-1", &next.request_id)
            )
            .err(),
            Some(Error::Replay)
        );
    }

    #[test]
    fn duplicate_agent_and_shared_pinned_identity_are_rejected() {
        let mut c = fixture();
        assert_eq!(
            c.enroll(
                AgentEnrollment::new(tenant("nengnet"), "synthetic-agent-a", [2; 32]).unwrap()
            ),
            Err(Error::DuplicateAgent)
        );
        assert_eq!(
            c.enroll(
                AgentEnrollment::new(tenant("nengnet"), "synthetic-agent-b", [1; 32]).unwrap()
            ),
            Err(Error::ReusedCertificate)
        );
    }

    #[test]
    fn invalid_parameter_paths_prevent_any_pending_request() {
        let mut c = fixture();
        for path in [
            "Device..Info",
            "Other.Info",
            "Device.A;Set",
            "Device.A/Other",
            "",
        ] {
            assert_eq!(
                c.plan_read(&trusted_operator("kangnet"), "synthetic-agent-a", path)
                    .err(),
                Some(Error::InvalidPath)
            );
        }
        assert_eq!(c.pending_count(), 0);
    }

    #[test]
    fn malformed_or_oversized_reply_is_rejected_without_consuming_pending() {
        let mut c = fixture();
        let p = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        let too_large = vec![b'X'; MAX_REPLY + 1];
        assert_eq!(
            c.accept_reply(
                &peer(1),
                &tenant("kangnet"),
                SyntheticReply {
                    claimed_endpoint_id: "synthetic-agent-a",
                    message_id: "ok",
                    in_reply_to: &p.request_id,
                    payload: &too_large,
                }
            )
            .err(),
            Some(Error::BadReply)
        );
        assert_eq!(c.pending_count(), 1);
    }

    #[test]
    fn busy_and_pending_limits_fail_closed() {
        let mut c = fixture();
        c.max_pending = 1;
        c.enroll(AgentEnrollment::new(tenant("nengnet"), "synthetic-agent-b", [2; 32]).unwrap())
            .unwrap();
        let _ = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert_eq!(
            c.plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info."
            )
            .err(),
            Some(Error::Busy)
        );
        assert_eq!(
            c.plan_read(
                &trusted_operator("nengnet"),
                "synthetic-agent-b",
                "Device.Info."
            )
            .err(),
            Some(Error::PendingFull)
        );
    }

    #[test]
    fn replay_capacity_fails_closed_no_silent_eviction() {
        let mut c = fixture();
        c.max_replay = 1;
        let p = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        c.accept_reply(&peer(1), &tenant("kangnet"), reply("msg-1", &p.request_id))
            .unwrap();
        let q = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        assert_eq!(
            c.accept_reply(&peer(1), &tenant("kangnet"), reply("msg-2", &q.request_id))
                .err(),
            Some(Error::ReplayFull)
        );
        assert_eq!(c.pending_count(), 1);
    }

    #[test]
    fn unknown_agent_and_untrusted_endpoint_rejected() {
        let mut c = fixture();
        assert_eq!(
            c.plan_read(
                &trusted_operator("kangnet"),
                "unregistered-agent",
                "Device.Info."
            )
            .err(),
            Some(Error::Unenrolled)
        );
        let p = c
            .plan_read(
                &trusted_operator("kangnet"),
                "synthetic-agent-a",
                "Device.Info.",
            )
            .unwrap();
        let mut forged = reply("msg-1", &p.request_id);
        forged.claimed_endpoint_id = "unregistered-agent";
        assert_eq!(
            c.accept_reply(&peer(1), &tenant("kangnet"), forged).err(),
            Some(Error::Unenrolled)
        );
    }

    #[test]
    fn all_zero_peer_or_control_char_endpoint_is_invalid() {
        assert!(matches!(
            AgentEnrollment::new(tenant("kangnet"), "agent:bad\n", [1; 32]),
            Err(Error::InvalidEnrollment)
        ));
        assert!(matches!(
            AgentEnrollment::new(tenant("kangnet"), "agent-x", [0; 32]),
            Err(Error::InvalidEnrollment)
        ));
    }
}

#[cfg(test)]
mod r81_offline_virtual_agent {
    use super::*;
    use crate::wire14::{encode_offline_get, inspect_no_session_get_response, WireError};
    const CORRELATED: &[u8] = include_bytes!("../tests/fixtures/usp14_get_response_correlated.bin");

    #[test]
    fn actual_protobuf_wire_to_virtual_controller_domain_denies_cross_tenant_and_replay() {
        // Test-only mock verification: NOT cryptographic mTLS, MQTT or
        // proof that an untrusted protobuf from_id really owns a certificate.
        let mut controller = SyntheticController::default();
        let a = TenantId::parse("tenant-alpha").unwrap();
        let b = TenantId::parse("tenant-beta").unwrap();
        controller
            .enroll(AgentEnrollment::new(a.clone(), "usp::sim-agent-a", [0xa1; 32]).unwrap())
            .unwrap();
        controller
            .enroll(AgentEnrollment::new(b.clone(), "usp::sim-agent-b", [0xb2; 32]).unwrap())
            .unwrap();

        let operator_a = TrustedOperator { tenant: a.clone() };
        assert_eq!(
            controller
                .plan_read(&operator_a, "usp::sim-agent-b", "Device.DeviceInfo.")
                .err(),
            Some(Error::WrongTenant)
        );
        let plan = controller
            .plan_read(&operator_a, "usp::sim-agent-a", "Device.DeviceInfo.")
            .unwrap();
        assert_eq!(plan.request_id, "r1");
        let outbound = encode_offline_get(
            "usp::offline-controller",
            &plan.endpoint_id,
            &plan.request_id,
            &[&plan.parameter_path],
        )
        .unwrap();
        assert!(!outbound.is_empty());
        assert_eq!(
            inspect_no_session_get_response(&outbound).err(),
            Some(WireError::UnsupportedMessage)
        );

        // Correlated GetResp is a separately hand-encoded, real USP 1.4
        // protobuf fixture, not a fake JSON or opaque arbitrary byte reply.
        let decoded = inspect_no_session_get_response(CORRELATED).unwrap();
        assert_eq!(decoded.message_id, plan.request_id);
        assert_eq!(decoded.claimed_from, "usp::sim-agent-a");
        assert_eq!(decoded.claimed_to, "usp::offline-controller");
        assert_eq!(decoded.parameter_values, 1);
        let frame = SyntheticReply {
            claimed_endpoint_id: &decoded.claimed_from,
            message_id: &decoded.message_id,
            in_reply_to: &plan.request_id,
            payload: CORRELATED,
        };
        let wrong_peer = VerifiedAgent {
            client_spki_sha256: [0xc3; 32],
        };
        let verified_mock = VerifiedAgent {
            client_spki_sha256: [0xa1; 32],
        };
        assert_eq!(
            controller.accept_reply(&wrong_peer, &a, frame).err(),
            Some(Error::WrongPeer)
        );
        assert_eq!(controller.pending_count(), 1);
        let frame = SyntheticReply {
            claimed_endpoint_id: &decoded.claimed_from,
            message_id: &decoded.message_id,
            in_reply_to: &plan.request_id,
            payload: CORRELATED,
        };
        assert_eq!(
            controller.accept_reply(&verified_mock, &b, frame).err(),
            Some(Error::WrongTenant)
        );
        let frame = SyntheticReply {
            claimed_endpoint_id: &decoded.claimed_from,
            message_id: &decoded.message_id,
            in_reply_to: &plan.request_id,
            payload: CORRELATED,
        };
        let accepted = controller.accept_reply(&verified_mock, &a, frame).unwrap();
        assert!(accepted.correlated);
        assert_eq!(controller.pending_count(), 0);
        let second = controller
            .plan_read(&operator_a, "usp::sim-agent-a", "Device.DeviceInfo.")
            .unwrap();
        let old = SyntheticReply {
            claimed_endpoint_id: &decoded.claimed_from,
            message_id: &decoded.message_id,
            in_reply_to: &second.request_id,
            payload: CORRELATED,
        };
        assert_eq!(
            controller.accept_reply(&verified_mock, &a, old).err(),
            Some(Error::Replay)
        );
        assert_eq!(controller.pending_count(), 1);
    }
}
