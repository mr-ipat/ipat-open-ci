//! In-memory lab-only CWMP session transition for one fixed READ RPC.
//! Trusted admission remains sealed; these methods cannot create a peer.
use super::{AdmissionRegistry, AuthenticatedPeer, Error, Lease, ReadStage};
use cwmp_protocol::rpc::{parse_read_reply, read_request, RpcReply, LAB_PARAMETER};

/// Only a genuinely empty CPE POST may advance the lab state machine.
/// Transport must supply actual received body and parsed HTTP headers.
pub struct ValidEmptyPost;
impl ValidEmptyPost {
    pub fn validate(
        body: &[u8],
        soap_action: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<Self, Error> {
        if !body.is_empty() || soap_action.is_some() || content_type.is_some() {
            return Err(Error::InvalidEmptyPost);
        }
        Ok(Self)
    }
}
/// Already-serialized, read-only SOAP request emitted for one trusted lease.
pub struct OutboundRead {
    pub xml: String,
}
/// Deliberately excludes raw CPE values, identifiers and unreviewed tenant claims.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadEvidence {
    pub returned_parameter_count: usize,
    pub fault_code: Option<u16>,
    pub operator_reviewed: bool,
    pub physical_device_verified: bool,
    pub tenant_approved_for_live_provisioning: bool,
}
impl AdmissionRegistry {
    /// Can only start once after admission, same peer + internal lease +
    /// fully validated empty POST; unauthorized callers cannot forge peers.
    pub fn issue_one_read(
        &mut self,
        peer: &AuthenticatedPeer,
        lease: &Lease,
        _post: ValidEmptyPost,
    ) -> Result<OutboundRead, Error> {
        let active = self
            .active
            .get_mut(&lease.device)
            .ok_or(Error::InvalidLease)?;
        if active.ticket != lease.ticket || active.spki != peer.client_spki_sha256 {
            return Err(Error::InvalidLease);
        }
        if !matches!(active.read_stage, ReadStage::InformOnly) {
            return Err(Error::InvalidReadState);
        }
        let id = format!("ipat-lab-read-{}", active.ticket);
        let xml = read_request(&id, LAB_PARAMETER).map_err(|_| Error::InvalidReadState)?;
        active.read_stage = ReadStage::Awaiting { id };
        Ok(OutboundRead { xml })
    }
    /// Response/fault is consumed only if issued on the same lease and peer.
    /// A malformed/replayed/unrelated payload never advances the state.
    pub fn accept_one_read(
        &mut self,
        peer: &AuthenticatedPeer,
        lease: &Lease,
        body: &str,
    ) -> Result<ReadEvidence, Error> {
        let active = self
            .active
            .get_mut(&lease.device)
            .ok_or(Error::InvalidLease)?;
        if active.ticket != lease.ticket || active.spki != peer.client_spki_sha256 {
            return Err(Error::InvalidLease);
        }
        let ReadStage::Awaiting { id } = &active.read_stage else {
            return Err(Error::InvalidReadState);
        };
        let reply = parse_read_reply(body, id, LAB_PARAMETER).map_err(|_| Error::InvalidRpc)?;
        let evidence = match reply {
            RpcReply::Values(values) => ReadEvidence {
                returned_parameter_count: values.count(),
                fault_code: None,
                operator_reviewed: false,
                physical_device_verified: false,
                tenant_approved_for_live_provisioning: false,
            },
            RpcReply::Fault(fault) => ReadEvidence {
                returned_parameter_count: 0,
                fault_code: Some(fault.code),
                operator_reviewed: false,
                physical_device_verified: false,
                tenant_approved_for_live_provisioning: false,
            },
        };
        active.read_stage = ReadStage::Completed;
        Ok(evidence)
    }
    /// Explicitly abandon a malformed/timed-out lab session, without erasing
    /// the replay ID. This is not durable crash/retry management.
    pub fn abort_session(&mut self, peer: &AuthenticatedPeer, lease: &Lease) -> Result<(), Error> {
        let active = self.active.get(&lease.device).ok_or(Error::InvalidLease)?;
        if active.ticket != lease.ticket || active.spki != peer.client_spki_sha256 {
            return Err(Error::InvalidLease);
        }
        self.active.remove(&lease.device);
        Ok(())
    }
}
