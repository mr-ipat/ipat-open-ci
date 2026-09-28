//! Offline CWMP admission/session simulator. NOT an authenticated HTTPS listener.
//!
//! Important design boundary: AuthenticatedPeer deliberately has NO public
//! constructor. Only a future, independently tested TLS mTLS adapter may mint
//! it from cryptographically verified CPE client identity. A test-only peer
//! constructor exists inside this crate, not in the production API.
//! This module uses bounded IN-MEMORY replay/session state: NOT resilient to
//! restarts or suitable for production ACS retry/idempotency guarantees.

pub mod read;
#[cfg(test)]
mod read_tests;

use cwmp_protocol::{inform_response, parse_inform};
use std::collections::{HashMap, HashSet};
use tenant_core::TenantId;

const MAX_ENROLLMENTS: usize = 256;
const MAX_ACTIVE: usize = 64;
const MAX_REPLAY: usize = 1024;
const MAX_IDENTIFIER: usize = 128;

#[derive(Clone, PartialEq, Eq, Hash)]
struct DeviceKey {
    oui: String,
    product_class: String,
    serial_number: String,
}

impl DeviceKey {
    fn checked(oui: &str, product_class: &str, serial_number: &str) -> Result<Self, Error> {
        if oui.len() != 6 || !oui.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidEnrollment);
        }
        if product_class.len() > MAX_IDENTIFIER
            || serial_number.is_empty()
            || serial_number.len() > MAX_IDENTIFIER
            || [product_class, serial_number]
                .iter()
                .any(|s| s.chars().any(|ch| ch.is_control()))
        {
            return Err(Error::InvalidEnrollment);
        }
        Ok(Self {
            oui: oui.to_ascii_uppercase(),
            product_class: product_class.to_owned(),
            serial_number: serial_number.to_owned(),
        })
    }
}

/// A trusted registration is obtained from the operator's audited enrollment
/// database, not from a CWMP XML claim or HTTP tenant/Host headers.
pub struct Enrollment {
    pub tenant: TenantId,
    oui: String,
    product_class: String,
    serial_number: String,
    /// Pinned client SPKI SHA-256 from real TLS verification in the future.
    client_spki_sha256: [u8; 32],
}

impl Enrollment {
    pub fn new(
        tenant: TenantId,
        oui: &str,
        product_class: &str,
        serial_number: &str,
        client_spki_sha256: [u8; 32],
    ) -> Result<Self, Error> {
        let key = DeviceKey::checked(oui, product_class, serial_number)?;
        if client_spki_sha256 == [0u8; 32] {
            return Err(Error::InvalidEnrollment);
        }
        Ok(Self {
            tenant,
            oui: key.oui,
            product_class: key.product_class,
            serial_number: key.serial_number,
            client_spki_sha256,
        })
    }

    fn key(&self) -> DeviceKey {
        DeviceKey {
            oui: self.oui.clone(),
            product_class: self.product_class.clone(),
            serial_number: self.serial_number.clone(),
        }
    }
}

/// *Not constructible by public callers.* A future TLS edge must validate
/// client certificate chain, trust anchor, expiry, mTLS purpose and revocation
/// before minting proof. Simulator-only synthetic proofs live in unit tests.
pub struct AuthenticatedPeer {
    client_spki_sha256: [u8; 32],
}

enum ReadStage {
    InformOnly,
    Awaiting { id: String },
    Completed,
}

struct Active {
    ticket: u64,
    spki: [u8; 32],
    read_stage: ReadStage,
}

/// Server-internal ephemeral session capability; not an HTTP bearer token.
pub struct Lease {
    device: DeviceKey,
    ticket: u64,
}

pub struct Admission {
    pub response_xml: String,
    pub event_count: usize,
    pub lease: Lease,
}

/// Fine-grained errors are INTERNAL ONLY. A future public adapter must map
/// all identity/tenant/cert failures to an indistinguishable reject response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidEnrollment,
    EnrollmentFull,
    DuplicateDevice,
    ReusedCertificate,
    InvalidInform,
    MissingCorrelation,
    Unenrolled,
    WrongTenant,
    WrongTransportIdentity,
    Busy,
    Replay,
    SessionFull,
    ReplayTableFull,
    TicketExhausted,
    InvalidLease,
    InvalidEmptyPost,
    InvalidReadState,
    InvalidRpc,
}

pub struct AdmissionRegistry {
    devices: HashMap<DeviceKey, (TenantId, [u8; 32])>,
    active: HashMap<DeviceKey, Active>,
    replayed: HashSet<(DeviceKey, String)>,
    next_ticket: u64,
    active_limit: usize,
    replay_limit: usize,
}

impl Default for AdmissionRegistry {
    fn default() -> Self {
        Self {
            devices: HashMap::new(),
            active: HashMap::new(),
            replayed: HashSet::new(),
            next_ticket: 0,
            active_limit: MAX_ACTIVE,
            replay_limit: MAX_REPLAY,
        }
    }
}

impl AdmissionRegistry {
    /// Safe only when invoked by a separately authorized operator enrollment
    /// workflow, which is NOT implemented by this synthetic-lab crate.
    pub fn register(&mut self, enrollment: Enrollment) -> Result<(), Error> {
        let key = enrollment.key();
        if self.devices.contains_key(&key) {
            return Err(Error::DuplicateDevice);
        }
        if self.devices.len() >= MAX_ENROLLMENTS {
            return Err(Error::EnrollmentFull);
        }
        if self
            .devices
            .values()
            .any(|(_, fingerprint)| *fingerprint == enrollment.client_spki_sha256)
        {
            return Err(Error::ReusedCertificate);
        }
        self.devices
            .insert(key, (enrollment.tenant, enrollment.client_spki_sha256));
        Ok(())
    }

    /// Offline-only admission. This method is unreachable from a public
    /// transport because AuthenticatedPeer has no production constructor.
    pub fn begin(
        &mut self,
        peer: &AuthenticatedPeer,
        trusted_tenant: &TenantId,
        untrusted_xml: &str,
    ) -> Result<Admission, Error> {
        let inform = parse_inform(untrusted_xml).map_err(|_| Error::InvalidInform)?;
        let key = DeviceKey::checked(&inform.oui, &inform.product_class, &inform.serial_number)
            .map_err(|_| Error::InvalidInform)?;
        let id = inform.cwmp_id.as_ref().ok_or(Error::MissingCorrelation)?;
        let (actual_tenant, pinned_spki) = self.devices.get(&key).ok_or(Error::Unenrolled)?;
        if actual_tenant != trusted_tenant {
            return Err(Error::WrongTenant);
        }
        if *pinned_spki != peer.client_spki_sha256 {
            return Err(Error::WrongTransportIdentity);
        }
        if self.active.contains_key(&key) {
            return Err(Error::Busy);
        }
        if self.replayed.contains(&(key.clone(), id.clone())) {
            return Err(Error::Replay);
        }
        if self.active.len() >= self.active_limit {
            return Err(Error::SessionFull);
        }
        if self.replayed.len() >= self.replay_limit {
            // Fail closed rather than silently evict replay data.
            return Err(Error::ReplayTableFull);
        }
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(Error::TicketExhausted)?;
        let ticket = self.next_ticket;
        let response_xml = inform_response(&inform);
        let event_count = inform.event_codes.len();
        self.replayed.insert((key.clone(), id.to_owned()));
        self.active.insert(
            key.clone(),
            Active {
                ticket,
                spki: peer.client_spki_sha256,
                read_stage: ReadStage::InformOnly,
            },
        );
        Ok(Admission {
            response_xml,
            event_count,
            lease: Lease {
                device: key,
                ticket,
            },
        })
    }

    /// Only a matching authenticated peer/session can close a lease.
    /// A future session transport must add network timeout/fault semantics.
    pub fn finish(&mut self, peer: &AuthenticatedPeer, lease: Lease) -> Result<(), Error> {
        let active = self.active.get(&lease.device).ok_or(Error::InvalidLease)?;
        if active.ticket != lease.ticket || active.spki != peer.client_spki_sha256 {
            return Err(Error::InvalidLease);
        }
        if matches!(active.read_stage, ReadStage::Awaiting { .. }) {
            return Err(Error::InvalidReadState);
        }
        self.active.remove(&lease.device);
        Ok(())
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<soap:Header><cwmp:ID soap:mustUnderstand="1">corr-1</cwmp:ID></soap:Header>
<soap:Body><cwmp:Inform>
<DeviceId><Manufacturer>Synthetic Lab</Manufacturer><OUI>001122</OUI>
<ProductClass>LAB-ONT</ProductClass><SerialNumber>SN-TEST</SerialNumber></DeviceId>
<Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode><CommandKey/></EventStruct></Event>
<MaxEnvelopes>1</MaxEnvelopes><CurrentTime>2026-09-25T10:00:00Z</CurrentTime>
<RetryCount>0</RetryCount><ParameterList/>
</cwmp:Inform></soap:Body></soap:Envelope>"#;

    fn tenant(name: &str) -> TenantId {
        TenantId::parse(name).unwrap()
    }

    fn peer(key: u8) -> AuthenticatedPeer {
        AuthenticatedPeer {
            client_spki_sha256: [key; 32],
        }
    }

    fn enrolled() -> AdmissionRegistry {
        let mut reg = AdmissionRegistry::default();
        reg.register(
            Enrollment::new(tenant("kangnet"), "001122", "LAB-ONT", "SN-TEST", [1; 32]).unwrap(),
        )
        .unwrap();
        reg
    }

    #[test]
    fn enrolled_device_has_inform_response_only_after_trusted_peer_and_tenant() {
        let mut r = enrolled();
        let accepted = r.begin(&peer(1), &tenant("kangnet"), VALID).unwrap();
        assert!(accepted.response_xml.contains("InformResponse"));
        assert!(accepted.response_xml.contains("corr-1"));
        assert_eq!(accepted.event_count, 1);
        assert_eq!(r.active_count(), 1);
        r.finish(&peer(1), accepted.lease).unwrap();
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn forged_xml_identity_cannot_cross_tenant() {
        let mut r = enrolled();
        assert_eq!(
            r.begin(&peer(1), &tenant("nengnet"), VALID).err(),
            Some(Error::WrongTenant)
        );
        assert_eq!(r.active_count(), 0);
        assert_eq!(
            r.begin(&peer(2), &tenant("kangnet"), VALID).err(),
            Some(Error::WrongTransportIdentity)
        );
        let forged = VALID.replace("SN-TEST", "ANOTHER-SERIAL");
        assert_eq!(
            r.begin(&peer(1), &tenant("kangnet"), &forged).err(),
            Some(Error::Unenrolled)
        );
    }

    #[test]
    fn duplicate_and_reused_cert_enrollments_rejected() {
        let mut r = enrolled();
        assert_eq!(
            r.register(
                Enrollment::new(tenant("nengnet"), "001122", "LAB-ONT", "SN-TEST", [2; 32])
                    .unwrap()
            ),
            Err(Error::DuplicateDevice)
        );
        assert_eq!(
            r.register(
                Enrollment::new(tenant("nengnet"), "001122", "LAB-ONT", "SN-OTHER", [1; 32])
                    .unwrap()
            ),
            Err(Error::ReusedCertificate)
        );
        assert_eq!(
            Enrollment::new(tenant("kangnet"), "001122", "", "SN-TEST", [0; 32]).err(),
            Some(Error::InvalidEnrollment)
        );
    }

    #[test]
    fn duplicate_correlation_rejected_after_session_closes() {
        let mut r = enrolled();
        let lease = r.begin(&peer(1), &tenant("kangnet"), VALID).unwrap().lease;
        r.finish(&peer(1), lease).unwrap();
        assert_eq!(
            r.begin(&peer(1), &tenant("kangnet"), VALID).err(),
            Some(Error::Replay)
        );
    }

    #[test]
    fn concurrent_same_device_is_busy_even_with_new_id() {
        let mut r = enrolled();
        let first = r.begin(&peer(1), &tenant("kangnet"), VALID).unwrap();
        let another = VALID.replace("corr-1", "corr-2");
        assert_eq!(
            r.begin(&peer(1), &tenant("kangnet"), &another).err(),
            Some(Error::Busy)
        );
        r.finish(&peer(1), first.lease).unwrap();
        assert!(r.begin(&peer(1), &tenant("kangnet"), &another).is_ok());
    }

    #[test]
    fn unknown_or_unsafe_soap_cannot_create_session() {
        let mut r = enrolled();
        let unsafe_xml = VALID.replace("<?xml version=\"1.0\"?>", "<!DOCTYPE bad>[]");
        assert_eq!(
            r.begin(&peer(1), &tenant("kangnet"), &unsafe_xml).err(),
            Some(Error::InvalidInform)
        );
        assert_eq!(r.active_count(), 0);
        let absent = VALID.replace(
            "<soap:Header><cwmp:ID soap:mustUnderstand=\"1\">corr-1</cwmp:ID></soap:Header>",
            "",
        );
        assert_eq!(
            r.begin(&peer(1), &tenant("kangnet"), &absent).err(),
            Some(Error::MissingCorrelation)
        );
    }

    #[test]
    fn strict_replay_capacity_fails_closed_not_evicted() {
        let mut r = enrolled();
        r.replay_limit = 1;
        let first = r.begin(&peer(1), &tenant("kangnet"), VALID).unwrap();
        r.finish(&peer(1), first.lease).unwrap();
        let new = VALID.replace("corr-1", "corr-2");
        assert_eq!(
            r.begin(&peer(1), &tenant("kangnet"), &new).err(),
            Some(Error::ReplayTableFull)
        );
    }

    #[test]
    fn independent_devices_respect_global_session_limit() {
        let mut r = enrolled();
        r.active_limit = 1;
        r.register(
            Enrollment::new(tenant("nengnet"), "001122", "LAB-ONT", "SN-OTHER", [2; 32]).unwrap(),
        )
        .unwrap();
        let first = r.begin(&peer(1), &tenant("kangnet"), VALID).unwrap();
        let second = VALID
            .replace("SN-TEST", "SN-OTHER")
            .replace("corr-1", "corr-2");
        assert_eq!(
            r.begin(&peer(2), &tenant("nengnet"), &second).err(),
            Some(Error::SessionFull)
        );
        r.finish(&peer(1), first.lease).unwrap();
        assert!(r.begin(&peer(2), &tenant("nengnet"), &second).is_ok());
    }

    #[test]
    fn wrong_peer_cannot_finish_existing_session() {
        let mut r = enrolled();
        let admission = r.begin(&peer(1), &tenant("kangnet"), VALID).unwrap();
        assert_eq!(
            r.finish(&peer(2), admission.lease),
            Err(Error::InvalidLease)
        );
        assert_eq!(r.active_count(), 1);
    }

    #[test]
    fn xml_id_is_escaped_without_becoming_identity() {
        let mut r = enrolled();
        let xml = VALID.replace("corr-1", "corr&amp;&lt;admin&gt;");
        let admission = r.begin(&peer(1), &tenant("kangnet"), &xml).unwrap();
        assert!(admission.response_xml.contains("corr&amp;&lt;admin&gt;"));
        assert!(!admission.response_xml.contains("corr&<admin>"));
    }

    #[test]
    fn fingerprint_zero_and_oversize_identity_rejected() {
        assert_eq!(
            Enrollment::new(tenant("kangnet"), "001122", "LAB-ONT", "SN-TEST", [0; 32]).err(),
            Some(Error::InvalidEnrollment)
        );
        assert_eq!(
            Enrollment::new(tenant("kangnet"), "BAD OUI", "LAB-ONT", "SN-TEST", [1; 32]).err(),
            Some(Error::InvalidEnrollment)
        );
        assert_eq!(
            Enrollment::new(
                tenant("kangnet"),
                "001122",
                "LAB-ONT",
                &"S".repeat(MAX_IDENTIFIER + 1),
                [1; 32]
            )
            .err(),
            Some(Error::InvalidEnrollment)
        );
    }
}
