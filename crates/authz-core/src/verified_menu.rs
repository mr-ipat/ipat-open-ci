//! Lab-only pure verifier-to-dashboard policy bridge.
//!
//! VerifiedSubject requires a cryptographically verified pinned-issuer JWT.
//! CandidateMembershipRow is NOT proof of approved DB provenance:
//! an operator-authenticated restricted lookup, policy, audit and MFA
//! enforcement must be implemented before any real user endpoint calls this.
//! No Host/cookie/header/domain fallback. No platform-owner bridge.
use crate::dashboard::{
    visible_sections, DashboardResource, DashboardRole, DashboardSection, DashboardSubject,
};
use identity_core::VerifiedSubject;
use tenant_core::TenantId;

/// Typed candidate row, not a trusted membership constructor.
/// Future callers must obtain the exact role/POP row from a trusted,
/// audited PostgreSQL lookup rather than user request/JWT claims.
pub struct CandidateMembershipRow<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub tenant: &'a TenantId,
    pub role: DashboardRole,
    pub approved_by: &'a str,
    pub authorized_pops: &'a [&'a str],
    pub expires_at: u64,
    pub revoked: bool,
}

/// Fail-closed single-role synthetic reference: never call with records
/// originating from browser input, untrusted claims or tenant DNS.
/// Returns zero sections on any mismatch, expiration or revocation.
pub fn visible_for_verified_candidate(
    verified: &VerifiedSubject,
    requested_tenant: &TenantId,
    requested_pop: Option<&str>,
    record: &CandidateMembershipRow<'_>,
    now: u64,
) -> Vec<DashboardSection> {
    if verified.issuer() != record.issuer
        || verified.subject() != record.subject
        || record.tenant != requested_tenant
        || now >= record.expires_at
        || now >= verified.expires_at()
        || record.revoked
        || record.approved_by.trim().is_empty()
        || record.issuer.is_empty()
        || record.subject.is_empty()
    {
        return Vec::new();
    }
    // Never manufacture platform owner privileges from a tenant row.
    // Current roles are read-only; bulk and firmware are always denied.
    visible_sections(
        &DashboardSubject::Tenant {
            tenant: record.tenant,
            roles: &[record.role],
            authorized_pops: record.authorized_pops,
        },
        DashboardResource::Tenant {
            tenant: requested_tenant,
            pop: requested_pop,
        },
    )
}
