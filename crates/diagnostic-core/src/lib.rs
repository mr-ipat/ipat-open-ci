//! Synthetic, read-only, tenant-scoped diagnostic hypotheses — no device
//! access or remediation. Callers MUST verify the input scope and topology
//! against authenticated tenant membership before invoking this module.
//! Hypotheses are NOT proof, fault localization or calibrated probabilities.
use std::collections::BTreeSet;
use tenant_core::TenantId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    DistributionUplinkDown,
    DistributionUplinkHealthy,
    SubscriberUnreachable,
    OntOpticalLos,
    NeighborOntHealthy,
    OntOpticalNormal,
    PppoeAuthenticationRejected,
    CwmpInformMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub tenant_id: TenantId,
    pub pop_id: String,
    pub distribution_id: String,
    pub subscriber_id: Option<String>,
    pub signal: Signal,
    pub source_id: String,
    pub observed_at_epoch: u64,
}

/// The topology_verified flag is a CLAIM by the caller, not authenticated by
/// this crate. Do NOT set it from a raw client-supplied header or device event.
pub struct Scope {
    pub tenant_id: TenantId,
    pub pop_id: String,
    pub distribution_id: String,
    pub topology_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hypothesis {
    DistributionPath,
    OntAccess,
    PppoeAuthentication,
    InsufficientEvidence,
    ConflictingEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub hypothesis: Hypothesis,
    pub affected_subscribers: Vec<String>,
    pub evidence: Vec<Observation>,
    pub discarded_stale: usize,
    pub requires_operator_review: bool,
    pub remediation_permitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticError {
    EmptyOrUnboundedScope,
    UnboundedInput,
    CrossTenantOrWrongScope,
    InvalidObservation,
    FutureObservation,
    InvalidFreshnessWindow,
}

fn safe_label(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fail closed on tenant/path inconsistencies. Observations are intentionally
/// caller-provided synthetic normalized events; no inference from missing
/// CWMP Inform alone or unchecked live topology.
pub fn diagnose(
    scope: &Scope,
    observations: &[Observation],
    now_epoch: u64,
    max_age_seconds: u64,
) -> Result<Diagnostic, DiagnosticError> {
    if !safe_label(&scope.pop_id) || !safe_label(&scope.distribution_id) {
        return Err(DiagnosticError::EmptyOrUnboundedScope);
    }
    if max_age_seconds == 0 || max_age_seconds > 3600 {
        return Err(DiagnosticError::InvalidFreshnessWindow);
    }
    if observations.len() > 1024 {
        return Err(DiagnosticError::UnboundedInput);
    }
    let mut fresh = Vec::new();
    let mut stale = 0;
    for o in observations {
        if o.tenant_id != scope.tenant_id
            || o.pop_id != scope.pop_id
            || o.distribution_id != scope.distribution_id
        {
            return Err(DiagnosticError::CrossTenantOrWrongScope);
        }
        if !safe_label(&o.source_id) || o.subscriber_id.as_deref().is_some_and(|s| !safe_label(s)) {
            return Err(DiagnosticError::InvalidObservation);
        }
        let requires_subscriber = matches!(
            o.signal,
            Signal::SubscriberUnreachable
                | Signal::OntOpticalLos
                | Signal::OntOpticalNormal
                | Signal::PppoeAuthenticationRejected
        );
        if requires_subscriber && o.subscriber_id.is_none() {
            return Err(DiagnosticError::InvalidObservation);
        }
        if o.observed_at_epoch > now_epoch {
            return Err(DiagnosticError::FutureObservation);
        }
        if now_epoch - o.observed_at_epoch > max_age_seconds {
            stale += 1;
        } else {
            fresh.push(o.clone());
        }
    }
    let uplink_down = fresh
        .iter()
        .any(|o| o.signal == Signal::DistributionUplinkDown);
    let uplink_healthy = fresh
        .iter()
        .any(|o| o.signal == Signal::DistributionUplinkHealthy);
    let reachable_lost: BTreeSet<String> = fresh
        .iter()
        .filter(|o| o.signal == Signal::SubscriberUnreachable)
        .filter_map(|o| o.subscriber_id.clone())
        .collect();
    let optical_los: BTreeSet<String> = fresh
        .iter()
        .filter(|o| o.signal == Signal::OntOpticalLos)
        .filter_map(|o| o.subscriber_id.clone())
        .collect();
    let optical_normal: BTreeSet<String> = fresh
        .iter()
        .filter(|o| o.signal == Signal::OntOpticalNormal)
        .filter_map(|o| o.subscriber_id.clone())
        .collect();
    let pppoe_failure: BTreeSet<String> = fresh
        .iter()
        .filter(|o| o.signal == Signal::PppoeAuthenticationRejected)
        .filter_map(|o| o.subscriber_id.clone())
        .collect();
    let neighbor_healthy = fresh.iter().any(|o| o.signal == Signal::NeighborOntHealthy);
    let optical_conflict = optical_los.intersection(&optical_normal).next().is_some();

    let distribution = scope.topology_verified && uplink_down && reachable_lost.len() >= 2;
    let ont_access =
        uplink_healthy && neighbor_healthy && optical_los.len() == 1 && !optical_conflict;
    let pppoe: BTreeSet<String> = if uplink_healthy && !optical_conflict {
        pppoe_failure
            .intersection(&optical_normal)
            .filter(|id| !optical_los.contains(*id))
            .cloned()
            .collect()
    } else {
        BTreeSet::new()
    };
    let candidates = u8::from(distribution) + u8::from(ont_access) + u8::from(!pppoe.is_empty());
    let hypothesis = if optical_conflict || (uplink_down && uplink_healthy) || candidates > 1 {
        Hypothesis::ConflictingEvidence
    } else if distribution {
        Hypothesis::DistributionPath
    } else if ont_access {
        Hypothesis::OntAccess
    } else if !pppoe.is_empty() {
        Hypothesis::PppoeAuthentication
    } else {
        Hypothesis::InsufficientEvidence
    };
    let affected_subscribers = match hypothesis {
        Hypothesis::DistributionPath => reachable_lost.into_iter().collect(),
        Hypothesis::OntAccess => optical_los.into_iter().collect(),
        Hypothesis::PppoeAuthentication => pppoe.into_iter().collect(),
        _ => vec![],
    };
    Ok(Diagnostic {
        hypothesis,
        affected_subscribers,
        evidence: fresh,
        discarded_stale: stale,
        requires_operator_review: true,
        remediation_permitted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1000;
    fn tenant(s: &str) -> TenantId {
        TenantId::parse(s).unwrap()
    }
    fn scope() -> Scope {
        Scope {
            tenant_id: tenant("kangnet"),
            pop_id: "pop-a".into(),
            distribution_id: "dist-a".into(),
            topology_verified: true,
        }
    }
    fn observation(signal: Signal, subscriber: Option<&str>) -> Observation {
        Observation {
            tenant_id: tenant("kangnet"),
            pop_id: "pop-a".into(),
            distribution_id: "dist-a".into(),
            subscriber_id: subscriber.map(str::to_owned),
            signal,
            source_id: "simulator".into(),
            observed_at_epoch: NOW,
        }
    }
    fn run(input: Vec<Observation>) -> Diagnostic {
        diagnose(&scope(), &input, NOW, 120).unwrap()
    }

    #[test]
    fn multi_subscriber_uplink_failure_is_distribution_hypothesis() {
        let outcome = run(vec![
            observation(Signal::DistributionUplinkDown, None),
            observation(Signal::SubscriberUnreachable, Some("sub-a")),
            observation(Signal::SubscriberUnreachable, Some("sub-b")),
        ]);
        assert_eq!(outcome.hypothesis, Hypothesis::DistributionPath);
        assert_eq!(outcome.affected_subscribers, ["sub-a", "sub-b"]);
        assert!(!outcome.remediation_permitted);
        assert!(outcome.requires_operator_review);
        assert_eq!(outcome.evidence.len(), 3);
    }

    #[test]
    fn absent_verified_topology_blocks_distribution_claim() {
        let mut context = scope();
        context.topology_verified = false;
        let input = vec![
            observation(Signal::DistributionUplinkDown, None),
            observation(Signal::SubscriberUnreachable, Some("sub-a")),
            observation(Signal::SubscriberUnreachable, Some("sub-b")),
        ];
        assert_eq!(
            diagnose(&context, &input, NOW, 120).unwrap().hypothesis,
            Hypothesis::InsufficientEvidence
        );
    }

    #[test]
    fn one_los_with_good_uplink_and_neighbor_yields_access_hypothesis() {
        let result = run(vec![
            observation(Signal::DistributionUplinkHealthy, None),
            observation(Signal::NeighborOntHealthy, Some("neighbor-a")),
            observation(Signal::OntOpticalLos, Some("sub-a")),
        ]);
        assert_eq!(result.hypothesis, Hypothesis::OntAccess);
        assert_eq!(result.affected_subscribers, ["sub-a"]);
    }

    #[test]
    fn pppoe_failures_need_matching_normal_optics_and_good_uplink() {
        let result = run(vec![
            observation(Signal::DistributionUplinkHealthy, None),
            observation(Signal::OntOpticalNormal, Some("sub-a")),
            observation(Signal::PppoeAuthenticationRejected, Some("sub-a")),
            observation(Signal::PppoeAuthenticationRejected, Some("sub-b")),
        ]);
        assert_eq!(result.hypothesis, Hypothesis::PppoeAuthentication);
        assert_eq!(result.affected_subscribers, ["sub-a"]);
    }

    #[test]
    fn missing_cwmp_inform_never_proves_fiber_damage() {
        let result = run(vec![observation(Signal::CwmpInformMissing, Some("sub-a"))]);
        assert_eq!(result.hypothesis, Hypothesis::InsufficientEvidence);
        assert!(result.affected_subscribers.is_empty());
    }

    #[test]
    fn stale_observations_cannot_trigger_inference() {
        let mut input = vec![
            observation(Signal::DistributionUplinkDown, None),
            observation(Signal::SubscriberUnreachable, Some("sub-a")),
            observation(Signal::SubscriberUnreachable, Some("sub-b")),
        ];
        for event in &mut input {
            event.observed_at_epoch = 700;
        }
        let outcome = run(input);
        assert_eq!(outcome.hypothesis, Hypothesis::InsufficientEvidence);
        assert_eq!(outcome.discarded_stale, 3);
        assert!(outcome.evidence.is_empty());
    }

    #[test]
    fn mixed_tenant_or_pop_observations_fail_without_leak() {
        let mut input = observation(Signal::OntOpticalLos, Some("sub-b"));
        input.tenant_id = tenant("nengnet");
        assert_eq!(
            diagnose(&scope(), &[input.clone()], NOW, 120).unwrap_err(),
            DiagnosticError::CrossTenantOrWrongScope
        );
        input.tenant_id = tenant("kangnet");
        input.pop_id = "pop-other".into();
        assert_eq!(
            diagnose(&scope(), &[input], NOW, 120).unwrap_err(),
            DiagnosticError::CrossTenantOrWrongScope
        );
    }

    #[test]
    fn conflicting_healthy_and_down_or_optical_signals_require_review() {
        let outcome = run(vec![
            observation(Signal::DistributionUplinkDown, None),
            observation(Signal::DistributionUplinkHealthy, None),
            observation(Signal::SubscriberUnreachable, Some("sub-a")),
            observation(Signal::SubscriberUnreachable, Some("sub-b")),
        ]);
        assert_eq!(outcome.hypothesis, Hypothesis::ConflictingEvidence);
        assert!(outcome.affected_subscribers.is_empty());
        let optical = run(vec![
            observation(Signal::DistributionUplinkHealthy, None),
            observation(Signal::OntOpticalLos, Some("sub-a")),
            observation(Signal::OntOpticalNormal, Some("sub-a")),
            observation(Signal::NeighborOntHealthy, Some("neighbor-a")),
        ]);
        assert_eq!(optical.hypothesis, Hypothesis::ConflictingEvidence);
    }

    #[test]
    fn limits_invalid_sources_and_future_events_fail_closed() {
        assert_eq!(
            diagnose(&scope(), &[], NOW, 0).unwrap_err(),
            DiagnosticError::InvalidFreshnessWindow
        );
        assert_eq!(
            diagnose(
                &scope(),
                &vec![observation(Signal::CwmpInformMissing, None); 1025],
                NOW,
                120
            )
            .unwrap_err(),
            DiagnosticError::UnboundedInput
        );
        let mut input = observation(Signal::CwmpInformMissing, None);
        input.source_id = "bad source".into();
        assert_eq!(
            diagnose(&scope(), &[input.clone()], NOW, 120).unwrap_err(),
            DiagnosticError::InvalidObservation
        );
        input.source_id = "sim".into();
        input.observed_at_epoch = NOW + 1;
        assert_eq!(
            diagnose(&scope(), &[input], NOW, 120).unwrap_err(),
            DiagnosticError::FutureObservation
        );
    }

    #[test]
    fn no_single_failed_subscriber_distribution_guess() {
        let outcome = run(vec![
            observation(Signal::DistributionUplinkDown, None),
            observation(Signal::SubscriberUnreachable, Some("sub-a")),
            observation(Signal::SubscriberUnreachable, Some("sub-a")),
        ]);
        assert_eq!(outcome.hypothesis, Hypothesis::InsufficientEvidence);
    }
}
