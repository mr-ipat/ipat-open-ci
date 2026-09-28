//! IPAT provider-independent, non-executing host firewall policy validator.
//!
//! This crate is an intentionally limited dry-run prototype. It does not
//! configure nftables, provider security groups, Kubernetes CNI or networking.
//! Actual host application needs a separately reviewed, privileged agent,
//! out-of-band rescue access, backups, timed rollback and real dual-stack tests.

use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Zone {
    /// IPAT operator login source; not an automatically trusted tenant source.
    Management,
    /// Separately validated private node-to-node overlay, NOT the public NIC.
    PrivateCluster,
    /// Future verified tenant-domain HTTPS edge only.
    PublicTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    Ssh,
    Https,
    KubernetesApi,
    Kubelet,
    Etcd,
    FlannelVxlan,
    Wireguard,
}

impl Service {
    pub const fn port(self) -> (Transport, u16) {
        match self {
            Self::Ssh => (Transport::Tcp, 22),
            Self::Https => (Transport::Tcp, 443),
            Self::KubernetesApi => (Transport::Tcp, 6443),
            Self::Kubelet => (Transport::Tcp, 10250),
            Self::Etcd => (Transport::Tcp, 2379),
            Self::FlannelVxlan => (Transport::Udp, 8472),
            Self::Wireguard => (Transport::Udp, 51820),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// A rule is only a proposed allowlist entry, never an nftables command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit {
    pub zone: Zone,
    pub service: Service,
    /// Explicit CIDR. Management sources must be exact /32 or /128 addresses.
    pub source_cidr: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Evidence {
    /// Set only AFTER independent private interface/route tests and ADR review.
    pub private_overlay_verified: bool,
    /// Set only AFTER verified DNS ownership, certificate and ingress controls.
    pub tenant_tls_verified: bool,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub permits: Vec<Permit>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub permits: Vec<Permit>,
    /// Intent only: a dedicated IPv4/IPv6 host input chain would default deny.
    pub proposed_ipv4_default_drop: bool,
    pub proposed_ipv6_default_drop: bool,
    /// There is deliberately no callable apply operation in this crate.
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NoRules,
    TooManyRules,
    NoManagementRoute,
    BadCidr,
    BroadSourceForbidden,
    WrongScope,
    ManagementMustBeExactAddress,
    InvalidManagementAddress,
    PrivateOverlayNotVerified,
    PrivateSubnetRequired,
    TlsNotVerified,
    DuplicateRule,
}

fn cidr(source: &str) -> Result<(IpAddr, u8), Error> {
    let (addr, bits) = source.split_once('/').ok_or(Error::BadCidr)?;
    if addr.is_empty() || bits.is_empty() || bits.starts_with('+') {
        return Err(Error::BadCidr);
    }
    let ip: IpAddr = addr.parse().map_err(|_| Error::BadCidr)?;
    let prefix: u8 = bits.parse().map_err(|_| Error::BadCidr)?;
    match ip {
        IpAddr::V4(_) if prefix <= 32 => Ok((ip, prefix)),
        IpAddr::V6(_) if prefix <= 128 => Ok((ip, prefix)),
        _ => Err(Error::BadCidr),
    }
}

fn management_ip_ok(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_loopback()
                && !v.is_broadcast()
                && !v.is_link_local()
        }
        IpAddr::V6(v) => {
            !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_loopback()
                && !v.is_unicast_link_local()
        }
    }
}

fn private_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private(),
        // RFC 4193 unique-local fc00::/7. Link-local is excluded.
        IpAddr::V6(v) => v.octets()[0] & 0xfe == 0xfc,
    }
}

/// Validate a proposal only. Never mistake a plan for active firewall rules.
///
/// Both address families have proposed default-deny INPUT intent. Actual
/// rules require careful ICMPv6 ND/PMTU, K3s CNI and existing ruleset handling.
/// No actor/tenant authorization or approval is implemented here yet.
pub fn draft(request: Request) -> Result<Draft, Error> {
    if request.permits.is_empty() {
        return Err(Error::NoRules);
    }
    if request.permits.len() > 32 {
        return Err(Error::TooManyRules);
    }
    let mut has_management = false;
    let mut seen = HashSet::new();

    for rule in &request.permits {
        let (address, prefix) = cidr(&rule.source_cidr)?;
        if prefix == 0 && !(rule.zone == Zone::PublicTls && rule.service == Service::Https) {
            return Err(Error::BroadSourceForbidden);
        }
        if !seen.insert((rule.zone, rule.service, address, prefix)) {
            return Err(Error::DuplicateRule);
        }
        match rule.zone {
            Zone::Management => {
                if rule.service != Service::Ssh {
                    return Err(Error::WrongScope);
                }
                let maximum = match address {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                if prefix != maximum {
                    return Err(Error::ManagementMustBeExactAddress);
                }
                if !management_ip_ok(address) {
                    return Err(Error::InvalidManagementAddress);
                }
                has_management = true;
            }
            Zone::PrivateCluster => {
                if matches!(rule.service, Service::Ssh | Service::Https) {
                    return Err(Error::WrongScope);
                }
                if !request.evidence.private_overlay_verified {
                    return Err(Error::PrivateOverlayNotVerified);
                }
                if !private_network(address) {
                    return Err(Error::PrivateSubnetRequired);
                }
            }
            Zone::PublicTls => {
                if rule.service != Service::Https {
                    return Err(Error::WrongScope);
                }
                if !request.evidence.tenant_tls_verified {
                    return Err(Error::TlsNotVerified);
                }
            }
        }
    }
    if !has_management {
        return Err(Error::NoManagementRoute);
    }
    Ok(Draft {
        permits: request.permits,
        proposed_ipv4_default_drop: true,
        proposed_ipv6_default_drop: true,
        executable: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn management(cidr: &str) -> Permit {
        Permit {
            zone: Zone::Management,
            service: Service::Ssh,
            source_cidr: cidr.to_owned(),
        }
    }

    fn request(permits: Vec<Permit>, evidence: Evidence) -> Request {
        Request { permits, evidence }
    }

    #[test]
    fn explicit_ipv4_management_is_a_nonexecutable_dual_stack_draft() {
        let d = draft(request(
            vec![management("198.51.100.9/32")],
            Evidence::default(),
        ))
        .unwrap();
        assert!(!d.executable);
        assert!(d.proposed_ipv4_default_drop);
        assert!(d.proposed_ipv6_default_drop);
    }

    #[test]
    fn ipv6_management_requires_exact_source() {
        assert!(draft(request(
            vec![management("2001:db8::9/128")],
            Evidence::default()
        ))
        .is_ok());
        assert_eq!(
            draft(request(
                vec![management("2001:db8::9/64")],
                Evidence::default()
            ))
            .unwrap_err(),
            Error::ManagementMustBeExactAddress
        );
    }

    #[test]
    fn global_ssh_allow_is_rejected_for_both_families() {
        for source in ["0.0.0.0/0", "::/0"] {
            assert_eq!(
                draft(request(vec![management(source)], Evidence::default())).unwrap_err(),
                Error::BroadSourceForbidden
            );
        }
    }

    #[test]
    fn malformed_and_unspecified_management_sources_rejected() {
        for source in ["198.51.100.9", "198.51.100.9/33", "2001:db8::1/129"] {
            assert_eq!(
                draft(request(vec![management(source)], Evidence::default())).unwrap_err(),
                Error::BadCidr
            );
        }
        assert_eq!(
            draft(request(
                vec![management("127.0.0.1/32")],
                Evidence::default()
            ))
            .unwrap_err(),
            Error::InvalidManagementAddress
        );
    }

    #[test]
    fn public_kubernetes_and_overlay_never_allowed() {
        for service in [
            Service::KubernetesApi,
            Service::Kubelet,
            Service::Etcd,
            Service::FlannelVxlan,
        ] {
            let rules = vec![
                management("198.51.100.9/32"),
                Permit {
                    zone: Zone::PublicTls,
                    service,
                    source_cidr: "0.0.0.0/0".into(),
                },
            ];
            assert_eq!(
                draft(request(
                    rules,
                    Evidence {
                        tenant_tls_verified: true,
                        ..Evidence::default()
                    }
                ))
                .unwrap_err(),
                Error::BroadSourceForbidden
            );
        }
    }

    #[test]
    fn private_overlay_requires_explicit_verification_and_private_cidr() {
        let cluster = Permit {
            zone: Zone::PrivateCluster,
            service: Service::KubernetesApi,
            source_cidr: "10.42.0.0/16".into(),
        };
        let rules = vec![management("198.51.100.9/32"), cluster.clone()];
        assert_eq!(
            draft(request(rules.clone(), Evidence::default())).unwrap_err(),
            Error::PrivateOverlayNotVerified
        );
        assert!(draft(request(
            rules,
            Evidence {
                private_overlay_verified: true,
                ..Evidence::default()
            }
        ))
        .is_ok());
        assert_eq!(
            draft(request(
                vec![
                    management("198.51.100.9/32"),
                    Permit {
                        source_cidr: "198.51.100.191/24".into(),
                        ..cluster
                    }
                ],
                Evidence {
                    private_overlay_verified: true,
                    ..Evidence::default()
                }
            ))
            .unwrap_err(),
            Error::PrivateSubnetRequired
        );
    }

    #[test]
    fn public_https_requires_verified_tls_and_management_route() {
        let https = Permit {
            zone: Zone::PublicTls,
            service: Service::Https,
            source_cidr: "::/0".into(),
        };
        assert_eq!(
            draft(request(
                vec![management("198.51.100.9/32"), https.clone()],
                Evidence::default()
            ))
            .unwrap_err(),
            Error::TlsNotVerified
        );
        assert!(draft(request(
            vec![management("198.51.100.9/32"), https.clone()],
            Evidence {
                tenant_tls_verified: true,
                ..Evidence::default()
            }
        ))
        .is_ok());
        assert_eq!(
            draft(request(
                vec![https],
                Evidence {
                    tenant_tls_verified: true,
                    ..Evidence::default()
                }
            ))
            .unwrap_err(),
            Error::NoManagementRoute
        );
    }

    #[test]
    fn duplicate_rules_and_excessive_proposals_are_rejected() {
        assert_eq!(
            draft(request(
                vec![management("198.51.100.9/32"); 2],
                Evidence::default()
            ))
            .unwrap_err(),
            Error::DuplicateRule
        );
        assert_eq!(
            draft(request(
                vec![management("198.51.100.9/32"); 33],
                Evidence::default()
            ))
            .unwrap_err(),
            Error::TooManyRules
        );
    }

    #[test]
    fn empty_or_misplaced_management_fails_closed() {
        assert_eq!(
            draft(request(vec![], Evidence::default())).unwrap_err(),
            Error::NoRules
        );
        let bad = Permit {
            zone: Zone::Management,
            service: Service::Https,
            source_cidr: "198.51.100.9/32".into(),
        };
        assert_eq!(
            draft(request(vec![bad], Evidence::default())).unwrap_err(),
            Error::WrongScope
        );
    }
}
