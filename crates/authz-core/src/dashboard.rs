//! Pure dashboard capability reference policy, NOT an authentication layer.
//! The caller MUST originate roles/tenant/POP from validated OIDC plus
//! persisted tenant membership. No HTTP endpoint uses this until that exists.
use tenant_core::TenantId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardRole {
    TenantAdmin,
    NocEngineer,
    Helpdesk,
    Auditor,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardSection {
    PlatformOverview,
    PlatformTenantCatalog,
    PlatformSubscriptionPlans,
    TenantOverview,
    TenantMembers,
    TenantInventory,
    TenantSubscribers,
    TenantAudit,
    OperationsOverview,
    OperationsInventory,
    OperationsAlerts,
    BulkPppoeWrite,
}
#[derive(Clone, Copy, Debug)]
pub enum DashboardSubject<'a> {
    /// Only a future independently verified platform principal may mint this.
    PlatformOwner,
    Tenant {
        tenant: &'a TenantId,
        roles: &'a [DashboardRole],
        authorized_pops: &'a [&'a str],
    },
}
#[derive(Clone, Copy, Debug)]
pub enum DashboardResource<'a> {
    PlatformMetadata,
    Tenant {
        tenant: &'a TenantId,
        pop: Option<&'a str>,
    },
}
/// Pure, exhaustively scoped *read only* presentation policy.
///
/// Even a PlatformOwner is NOT permitted to see tenant subscriber/device
/// content. High-risk operations and "not yet approved" UI are denied.
pub fn allows(
    subject: &DashboardSubject<'_>,
    resource: DashboardResource<'_>,
    section: DashboardSection,
) -> bool {
    match (subject, resource) {
        (DashboardSubject::PlatformOwner, DashboardResource::PlatformMetadata) => {
            matches!(
                section,
                DashboardSection::PlatformOverview
                    | DashboardSection::PlatformTenantCatalog
                    | DashboardSection::PlatformSubscriptionPlans
            )
        }
        (
            DashboardSubject::Tenant {
                tenant,
                roles,
                authorized_pops,
            },
            DashboardResource::Tenant {
                tenant: resource_tenant,
                pop,
            },
        ) if *tenant == resource_tenant && !roles.is_empty() => {
            let admin = roles.contains(&DashboardRole::TenantAdmin);
            let engineer = roles.contains(&DashboardRole::NocEngineer);
            let helpdesk = roles.contains(&DashboardRole::Helpdesk);
            let auditor = roles.contains(&DashboardRole::Auditor);
            let pop_permitted = pop.is_some_and(|p| admin || authorized_pops.contains(&p));
            match section {
                DashboardSection::TenantOverview => admin || engineer || helpdesk || auditor,
                DashboardSection::TenantMembers => admin && pop.is_none(),
                DashboardSection::TenantInventory => pop_permitted && (admin || engineer),
                DashboardSection::TenantSubscribers => {
                    pop_permitted && (admin || engineer || helpdesk)
                }
                DashboardSection::TenantAudit => admin || (auditor && pop_permitted),
                DashboardSection::OperationsOverview => admin || (engineer && pop_permitted),
                DashboardSection::OperationsInventory | DashboardSection::OperationsAlerts => {
                    pop_permitted && (admin || engineer)
                }
                _ => false,
            }
        }
        _ => false,
    }
}
/// This is for future trusted server-side menu construction, NOT browser
/// security. Denied controls must ALSO be denied by every backend endpoint.
pub fn visible_sections(
    subject: &DashboardSubject<'_>,
    resource: DashboardResource<'_>,
) -> Vec<DashboardSection> {
    use DashboardSection::{
        OperationsAlerts, OperationsInventory, OperationsOverview, PlatformOverview,
        PlatformSubscriptionPlans, PlatformTenantCatalog, TenantAudit, TenantInventory,
        TenantMembers, TenantOverview, TenantSubscribers,
    };
    [
        PlatformOverview,
        PlatformTenantCatalog,
        PlatformSubscriptionPlans,
        TenantOverview,
        TenantMembers,
        TenantInventory,
        TenantSubscribers,
        TenantAudit,
        OperationsOverview,
        OperationsInventory,
        OperationsAlerts,
    ]
    .into_iter()
    .filter(|section| allows(subject, resource, *section))
    .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tenant(s: &str) -> TenantId {
        TenantId::parse(s).unwrap()
    }
    #[test]
    fn platform_owner_sees_platform_metadata_only_not_customer_secrets() {
        let a = tenant("synthetic-a");
        let p = DashboardSubject::PlatformOwner;
        assert_eq!(
            visible_sections(&p, DashboardResource::PlatformMetadata),
            vec![
                DashboardSection::PlatformOverview,
                DashboardSection::PlatformTenantCatalog,
                DashboardSection::PlatformSubscriptionPlans
            ]
        );
        for section in [
            DashboardSection::TenantOverview,
            DashboardSection::TenantMembers,
            DashboardSection::TenantInventory,
            DashboardSection::TenantSubscribers,
            DashboardSection::TenantAudit,
            DashboardSection::OperationsOverview,
            DashboardSection::OperationsInventory,
            DashboardSection::OperationsAlerts,
            DashboardSection::BulkPppoeWrite,
        ] {
            assert!(!allows(
                &p,
                DashboardResource::Tenant {
                    tenant: &a,
                    pop: Some("pop-a")
                },
                section
            ));
        }
    }
    #[test]
    fn tenant_admin_never_crosses_tenant_or_platform_metadata() {
        let a = tenant("synthetic-a");
        let b = tenant("synthetic-b");
        let role = [DashboardRole::TenantAdmin];
        let actor = DashboardSubject::Tenant {
            tenant: &a,
            roles: &role,
            authorized_pops: &[],
        };
        assert!(allows(
            &actor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: None
            },
            DashboardSection::TenantMembers
        ));
        assert!(allows(
            &actor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: Some("pop-a")
            },
            DashboardSection::TenantInventory
        ));
        for section in [
            DashboardSection::PlatformOverview,
            DashboardSection::PlatformTenantCatalog,
            DashboardSection::TenantOverview,
            DashboardSection::TenantSubscribers,
            DashboardSection::TenantMembers,
            DashboardSection::TenantInventory,
            DashboardSection::OperationsAlerts,
        ] {
            assert!(!allows(
                &actor,
                DashboardResource::Tenant {
                    tenant: &b,
                    pop: Some("pop-a")
                },
                section
            ));
        }
        assert!(visible_sections(&actor, DashboardResource::PlatformMetadata).is_empty());
        assert!(!allows(
            &actor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: None
            },
            DashboardSection::BulkPppoeWrite
        ));
    }
    #[test]
    fn pop_scoped_noc_cannot_read_unassigned_areas_or_manage_users() {
        let a = tenant("synthetic-a");
        let actor = DashboardSubject::Tenant {
            tenant: &a,
            roles: &[DashboardRole::NocEngineer],
            authorized_pops: &["assigned-pop"],
        };
        let good = DashboardResource::Tenant {
            tenant: &a,
            pop: Some("assigned-pop"),
        };
        let bad = DashboardResource::Tenant {
            tenant: &a,
            pop: Some("other-pop"),
        };
        for action in [
            DashboardSection::TenantInventory,
            DashboardSection::OperationsAlerts,
            DashboardSection::OperationsInventory,
            DashboardSection::TenantSubscribers,
        ] {
            assert!(allows(&actor, good, action));
            assert!(!allows(&actor, bad, action));
        }
        assert!(allows(&actor, good, DashboardSection::OperationsOverview));
        assert!(!allows(&actor, bad, DashboardSection::OperationsOverview));
        assert!(!allows(
            &actor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: None
            },
            DashboardSection::OperationsOverview
        ));
        assert!(!allows(&actor, good, DashboardSection::TenantMembers));
        assert!(!allows(&actor, good, DashboardSection::PlatformOverview));
    }
    #[test]
    fn helpdesk_only_has_minimal_pop_scoped_read_no_noc_or_exports() {
        let a = tenant("synthetic-a");
        let actor = DashboardSubject::Tenant {
            tenant: &a,
            roles: &[DashboardRole::Helpdesk],
            authorized_pops: &["assigned-pop"],
        };
        let scope = DashboardResource::Tenant {
            tenant: &a,
            pop: Some("assigned-pop"),
        };
        assert!(allows(&actor, scope, DashboardSection::TenantSubscribers));
        assert!(!allows(&actor, scope, DashboardSection::TenantInventory));
        assert!(!allows(&actor, scope, DashboardSection::OperationsAlerts));
        assert!(!allows(&actor, scope, DashboardSection::BulkPppoeWrite));
        assert!(!allows(
            &actor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: None
            },
            DashboardSection::TenantSubscribers
        ));
    }
    #[test]
    fn auditor_and_no_roles_fail_closed_on_mutations_and_operations() {
        let a = tenant("synthetic-a");
        let scope = DashboardResource::Tenant {
            tenant: &a,
            pop: Some("assigned-pop"),
        };
        let auditor = DashboardSubject::Tenant {
            tenant: &a,
            roles: &[DashboardRole::Auditor],
            authorized_pops: &["assigned-pop"],
        };
        assert!(allows(&auditor, scope, DashboardSection::TenantAudit));
        assert!(!allows(
            &auditor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: None
            },
            DashboardSection::TenantAudit
        ));
        assert!(!allows(
            &auditor,
            DashboardResource::Tenant {
                tenant: &a,
                pop: Some("wrong-pop")
            },
            DashboardSection::TenantAudit
        ));
        for permission in [
            DashboardSection::TenantSubscribers,
            DashboardSection::TenantInventory,
            DashboardSection::OperationsAlerts,
            DashboardSection::BulkPppoeWrite,
        ] {
            assert!(!allows(&auditor, scope, permission));
        }
        let empty = DashboardSubject::Tenant {
            tenant: &a,
            roles: &[],
            authorized_pops: &["assigned-pop"],
        };
        assert!(visible_sections(&empty, scope).is_empty());
    }
}
