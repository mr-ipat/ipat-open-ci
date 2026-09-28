//! Pure authorization policy. Authentication / trusted identity are NOT implemented.

pub mod dashboard;
pub mod verified_menu;

use tenant_core::TenantId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    TenantAdmin,
    NocEngineer,
    Helpdesk,
    Auditor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    ViewDevice,
    ViewSubscriber,
    ExportSubscriber,
    ViewAudit,
    BulkPppoeWrite,
}

#[derive(Debug)]
pub struct PolicyPrincipal<'a> {
    /// Must originate from a verified identity, never request headers.
    pub tenant_id: &'a TenantId,
    pub roles: &'a [Role],
    pub authorized_pops: &'a [&'a str],
}

pub struct ResourceScope<'a> {
    pub tenant_id: &'a TenantId,
    pub pop_id: &'a str,
}

/// Deny by default. HIGH-RISK writes are denied until approval checks exist.
pub fn is_allowed(
    principal: &PolicyPrincipal<'_>,
    resource: &ResourceScope<'_>,
    action: Action,
) -> bool {
    if principal.tenant_id != resource.tenant_id {
        return false;
    }
    let has = |role| principal.roles.contains(&role);
    let is_admin = has(Role::TenantAdmin);
    let in_pop = is_admin || principal.authorized_pops.contains(&resource.pop_id);
    if !in_pop {
        return false;
    }
    match action {
        Action::ViewDevice => is_admin || has(Role::NocEngineer),
        Action::ViewSubscriber => is_admin || has(Role::NocEngineer) || has(Role::Helpdesk),
        Action::ExportSubscriber => is_admin,
        Action::ViewAudit => is_admin || has(Role::Auditor),
        Action::BulkPppoeWrite => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> TenantId {
        TenantId::parse(s).unwrap()
    }

    #[test]
    fn tenant_admin_cannot_cross_tenant_boundary() {
        let own = id("kangnet");
        let other = id("nengnet");
        let admin = PolicyPrincipal {
            tenant_id: &own,
            roles: &[Role::TenantAdmin],
            authorized_pops: &[],
        };
        assert!(is_allowed(
            &admin,
            &ResourceScope {
                tenant_id: &own,
                pop_id: "a"
            },
            Action::ViewDevice
        ));
        for action in [
            Action::ViewDevice,
            Action::ViewSubscriber,
            Action::ExportSubscriber,
            Action::ViewAudit,
            Action::BulkPppoeWrite,
        ] {
            assert!(!is_allowed(
                &admin,
                &ResourceScope {
                    tenant_id: &other,
                    pop_id: "a"
                },
                action
            ));
        }
    }

    #[test]
    fn helpdesk_can_only_view_authorized_pop_subscribers() {
        let own = id("kangnet");
        let helpdesk = PolicyPrincipal {
            tenant_id: &own,
            roles: &[Role::Helpdesk],
            authorized_pops: &["pop-a"],
        };
        let in_scope = ResourceScope {
            tenant_id: &own,
            pop_id: "pop-a",
        };
        let wrong_pop = ResourceScope {
            tenant_id: &own,
            pop_id: "pop-b",
        };
        assert!(is_allowed(&helpdesk, &in_scope, Action::ViewSubscriber));
        assert!(!is_allowed(&helpdesk, &in_scope, Action::ViewDevice));
        assert!(!is_allowed(&helpdesk, &in_scope, Action::ExportSubscriber));
        assert!(!is_allowed(&helpdesk, &wrong_pop, Action::ViewSubscriber));
    }

    #[test]
    fn high_risk_write_is_unconditionally_blocked() {
        let own = id("kangnet");
        let admin = PolicyPrincipal {
            tenant_id: &own,
            roles: &[Role::TenantAdmin],
            authorized_pops: &[],
        };
        assert!(!is_allowed(
            &admin,
            &ResourceScope {
                tenant_id: &own,
                pop_id: "a"
            },
            Action::BulkPppoeWrite
        ));
    }

    #[test]
    fn no_roles_means_no_access() {
        let own = id("kangnet");
        let actor = PolicyPrincipal {
            tenant_id: &own,
            roles: &[],
            authorized_pops: &["a"],
        };
        assert!(!is_allowed(
            &actor,
            &ResourceScope {
                tenant_id: &own,
                pop_id: "a"
            },
            Action::ViewSubscriber
        ));
    }
}
