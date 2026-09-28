# IPAT R7.6 — Domain intent Fadly, platform domain later, identity-first lab

**Owner-provided business intent, 27 September 2026.** The owner
identifies hub.example.invalid as the *intended future custom domain for
Fadly's company tenant*, and ipat.id as IPAT's intended *future
commercial platform domain*. Do not treat the claim as independently
verified DNS/legal control, a live tenant enrollment, or approval to
expose an application to public traffic.

## Distinguish three independent identities

| Name | Intended layer | Current verified capability / status |
|---|---|---|
| Fadly tenant (illustrative stable slug: fadly) | Company tenant ID resolved from approved database membership | SYNTHETIC test tenant only. No real membership or company dashboard login. |
| hub.example.invalid | Future Fadly-owned customer-custom-domain dashboard | INTENT ONLY / unverified / no customer UI routing. Currently also used as owner Mac SSH alias target for the LAB VPS. Do not switch DNS, routing or override Host-derived tenant. |
| ipat.id | Future commercial IPAT platform brand / candidate SaaS primary domain | INTENT ONLY, future ownership and DNS/TLS verification pending; no production listeners. |
| 127.0.0.1:48765 via strict SSH tunnel | Current private operator/lab preview URL | VERIFIED private lab transport, three synthetic workspace selectors, business APIs HTTP401. It is NOT a Fadly custom domain or real tenant application. |

Tenant identity is the *operator-approved UUID / tenant context*, not
the current FQDN, the IP address, the VPS hostname, a JWT-supplied
tenant_id, or an HTTP request header. Future domain↔tenant table must
use a separately verified, unique hostname claim and audited workflow.
Changing an address must NOT reassign devices, subscribers or stored
operational resources to a new tenant.

## Management-hostname collision: migration safety gate

The existing authorized operator SSH target already resolves through
hub.example.invalid. Turning that DNS name into a Fadly tenant public UI
requires a reviewed management-access migration/ingress split; do NOT
delete or repoint the current management DNS/SSH configuration in
R7.6. Confirm independent rescue console and dual-stack firewall
rollback (seven production safety gates remain blocked) before
replacing this alias or adding any public web listeners.
A hostname may technically host both SSH and HTTPS on different
ports, but that is not a security approval or a recommendation to
co-locate sensitive operator access with commercial customer ingress.

## First working lab now

1. Continue one private localhost operator preview with synthetic
   tenant/model fixtures, no public ingress.
2. Bridge *cryptographically verified OIDC issuer+subject* to a
   separately operator-approved exact tenant/role/POP candidate row,
   with negative cross-issuer, cross-subject, cross-tenant, revoked,
   expired and POP isolation tests. Never read the tenant/role from
   browser Host or JWT extra claims.
3. Actual backend endpoint remains closed (HTTP401) until an
   approved and audited persistent membership adapter, MFA and
   end-to-end RLS/API/worker/menu denial are reviewed and tested.
4. Continue C320 exact-card/firmware, trusted read-only private
   operator path and independent recovery; no physical proof
   available at this change, so TC-OLT-01 remains NOT RUN.
5. Later per ADR-014/020, verify customer domain ownership,
   DNS/TLS/OIDC callbacks and cookie host-only separation before
   public company access; ipat.id commercial service is separate
   from the Fadly company tenant.

## R7.6 code artifact and acceptance

Rust identity-core VerifiedSubject now retains its *pinned
verified issuer*, not just subject+expiry. Authz-core contains a
pure candidate membership-to-menu function, never invoked
by current real API. Its candidate row is not an approved DB
record by itself. Genuine short-lived *synthetic* RS256-signed
tokens and fixture rows prove positive limited NOC menu access
and negative wrong issuer/subject/tenant/POP, expiry, revocation,
platform impersonation and high-impact actions. This is not
real OIDC login/MFA or database binding.

Local/CI tests:

    cargo fmt --all -- --check
    cargo test --locked -p identity-core --test oidc_signature
    cargo test --locked -p authz-core --test verified_menu
    cargo test --workspace --locked
    python3 -m unittest discover deploy/scripts/lab/r74 -p test_lab_readiness.py -q

No migrations this milestone: candidate R7.0 identity schema remains
unexposed and unapproved for production, and the future domain schema
is intentionally deferred. No actual SSH, K3s, firewall or device
configuration changes are needed for this identity-first slice.
