# IPAT R7.5 — Single-endpoint private laboratory first; tenant domains later

**27 September 2026 · Product-owner approved rollout sequencing only.**
Not an approval of a new production architecture, publicly exposed endpoint,
identity bypass, physical device access, firmware upgrade or lower PRD security
acceptance. FR-004 has always been a commercial (C) requirement.

## Product decision

1. MUST NOW: stabilize original Rust ACS and native USP architecture;
   prepare/read actual dedicated NONPRODUCTION C320 with proven private
   device identity; progress verified tenant/POP membership and backend
   authorization independently of any public domain names. Use the existing
   SSH-forwarded loopback-only operator preview to review UI, not a public
   tenant application.
2. MUST BEFORE ANY REAL MULTI-TENANT USER/DATA API: real OIDC/MFA,
   server-resolved approved tenant membership and POP grants, RBAC+ABAC
   enforcement at menu/API/jobs, PostgreSQL RLS and negative two-tenant
   tests (FR-001/002/003, AC-01/02). A shared temporary hostname is only
   a routing convenience, never a tenant identity or isolation proof.
   **No tenant isolation/security gate may be deferred.**
3. DEFER TO M2, BEFORE customer-domain or commercial access (FR-004/
   AC-09/ADR-014): company subdomain ownership, customer custom-domain
   DNS verification, dedicated TLS certificate issuance/renewal, trusted
   Host-to-tenant mapping, host-only cookies, per-domain CSRF/OIDC callbacks,
   and cross-domain spoof/takeover testing. Continue keeping the entrypoint
   private until that stage passes. Domain deferral never changes the
   product's SaaS multi-tenant target.

## Actual code delivered in R7.5

- New source-controlled static `web/lab/rollout-phase.json` is embedded
  in Rust control-api as read-only GET `/lab/rollout-phase` only in
  explicitly owner-enabled PRIVATE non-K3s loopback preview.
- The schema refuses to claim physical OLT connection, device-read approval,
  firmware capability, real tenant authentication or E2E isolation.
  The response says domain verification is deferred but isolation is still
  mandatory. Browser validates ALL those fixed fields; if inconsistent
  or missing, the UI explicitly warns phase is unverified.
- Each of the three private workspace previews shows an unmistakable
  common scheduling banner and separately keeps its large RED incomplete-PRD
  alert and per-workspace red gap ledger.
- Existing business endpoints still HTTP401 regardless of forged Host,
  Authorization, tenant or role header. There is NO domain-derived
  membership, fallback tenant, configuration flag or new data endpoint.
  POST/PUT/DELETE on the phase manifest must be HTTP405.
- No live VPS root actions, DNS, host firewall, K3s or PostgreSQL changes.
  A source preview refresh through the already-approved nonroot SSH
  loopback path is not public system activation.

## Acceptance / run tests

Source/CI:

    python3 -m json.tool web/lab/rollout-phase.json >/dev/null
    node --check web/lab/dashboard-preview.js
    node deploy/scripts/lab/r68/test_dashboard_preview.mjs
    python3 -m unittest discover deploy/scripts/lab/r68 -p test_dashboard_preview.py -v
    cargo fmt --all -- --check
    cargo test --workspace --locked --offline
    # CI disposable-loopback HTTP check only:
    IPAT_R68_PRIVATE_HTTP_SMOKE=YES bash deploy/scripts/lab/r68/private-dashboard-http-smoke.sh

Local private operator HTTP after reviewed merge/exact-SHA deployment:
GET phase HTTP200/no-store/static safe flags;
POST/PUT/DELETE phase HTTP405;
forged Platform/Tenant/NOC business requests HTTP401;
no public ingress, no physical device connection.

**Physical OLT TC-OLT-01 still NOT RUN**; independent exact
board/build, verified host and isolated route, dedicated read-only account,
local console and backup remain blockers. R7.4 packet remains explicitly
all-false until separate operator checks. See C320_ISOLATED_LAB_R74.md.
