# IPAT — Security Architecture & Threat Model v0.1

**Date:** 2026-09-25 · **Status:** design baseline + implementation proposals; no penetration test or security certification performed.
**Primary rule:** Deny by default. Multi-tenant isolation is a **security invariant across every subsystem**, not a frontend setting.

## 1. Assets, actors, trust boundaries

**Critical assets:** subscriber PII, device credentials, PPPoE secrets, ACS/CWMP and USP controller/agent keys, router/OLT configs, operational topology, telemetry, plans/quotas, audit trails, tenant backups, signing keys and admin identities.

**Actors:** platform admin (commercial platform control only), tenant roles, automated service identities, enrolled devices, external attacker, compromised device/tenant employee, compromised third-party/VPS or supply-chain dependency. Platform staff cannot directly reveal tenant device credentials by virtue of platform role.

**Boundaries (each enforced independently):** (A) public user/browser and authenticated tenant API; (B) custom-domain ingress; (C) external CWMP/USP device ingress; (D) authorized private OLT/RouterOS management links; (E) inter-service/queue/worker; (F) app↔database/secret store/object store; (G) shared K3s control plane/platform operators; (H) backup/restore and observability planes.

## 2. Essential invariants / defense in depth

| ID | Invariant | Enforcement & negative evidence expected |
|---|---|---|
| SEC-01 | User tenant scope not chosen by headers or hostname alone | Signed OIDC identity + DB membership + verified domain; hostile header/Host tests deny |
| SEC-02 | Unentitled menus inaccessible at **all levels** | UI filtered nav, route guards and backend `authorize(actor, action, resource)`, reject API/query/search/export/notifications |
| SEC-03 | A worker cannot use queue payload to gain tenant rights | Queue contains job ID, DB job provenance and policy re-evaluation, least-privilege service identity |
| SEC-04 | Device belongs to one verified tenant | CWMP authenticated enrollment and serial/OUI validation, USP endpoint identity/broker ACL bound to immutable tenant assignment |
| SEC-05 | Secrets never propagate across tenant or public outputs | External vault/credential refs, short-lived reads, no secret in logs/metrics/screenshot/export/queue blob, rotation |
| SEC-06 | DB shared storage denies cross-tenant reads/writes even on DAL mistake | Scoped FK/queries + PostgreSQL RLS FORCE; app runtime unprivileged, automated isolation tests |
| SEC-07 | Dangerous operations cannot execute from an unapproved/unbounded request | Immutable plan hash, per-item scope, two-person rule where required, expiry, quotas, kill switch, audit |
| SEC-08 | Device failures/retries cannot silently cause duplicate high-impact provisioning | Durable job transitions, idempotency+lease/fencing, read-back/unknown state, manual intervention |
| SEC-09 | Tenant observability/backup/search are also isolated | No high-cardinality secret labels, tenant-scoped audit/export access, backup encryption/access review and restore validation |
| SEC-10 | Platform support access is explicit and time-limited | Tenant-approved (policy-dependent) just-in-time elevation, scope + reason, notification and immutable audit |

## 3. Threat scenarios and mitigation ownership

| ID | Threat/entry | Consequence | Required mitigations & test |
|---|---|---|---|
| T-01 | Tenant/POP IDOR in Axum API, GraphQL/search/export | Cross-tenant PII and device control | Resource-level PEP + DB RLS, ownership on joins/aggregates, property negative tests for each endpoint |
| T-02 | Host / X-Forwarded-Host spoofing, dangling custom domain | Tenant login takeover, session crossover | Edge allowed-host, DNS TXT verification & periodic re-verification, TLS issuance controls, pinned callbacks, host-only cookie + CSRF |
| T-03 | Malicious CWMP Inform spoofing device ID/ACS URL | Cross-tenant device claim and unauthorized config | Auth credential per enrollment, unique-id collision quarantine, per-device tenant binding, rate-limit, reject duplicate/unknown |
| T-04 | SOAP/XML entity expansion or oversized data/fault | Resource exhaustion/parser data exfiltration | No DTD/XXE, parser limits, maximum XML/message depth, timeouts, malformed payload fuzzing |
| T-05 | USP agent/topic spoof, replay, broker topic ACL gap | False state/unauthorized command | TLS authenticated broker identities, per agent/controller ACL, verified tenant mapping, sequence/correlation replay tests |
| T-06 | Rogue/compromised network device and SSRF via address fields | Lateral network/cloud metadata access | Private/tunneled egress, allowlisted verified target IP/DNS/cert, block metadata IP, network policies, no arbitrary URL fetch |
| T-07 | Malicious PPPoE CSV or overbroad bulk job | Account outage/mass change | Strict schema/encoding/size, tenant duplicate checks, preview, immutable diff, two-person approval, rate & blast radius caps |
| T-08 | Ambiguous timeout, duplicate RabbitMQ messages, dead worker | Repeat config execution | DB outbox/idempotency, lease/fencing, per-device lock and unknown/reconcile state; chaos fault injection |
| T-09 | RLS owner bypass / pooled connection setting bleed | Cross-tenant data leak | Separate migration/runtime users, NO BYPASSRLS, FORCE RLS, `SET LOCAL` transaction context, tenant negative tests on pooled connections |
| T-10 | Secrets in structured logs, metrics, DLQ, support bundles | Credential leak | Redaction at source, reference IDs only, scrub test/failure sampling, retention RBAC and security audit |
| T-11 | Shared backups/restore or object key/prefix confusion | Mass tenant breach or silent data mix | Offsite encryption, scoped restore operations, immutable validated manifests, no self-service raw shared DB backup |
| T-12 | Supply-chain dependency, compromised CI/GitOps | Fleet compromise | Pinned deps/lockfiles, SBOM, signed build artifacts, minimum CI privileges and protected deployment approvals |
| T-13 | Compromised platform owner / support account | Cross-tenant blast radius | No automatic device-secret rights, MFA, JIT access and dual approval, segmentation and elevated activity alerts |
| T-14 | Stale topology/telemetry treated as fact | Wrong remediation and service outage | Evidence timestamp and uncertainty, stale gating, human approval for high-impact actions |
| T-15 | Subscriber/user PII exported in diagnostic evidence | Privacy incident | Purpose-limited fields, redacted evidence, row/column policy and retention classification |

## 4. RBAC + ABAC model v0.1 (proposal subject to owner approval)

- **Default:** every action/resource/scope denies unless explicitly listed. New frontend menu, endpoint, command, event consumer or export must ship with a named policy and a denial test.
- **RBAC** establishes coarse role; **ABAC** checks tenant, site/POP, region, device/subscriber ownership, operation risk, maintenance window, role session strength (MFA), ticket and expiry. Server calculates attributes from trusted database and signed identity, not request fields alone.
- **Policy inputs:** `subject`, `service_actor`, `action`, `resource_type/id`, `verified_tenant_context`, `attributes`, `auth_strength`, `requested_plan_hash`, `approval`, `time`. Policy output `allow/deny` with reason code; no hidden implicit admin wildcard.
- **Policy matrix initial suggestion:**

| Role | Typical permitted scope | Explicit non-entitlements |
|---|---|---|
| Platform owner | Create tenant, plans and aggregated billing/usage metadata | No implicit device-secret/tenant subscriber read or network write |
| Tenant admin | Tenant membership, eligible role delegation, tenant settings | Platform operations and global data; high-risk write without approval |
| System admin | Scoped infrastructure/config operations | Bypass security policy or secret access by role alone |
| Security admin | Policy, access review, privileged approval per separation rule | Approve own high-risk request; cross-tenant unapproved secret access |
| NOC manager | Tenant/POP diagnostics, operations and eligible change approval | Platform/global access and unrestricted high-risk execution |
| NOC engineer | Read inventory/telemetry/incidents; approved scoped diagnostics | User access/secret export/unapproved bulk write |
| Provisioning officer | Scoped onboarding and create dry-run/request | Self-approval or unrestricted bulk change |
| Helpdesk | Minimal subscriber view and permitted diagnostics | Bulk provisioning, full configs, device secrets, restricted menus |
| Field technician | Assigned work and device subset during work window | Org-wide subscriber export, policy editing, unrelated POP data |
| Auditor | Scoped audit events and approved evidentiary export | Mutations, secret reads, jobs |

**MVP proof:** render one helpdesk and one provisioning actor, test allowed vs disallowed menu/route/API/POP/tenant; full role matrix implementation before commercial release.

## 5. High-risk classification & approval lifecycle

**Baseline high-risk examples:** PPPoE bulk create/update/delete, OLT config writes, mass reboot/reset, firmware push, secret reveal/export/rotation, platform role elevation, bulk subscriber export, cross-tenant support access, emergency device changes. Risk tier and thresholds per tenant/device/service to be finalized (`ADR-009`).

Lifecycle: `draft → validate → dry-run/diff immutable → request approval (reason/ticket/TTL) → distinct qualified approver → execution lease → per-item verify/reconcile → signed/redacted audit`. If plan hash, target set, risk class or operator scope changes, revoke approval and require new approval. Emergency break-glass needs policy, MFA, reason, timebox, just-in-time credentials, alarms, post-facto review; never silently bypass all controls.

Worker independently verifies unexpired approval, policy and plan hash immediately prior to any write. Limits include maximum devices per batch, per-router concurrency/rate, tenant daily quotas and kill switch. No automatic high-impact remediation in diagnostic engine without separately approved policy + tests.

## 6. Secrets, cryptography, and tenant data

- Ingress/APIs use TLS; USP MQTT TLS plus topic ACL if approved; device RouterOS `api-ssl` or HTTPS only with validated certificates for staging/production; CWMP auth/TLS strategy adapts to measured ONT capabilities without silent security downgrade.
- Deploy secrets out of Git: KMS/Vault product selection open. Secret references in DB/job payload; least-privileged service identity per service/tenant scope, runtime retrieval and audited rotate/revoke. Do not give generic platform-admin direct tenant-secret read.
- Encrypt tenant PII and backups at rest with managed keys; evaluate per-tenant envelope keys and rotation cost; backups and restore operators with dual-control and export risk classification. Distinguish platform data vs customer data and support audit retention.
- Synthetic examples: `${IPAT_TEST_DB_PASSWORD}`, `${IPAT_LAB_ROUTER_PASSWORD}` etc are placeholders, NEVER usable production secrets. Evidence must redact Authorization, SOAP credentials, PPPoE secret, JWT and subscriber PII.

## 7. Logging, monitoring and incident response

Every authorization, protocol identity binding, high-risk request/approval, execution, failed/replayed job, device access and restore emits structured event with timestamp UTC, sanitized subject/tenant/resource/correlation ID, policy rule/result and request hash (not payload secret). Central logs should be append-only/tamper-evident according to product tier; audit role reads via tenant-verified policy. Rate-limit security alarms; observability tenant labels cardinality/security reviewed.

P0 incident triggers: any confirmed cross-tenant access; compromised agent/credential; mass write unintended; accidental raw backup exposure; unauthorized platform support access. Runbooks: disable ingress/service actor, quarantine impacted device/tenant tokens, pause affected queue and prevent replay, preserve redacted evidence/immutable audit, root-cause, tenant notification per contract/law. No live credentials in ChatGPT or Git issues.

## 8. Verification gates

| Gate | Minimum automated/manual evidence | Phase |
|---|---|---|
| G-01 | Cross-tenant and cross-POP negative tests for all delivered API + jobs + export/search, authz snapshot UI | S1 and every release |
| G-02 | Unknown/untrusted device not automatically enrolled; malformed CWMP fails safe | S1 simulated, C physical |
| G-03 | Bulk PPPoE dry-run does not write; expired/self-approval/plan diff denied | S1 simulated/lab, C all supported adapters |
| G-04 | DB RLS owner/pool bypass and `SET LOCAL` tests; denied path cannot leak row counts/IDs | S1 on selected schema, C full tables |
| G-05 | USP ACL spoof/topic/replay and tenant mapping tests | PoC S1 if transport works; C conformance |
| G-06 | Secret redaction in logs, audits, DLQ, exports, traces, metrics and test artifacts | S1 representative, C comprehensive |
| G-07 | Static dependency scan, SCA/SBOM, image signed build + threat model review | C |
| G-08 | Penetration test and backup-isolation/restore/failover security drill | Before commercial |

## 9. Open questions, dependencies and privacy

Unresolved: precise role/action matrix and maker-checker thresholds; MFA for all roles vs privileged only; Keycloak version/multi-tenant realm strategy; data residency and lawful retention/deletion; vault/key ownership; client certificate/device enrollment fallback; external broker ACL choice; audit retention and tamper-resistance technology; tenant-specific encryption and shared physical-backup contractual disclosure. Track in `DECISIONS.md` and assign reviewers before commercialization.

**References:** `IPAT_PROJECT_BRIEF.md` as source of decisions; `ARCHITECTURE.md` and `PRD.md` for scope. PostgreSQL RLS mechanics: https://www.postgresql.org/docs/current/ddl-rowsecurity.html. No independent security audit or physical test has occurred in this documentation milestone.

## 10. Ubuntu restricted laboratory SSH posture (2026-09-25 execution note)

This implementation note does **not** approve an architectural change. The independently executed Stage-1 installer successfully provided Rust/C compilation, but its privileged SSH policy report showed that remote root and password-based SSH remained enabled in evaluated synthetic-loopback contexts. The host still has **no VPS snapshot or complete off-host recovery copy**. Current Stage-2 key-only policy and timed automatic rollback are strictly **PREPARED, NOT APPLIED**; see [the controlled Stage-2 runbook](../deploy/scripts/lab/STAGE2-SSH.md) and [actual evidence](PROJECT_STATUS.md). The owner's separate interactive `CONSOLE_READY` and `DISABLE_PASSWORD_SSH` confirmations are mandatory before applying globally visible SSH policy changes. Provider firewall and K3s networking must be reviewed in separate transactions; do not treat SSH hardening source-code tests as evidence that the live firewall, backup or application isolation is secure.

## 11. Actual Stage-2 SSH outcome and K3s security prerequisites (2026-09-25)

**Later verification supersedes the historical pre-change state in section 10.** The owner successfully executed the gated, six-minute timed-rollback SSH Stage 2 and confirmed its completion. An independent NEW Mac public-key SSH session succeeded; the root-owned early config snippet explicitly disables root and password SSH, the rollback marker is absent and a password-only diagnostic was refused by the actual `openai` server connection. We have **not** independently exercised privileged effective-policy checks for every possible SSH Match/source address, nor a failed-SSH timed-rollback drill. SSH port and firewall were unchanged. Do not conflate key-only SSH with network ingress security.

The real Ubuntu 26.04.1 rootless K3s host preflight is [recorded separately](LAB_K3S_READ_ONLY_2026-09-25.md). Provider ingress, public Flannel/Kubernetes port exposure, full encrypted independent recovery, multi-node private overlay and production K3s datastore remain unverified. **Do not expose TCP/6443 or UDP/8472 publicly or deploy customer data until those gates pass.** Architecture decision ADR-017 remains OPEN.


## 12. R4.5 actual temporary Mac restic backup and external provider network gate

Actual Mac `restic 0.19.1` repo uses a cryptographically random high-entropy password stored in local macOS Keychain and `RESTIC_PASSWORD_COMMAND`, with no password in Git. Two encrypted snapshots (earlier PARTIAL VPS config and canonical Git source) passed full repository data reading and isolated checksum-verified restore. **FileVault is OFF on the Mac** and the restic Keychain secret has not been independently escrowed, so the Mac is a temporary LAB location, not sufficient secure/independent production recovery. Root-only VPS config/host keys and all future app/database/K3s state remain unbacked up. Source evidence: [R4.5 actual backup + external provider inspection](LAB_ENCRYPTED_BACKUP_EDGE_R45.md).

The external provider Managed Firewall rule set, IPv6 rule posture and provider rollback mechanism remain unknown; external Mac probing established only that TCP/22 was reachable while no connection to the sampled unused service ports completed. **Do not infer that the provider blocks those ports** or permit public Kubernetes API/Flannel VXLAN; review the external provider panel's actual inbound/outbound IPv4+IPv6 rules and verified console recovery before any change. ADR-008/010/017 remain OPEN where recorded.


## 13. R4.6 screenshot-verified external provider allow-all ingress and completed FileVault

**More recent evidence supersedes the earlier Mac FileVault OFF finding.** The operator supplied a completed FileVault setup screen, and independent Mac `fdesetup status` reported **FileVault is On**. The prior encrypted Restic repository and same-Mac Keychain password were confirmed readable after FileVault activation, and a repeat **real isolated restore of the latest canonical source plus previous partial VPS config**, with `restic check --read-data` across all four snapshots/eight packs, succeeded. An independent recovery password escrow and independent second copy still have NOT been verified; the root-only VPS config and real app databases are unprotected by this backup.

The operator's current external provider screenshot shows security group `allow-all` allowing **all inbound IPv4 from `0.0.0.0/0` and all inbound IPv6 from `::/0`**. An independent host audit confirms a global IPv6 address, an IPv6 default route, and SSH listening on **both IPv4 and IPv6**, despite no AAAA in the earlier public DNS lookup. The provider security-group assignment/share scope and any additional Managed Firewall layer remain unknown. **Do not modify a possibly shared `allow-all` group** or mistake key-only SSH for network ingress restriction. [Exact, gated source-CIDR/runbook/rollback plan](EDGE_SECURITY_GROUP_R46.md). No provider/host firewall mutation was executed; owner must first demonstrate actual external provider VNC console login and separate recovery-key escrow.


## 14. R4.7 — user-confirmed external password escrow; SHARED external provider allow-all and failed VNC login

Operator reports **actual VNC Console login has not succeeded**, the external provider `allow-all` group is **shared by multiple VPSs**, and an off-Mac Restic recovery password copy is independently accessible (operator attestation, not audited). It would be unsafe to edit/delete the shared group's allow-all rules or attempt an untested restrictive replacement while the console recovery pathway is unavailable. Provider/guest firewall and K3s state are unchanged.

The new [R4.7 read-only root-config-to-encrypted-Mac backup design and test evidence](ROOT_CONFIG_STREAM_R47.md) allow an owner-interactive sudo-based root-config stream without touching provider or guest network configuration. Its real unprivileged SSH/Restic smoke+isolated restore and deliberate producer-failure/non-snapshot tests succeeded; actual root-privileged capture and root-config restore remain **PENDING USER MAC TERMINAL ACTION**. Sensitive root configuration remains encrypted in Restic with Keychain-only local password retrieval and FileVault ON; this is not full VPS/block backup or AC-07 PostgreSQL restore.


## R4.8 current execution and first-party host firewall proposal

**Later actual verification supersedes earlier "root backup pending" notes.** On 2026-09-25 the owner completed an interactive sudo-based read-only root-config SSH stream directly into the Mac's encrypted Restic repository. The assistant independently inspected actual snapshot `abaa9827`, ran `restic check --read-data` over **11 snapshots/20 packs**, and used `--verify-root` to restore into an isolated, cleanup-protected private directory. It verified gzip/tar integrity, root-only `etc/sudoers` presence, the expected managed key-only SSH directives and removal of plaintext test artifacts. **PASS for SELECTED ROOT CONFIG RECOVERY ONLY.** SSH host private keys, all VM filesystem contents, application/database state and future K3s token/datastore are intentionally excluded. No snapshot/whole-machine restore or separate recovered-host boot has been tested; off-Mac Restic recovery secret remains an owner attestation, not independent auditor access.

**First-party firewall scope change:** this repository must not integrate with named hosting-provider firewall APIs. An optional IPAT-owned Ubuntu node firewall control plane is proposed in [FIREWALL_CONTROL_PLANE.md](FIREWALL_CONTROL_PLANE.md), and a new `firewall-policy` Rust crate implements **in-memory non-executable** dual-stack proposal validation. Global host firewall changes require platform-scoped RBAC+ABAC, MFA, two-person approvals for risky changes, a dedicated privileged agent, independent out-of-band console access, full recovery rehearsals, safe nftables/K3s coexistence and auditable automatic rollback; none of those runtime privileges or actions have yet been implemented. Tenant accounts cannot gain `CAP_NET_ADMIN` or host firewall access by choosing a menu item. The existing external shared permissive security group remains an **environment constraint, not a product integration**, and MUST NOT be changed by IPAT.


### R4.9 original CWMP offline identity and replay admission

A pure, **non-networked** Rust `cwmp-admission` unit-testable module enforces exact synthetic pinned-client identity and immutable tenant binding, bounded parser/session/replay capacities, rejects duplicate device/cert and duplicate CWMP correlation IDs, and refuses a different peer to end an active lease. It deliberately exposes **no public trusted-peer constructor** until a correctly audited real TLS adapter exists. Simulator enrollment/identity tests do not prove mTLS, transport security, durable replay safety or physical ONT compatibility. Future public endpoints must uniformly deny all identity/tenant mismatches, accept only genuine mTLS cryptographic evidence, preserve persistent state after restart, implement actual CWMP retry semantics and redact serial/certificate values in audit. [Full scope](CWMP_ADMISSION_R49.md).


### R5.0 synthetic native USP trust boundary (real USP wire support pending)

A separate `usp-core` Rust test-only controller/domain module now models exact tenant-bound agent enrollment and pinned synthetic client SPKI identity, constrained read-only planning, bounded pending/replay and strict synthetic response correlation. Crucially `VerifiedAgent` and `TrustedOperator` have **no production-constructible public proof constructors**. A spoofed broker topic, response endpoint or tenant request header cannot be treated as proof when the real MTP is developed. The optional `usp-controller` binary binds only loopback **if explicitly enabled**, with health-only routing and blanket 503 for attempted USP/data requests; it has not been run on the live VPS. No real certificate/OIDC verifier, binary protocol, broker ACL, durable anti-replay, high-risk operations or physical agent tests are delivered. Read [R5.0 exact scope and known threats](USP_SYNTHETIC_R50.md).


## R5.1 — synthetic PostgreSQL schema isolation (new source; acceptance requires actual CI)

Initial lab-only `ipat_platform` + `ipat_ops` schema migration uses tenant-scoped composite device/subscriber keys, `FORCE ROW LEVEL SECURITY`, a restricted runtime role and deny-without-trusted-transaction-scope policies. Tests explicitly cover missing/invalid tenant context, cross-tenant writes, denied platform reads and restricted `TRUNCATE`. See [R5.1 precise scope and actual test procedure](POSTGRES_TENANT_R51.md). **No verified OIDC/session binding, safe runtime SQL pool, real customer records, live PostgreSQL node or production PITR are present.** A direct client that can issue arbitrary SQL/`SET LOCAL` is NOT automatically an authenticated tenant; role and connection admission remain prerequisites.

## R5.3 sealed job simulator and explicit production write prohibition
The synthetic `provisioning-core` enforces tenant + router scoped test-only actor/worker proofs, separate checker identity, bounded approval expiry, immutable idempotent proposal comparison and global per-router claim serialization. Expired leases are `Unknown` and retain the router quarantine; no recovery or executor is wired. Private proof fields have no production constructors. **These are synthetic security properties only**: no identity provider, durable database transaction/outbox, production approval audit, verified router ownership, encrypted credentials, real RouterOS diff or crash-resistant cross-node fencing is implemented. Real `BulkPppoeWrite` stays denied by `authz-core`. Scope and negative tests: [R5.3 review](PROVISIONING_SIMULATOR_R53.md).

## R5.4 synthetic job/outbox data boundary (not authenticated runtime)
The R5.4 lab migration force-enables tenant+POP RLS and grants `ipat_app_runtime` read-only SELECT on new jobs/outbox; no user-issued SQL write path or real worker exists. A separate NOLOGIN schema-owner trigger writes a redacted outbox row atomically after each allowed synthetic transition. Cross-tenant/POP router FKs, immutable plan digest, exact synthetic distinct approver names, one-hour approval TTL, maximum 60-second lease and global unresolved-router-UUID uniqueness are defense-in-depth **data constraints**, not an OIDC/MFA identity verifier or canonical device registry. Real high-risk approval identity, binding user membership/POP to transaction scope, per-service least privilege, durable publisher, reconciliation, audit and external effects require independent implementation and adversarial tests before network writes are possible. See [R5.4 test plan](POSTGRES_JOB_OUTBOX_R54.md).

## R5.5 production admission stop condition
The nonprivileged `deploy/scripts/production/readiness.py` checks only private source/GitHub/VPS hashes, key-only SSH, Mac FileVault, existing encrypted source-snapshot presence and simple host-readiness facts. Its return value is intentionally always `NO_GO`; it never changes host firewalls, externally managed shared rules, K3s or PostgreSQL. Independently tested console recovery, complete independently recoverable full host and database backups, dedicated IPv4+IPv6 effective ingress, signed high-risk change/rollback approvals and selected network/HA architecture remain mandatory manual gates. No arbitrary attestation fields, screen capture or user-controlled headers can override them. See [R5.5 evidence and stop conditions](PRODUCTION_INFRA_RECOVERY_R55.md).

## R5.6 disposable K3s and live-installation isolation
The actual Ubuntu 26.04 GitHub-hosted runner is the only target authorized by `k3s-ubuntu26-ephemeral-ci.sh`. Non-CI machines, existing K3s installations, unverified OS/architecture, public-address selection and unpinned downloads fail closed. The real ephemeral CI experiment does not add any inbound application service to IPAT's VPS; isolated snapshot/token/kubeconfig artifacts are not published. No external hosting-provider firewall API integration or mutable shared Security Group rule is included. Production admission remains `NO_GO` until real independent console/rebuild recovery, a dedicated effective dual-stack perimeter and signed ADR-017 CNI/network and datastore/rollback design have been independently verified. See [R5.6 lab and limits](K3S_UBUNTU26_R56.md).

## R5.7 K3s/nftables recovery findings
R5.7 confirms three security-relevant failure modes in disposable Ubuntu 26.04 QEMU tests: a new-host embedded-etcd restore requires custody of the original K3s server token; restored stale Node and pod objects can direct workloads toward a dead source node until explicitly reconciled; and systemd timer default `AccuracySec=1min` can make an apparently short firewall rollback nondeterministic. The repository now requires root-only token handling, explicit stale-node/pod cleanup, a newly created pod to prove runtime recovery after K3s restart, `nft -c` validation, an isolated IPAT test table, explicit dangerous-drill opt-in, and `AccuracySec=1s` with no randomized delay. These controls were actually exercised on disposable VMs. They do not replace independent live-console access, full live-host recovery, dedicated dual-stack perimeter verification or production approval.

## R5.8 synthetic-only K3s packaging boundary
Only explicit disposable GitHub CI runs bind the original Rust health-only app processes on their pod network. The separate native USP stub has no USP Record/MTP, and the Control API device route returns anonymous 401 regardless of fake tenant headers. Helm app templates remain ClusterIP-only, non-root, no token mounts/capabilities/host namespaces, read-only and default-deny application egress with smoke-pod-only ingress. A strict rendered-Helm validator rejects unsafe drift, and CI tests deliberate negative policy mutations. Cluster smoke traffic does not itself prove the selected CNI enforces every policy, and none of this authorizes a real VPS installation. See [R5.8 lab application boundary](K3S_APPLICATION_PACKAGING_R58.md).

## R5.9 local-only web preview (not an authentication perimeter)

The optional Rust browser status preview is absent unless explicitly requested,
and the executable masks it when binding to the K3s pod network. Default
security boundary is `127.0.0.1:3000`; the only approved preview path is the
authorized Mac's strict-host-key key-only SSH tunnel bound to
`127.0.0.1:48765`. Its CSP forbids external resources/inline scripts,
framing and forms; read-only status exposes no operational data or secrets,
and anonymous device requests still return 401. There is no pseudo-login,
trust in user headers or private tenant menu rendered to unauthenticated
users. NEVER route this through public ingress, proxy or alternate domain.
Production OIDC, real RBAC+ABAC, domain ownership, verified recovery and
IPv4+IPv6 isolation remain unverified and are not replaced by this preview.

## R6.0 hardware intake trust boundary and sensitive-field denial

A planned vendor/target row is NOT a discovered or assigned physical device.
The private laboratory dashboard displays only generic public test-family
planning data with an explicit zero real devices count. Browser GET requires
the already reviewed Mac-loopback-only SSH preview; default/K3s routers
return 404 and mutation endpoints 405. No private management IP, credential,
serial or subscriber info may be embedded in HTTP or source-controlled
fixtures. The independent offline Python intake tool uses an allowlist of
required metadata keys and protocol *candidates*, duplicate-key rejection,
bounded strict field syntax, sensitive-field/IPv4 pattern denial and exclusive
0600 write under an owner-only 0700 directory outside Git; the output is
ALWAYS marked unverified and unconnected. A credential-free local file must
never be interpreted as approval, secure tenant binding or proof of protocol
support. Actual physical enrollment and read-only probing require explicit
lab/tenant owner permission, dedicated least-privileged identity, isolated
reachable channel, audited review, exact firmware record and negative tests.

## R6.1 RouterOS initial physical-read safety

One customer router's reported model/version never proves physical
reachability or service support. The candidate REST probe requires
owner permission, separate isolated lab route confirmation, owner-Mac
run, *two explicit* real-GET environment gates, RFC1918 single target,
independent TLS CA/hostname verification and dedicated local mode-0600
netrc; it does not use admin credentials, skip certificates, perform
discovery, auto-retry or any HTTP write. Only /rest/system/resource
is allowed, and untrusted/raw response fields including serials,
secrets and addresses are not emitted. The allowed evidence file is
new mode-0600 outside Git. Data still cannot be exposed via the
unauthenticated lab UI; even a successful unreviewed probe does not
provide true OIDC/tenant binding or any write permission.
A qualified human must ensure router www-ssl is source restricted
and account policy is custom least-privilege (read,rest-api only
as compatible), unlike the overprivileged built-in read group.

## R6.2 RouterOS raw JSON/evidence trust boundaries

An authenticated HTTPS result is untrusted until independently
reviewed against the precise authorized device. The original Rust
domain bounds raw bytes and field cardinality, rejects duplicate
fields and mismatched exact reported model/architecture/version,
drops unapproved fields, and returns only explicitly unreviewed
metadata. The independent private evidence parser *rejects unknown
fields*, duplicate JSON keys, missing allowed fields, fabricated
promotion flags, unsafe HTTP methods/resources, wrong identity and
invalid time syntax. Syntax is explicitly NOT an authenticity
signature, authorization claim or proof of physical interoperability.

The additional Rust owner-local CLI validates only an absolute path
to a redacted, non-symlink mode-0600 evidence file in an owner-private
directory outside its source repository; output never reproduces
payloads or paths. Its success expressly keeps enrollment, tenant
trust and compatibility false. Python-to-Rust synthetic cross-contract
fixtures verify fake serial, IP and password suppression and refusal
to promote a forged tenant record. No actual router traffic is needed.

## R6.3 immutable SSH host key conflict before any router credential is sent

The customer-router public SSH endpoint is reachable and presents
a MikroTik-style SSH banner, but the currently presented RSA key
**does not match** the authorized Mac's prior pinned RSA key
for the exact endpoint. OpenSSH strict checking correctly aborted
before any authentication. Do not interpret a public key scan
or software banner from the same network path as proof of
device identity. No chat-disclosed device password was
transmitted, written to local files, injected into process
arguments or stored in source, and no host trust was overridden.
A changed key requires an independent trusted direct-LAN
identity comparison, owner acceptance of the exact device,
investigation of possible different NAT/port-forwarding,
and credential rotation using a separate trusted path.
A new no-credential, no-login, one-host SSH fingerprint
preflight plus mocked denial tests are in
[MIKROTIK_SSH_HOST_TRUST_R63.md](MIKROTIK_SSH_HOST_TRUST_R63.md).
No configuration-write permission or live physical feature
claim follows from an SSH host-key match alone.

## R6.4 safe SSH transport preconditions and no-login default

Actual owner-supplied router SSH credentials were never used
after the Mac detected an unexpected SSH host RSA key.
R6.4 adds a **disabled-by-default** key-only SSH first-read
helper limited to the exact initial DEV-08 board/version and
a fixed three-field resource read. Its single untrusted
public RSA keyscan cannot authorize access: the fingerprint
must match an independent, owner-controlled direct-LAN
verification file with mode 0600 in a mode-0700 directory.
An existing historical key mismatch requires a separate
explicit operator opt-in. The helper uses a disposable
one-host exact public key pin, `-F /dev/null`, strict host-key
verification with only RSA SHA-2 algorithms, a dedicated
mode-0600 local SSH identity, BatchMode, public-key-only,
agent disabled, no passwords, no proxy, no port forwards,
bounded timeout and bounded command output. It never
rewrites historical known_hosts, stores a credential in
CLI args/CI/Git, or changes device configuration.

Offline --requirements and --preflight never contact the
router. No real --read may occur until the owner has
independently verified physical identity, safely rotated
the already-shared password from trusted management,
provided explicit non-disruptive customer permission,
established recovery and a restricted short-lived key.
Syntactically valid local fingerprint/evidence files
are only asserted inputs; they are NOT cryptographic
proof of the stated trusted-LAN origin or a verified
tenant/device assignment. Malformed model/version,
unapproved method or forged enrollment evidence is
rejected by the Python sanitizer and separate Rust
closed-schema verifier. All physical tests remain
NOT RUN until trusted human evidence is reviewed.

## R6.5 temporary customer router password authorization and alternatives

Owner permission for temporary password login does NOT authenticate
a server whose RSA SSH host key unexpectedly differs from the
previously pinned owner-Mac record. No credential should be
transmitted to that public endpoint until the actual physical
router is independently identified from a separate trusted
direct-LAN WinBox/console path and the discrepancy is explained.
The separate new owner-Mac keypair permits creation of a
restricted SSH read-only identity **after** that verification;
never use the already disclosed general-purpose password.
Default binary API-SSL and HTTPS availability checks were
unauthenticated and did not find a verified-reachable TLS endpoint.
TR-069 provisioning requires a separate authenticated and
TLS-trusted client-to-ACS path. No provider firewall,
RouterOS management service, account or production
cluster was changed. See
[the R6.5 operator access protocol plan](MIKROTIK_CUSTOMER_R65_PREP.md).

## R6.6 CWMP first read RPC, sealed session and private HTTP trust boundary

The only newly generated ACS RPC is the
allowlisted non-mutating `GetParameterValues`
for `Device.DeviceInfo.SoftwareVersion`.
Parsing rejects SOAP/correlation/method/type/
namespace/oversize/DTD violations and sanitizes
CWMP faults to numeric codes without logging
untrusted freeform fault strings. Rust admission
may advance only a sealed already-admitted
synthetic peer/tenant/opaque lease after
a genuinely empty POST; session evidence
never enables enrollment or config writes.
The running Rust gateway is **not yet an ACS
device endpoint**. It starts only with
a local explicit opt-in, binds exclusively to
127.0.0.1, and always denies external-style
`/cwmp` requests, including spoofed
`x-client-cert-verified` / tenant claims.
The safe synthetic parser route never issues
SOAP responses and echoes no device identifiers.

Threat-model blockers remain independent
real TLS CA/mTLS cryptographic CPE proof,

trusted operator enrollment, anti-replay
durable multi-pod ownership, resource
exhaustion limits at TLS edge, real HTTP
timeout/keepalive correctness, redacted
auditing and exact per-firmware physical
interop. No live TLS certs, public listener,
real subscriber secrets, hosted perimeter,
PostgreSQL or K3s were changed.
See [R6.6 acceptance boundaries](ACS_CWMP_R66.md).

## R6.7 pembuktian nyata mutual TLS dan penolakan identitas palsu

Biner Rustls TLS1.3 mTLS yang benar
hanya membuka 127.0.0.1:3433 setelah
opt-in eksplisit dan sertifikat
CA klien/server+private key yang sah
dari folder pemilik pribadi. Verifier
harus menerima CA tepercaya,
memvalidasi masa berlaku serta
EKU clientAuth; tanpa sertifikat,
CA klien palsu dan sertifikat
serverAuth di sisi klien ditolak.
Klien juga menguji verifikasi
CA/DNS server tanpa mengizinkan
TLS trust bypass. Berkas hanya
dimiliki akun nonroot, parent 0700,
file 0600 dan no-symlink/hardlink.
Sertifikat sementara dikunci dalam
folder tes sekali pakai, dibersihkan
setelah server tes berhenti.

**Batas keamanan yang belum
terpenuhi:** ini autentikasi
*transport berbasis CA*, BUKAN

otorisasi device/tenant. Bahkan
sertifikat valid CA tidak
boleh mengakses endpoint /cwmp
(503). Tidak ada koneksi bridge
kepada sealed Rust synthetic
AuthenticatedPeer, belum
ada pin SPKI spesifik perangkat,
sertifikat dicabut belum diuji,
belum ada private production
issuer/secret rotation, trusted
operator approval, persistent
session atau model firmware
interop. Tidak ada public ingress,
firewall maupun customer secret
yang diubah. [Kontrak R6.7](ACS_MTLS_R67.md).

## R6.8 role-preview UI dan API deny/default wajib dibedakan

R6.8 menyediakan tiga
tampilan UI berbasis
data sintetis yang semua
dapat dipilih dalam satu
browser lab privat.
Ini sengaja **bukan**
RBAC atau akun
platform/tenant sungguhan.
Privat bukan pengganti
login OIDC dan cookie
tenant yang benar.
API platform/tenant/NOC
masih menolak semua
GET/POST/DELETE dengan
HTTP 401 bahkan jika
Authorization, Host,
X-Tenant-Id dan role
palsu dikirim klien.
Endpoint browser preview
tidak ada pada K3s
public-pod bind,
memakai CSP same-origin

dan no-store, hanya
membaca endpoint status
laboratorium dan tidak
mengirim data pelanggan.

Pure dashboard policy
menguji isolasi peran
platform vs tenant dan
POP, tidak mengizinkan
mass-write. Policy
belum dipakai dalam
runtime sebelum
token OIDC/MFA
terverifikasi, domain
diikat ke membership
DB, FORCE RLS,
session CSRF dan
audit action diuji.
Lihat [kontrak R6.8](DASHBOARDS_R68.md).

## R6.9 verified signature is not tenant or administrator authority

The new pinned RSA RS256 JWT verifier requires exact issuer,
single audience, fixed key ID, time-bounded exp/nbf/iat,
short token lifetime and rejects asymmetric/symmetric
algorithm confusion, forged signatures, JOSE remote
key resolution and malicious identity claims.
No token-provided role, group, tenant or POP
is trusted or promoted to RBAC subject.
Operator-local public-key file is owner-only
in an owner-only directory, opened using
no-follow protection. The private probe
does not log or echo verified subject
and exists only by explicit loopback opt-in.

A cryptographically valid JWT MUST NOT be
mistaken for authenticated Keycloak login,
verified MFA, trusted active membership or
business authorization. Existing platform,
tenant and NOC business endpoints remain
401 even on signed token and spoofed headers.
Real Keycloak discovery and JWKS provenance,
key rotation/revocation, OIDC PKCE/nonce/state,

host-only tenant cookies, CSRF, operator-
authorized memberships and database-backed
resource/POP-specific RLS remain unimplemented.
No public port, provider firewall or
production secrets change in R6.9.
See [identity proof and blockers](IDENTITY_OIDC_R69.md).

### R7.0 tenant identity schema candidate, no runtime entitlement granted

R6.9 PinnedIssuer only validates an RS256
token signature, not authorization.
New R7.0 synthetic PostgreSQL candidate
separates approved identity membership
by tenant+issuer+subject+role from
exact POP grants via composite FK,
and platform principals into an
independent table. All three tables
have ENABLE/FORCE RLS and grant the
existing application DB runtime role
**NO access**. Tests reject runtime
read/write/enumeration, wrong-tenant
POP assignment, unapproved role,
structural expiry and missing approver.
Superuser fixture in disposable CI
is NOT the intended operational
operator-approval mechanism.

No online actor can currently read
the membership tables or create
trusted DashboardSubject from them.
JWT custom roles/tenant claims,
Host or X-Tenant-ID still must be

ignored for privilege. Before any
enablement: trusted IdP OIDC
discovery/JWKS pin rotation, PKCE,
MFA assurance, independent approval,
backend policy, RLS session-scope,
audit, CSRF and custom-domain
ownership verification.
[Exact R7.0 tests/gaps](DASHBOARD_MEMBERSHIP_R70.md).

### R7.1 native OLT read-only boundary and protected firmware gate

ZTE C320 parsing runs offline on bounded text; it rejects
control characters, unexpected table layout and duplicate slots.
The offline importer checks exact filenames, absolute owner
directory 0700, file mode 0600, no symlinks/hardlinks, rechecks
file identity with O_NOFOLLOW and never echoes raw CLI transcripts.
The binary has NO live equipment transport, firmware image
upload, dangerous configuration command or web listener.
Even all firmware check flags only mark HUMAN_REVIEW_ONLY;
the flags themselves are not trustworthy signed attestations.
Actual write automation must additionally prove exact
device/card/version compatibility with authenticated operator
and maker-checker authorization, tested restoration, onsite
independent rescue and maintenance/customer impact controls.
Do not distribute customer firmware images or management secrets
in Git/chat. This feature does NOT bypass seven blocked
live-production infrastructure safety gates.

## R7.2 ZTE C320 offline vendor file-integrity gate is not an authorization gate

A separate Python standard-library
tool can calculate one local SHA256
from an operator-private exact-name
image (mode0600, no links, bounded
size, O_NOFOLLOW) and compare to
the checksum copied by the operator
into a second private file.
It is explicitly opt-in, refuses
root, and has no network/library
support for firmware execution.
Output can prove **only local
arithmetic file integrity**,
not independently verified ZTE
image provenance, compatibility
with C320 cards, disaster recovery,
maintenance approval or physical
interoperability. All firmware
execution flags are permanently
FALSE. Official vendor release
notes, permitted image source,
cryptographic vendor evidence
when available, two distinct
approvers, real host backup/

restore and onsite console
remain independent human gates.
See [R7.2 preflight](C320_FIRMWARE_INTEGRITY_R72.md).


## R7.5 explicit scope of allowed domain deferral (2026-09-27)

Only domain OWNERSHIP VERIFICATION and isolation of cookies/sessions
ACROSS DIFFERENT CUSTOMER HOSTNAMES are deferred to M2.
The existing developer/operator preview stays in owner-controlled
SSH localhost; it contains NO real customer records, credentials or
authenticated customer workspace and uses only no-store GETs.
Never replace this constraint with a publicly accessible shared
login/tenant UI. No use of Host/X-Forwarded-Host to select a trusted
tenant, regardless of temporary deployment phase.

Tenant record/query/job/export/POP secrecy and deny-by-default
API/menu/backend/database enforcement (FR-001/002/003) remain MUST
BEFORE ANY multi-tenant data is exposed. Existing RLS candidate and
synthetic role tests do NOT prove production isolation. Early physical
C320 reads remain isolated operator-managed lab activity, NOT
authenticated tenant device enrollment, and require independent
host verification, read-only permission and backup.


## R7.6 explicit management-host and issuer confusion threat

hub.example.invalid is currently a known management SSH destination but
the owner also intends it as a Fadly tenant CUSTOM domain later.
NEVER imply host DNS controls verified tenant membership, or repoint
the existing management SSH alias while external recovery gates
remain blocked. A hypothetical shared host serving SSH and HTTPS
is not approved public security architecture. A forged Host,
X-Forwarded-Host or extra OIDC tenant/role/domain claim must not
change actor tenant or POP; token issuer+subject must match exact
approved server-side membership source. The new pure R7.6 policy
function is only a candidate-row reference; there is NO approved
DB provenance adapter, real MFA, commercial cookie design or
actual real-user authorization endpoint yet. No prod exposure.


## R7.7 restricted identity-query threat closure (partial, synthetic)

Disposable SQL requires NOLOGIN/NOBYPASSRLS function owner and
NOLOGIN query-only role; default PUBLIC function EXECUTE is revoked
within one transaction and no production app role is granted access.
Two SELECT-only identity-table RLS policies apply only to the
non-login function owner. Exact issuer/subject/tenant/role/POP,
revocation, expiry and suspended-tenant checks deny cross-tenant
lookups in ephemeral DB. Function uses a fixed pg_catalog-first
search_path, schema-qualified static SQL and exposes only approver
label and expiry. A future reviewer must threat-model SECURITY
DEFINER, authenticate approvals, supply verified IdP subject/MFA,
protect dedicated connector credentials and enforce session
revocation; this slice does NONE of those real app tasks.
Existing public-domain/SSH recovery and physical OLT gates remain
blocked; no actual user/business endpoint is enabled.


## R7.8 opt-in private signed-JWT-to-PostgreSQL threat boundary

The new private lab requires separately enabled nonroot OIDC and
restricted DB flags; production K3s cannot mount its route.
A verified token yields only issuer+subject; requested UUID,
fixed role and POP are untrusted and independently exact-matched
in the RLS-protected narrow PostgreSQL function per request.
Runtime DB config requires a dedicated role, owner 0700 folder
and O_NOFOLLOW 0600 one-link secret file, with a single ABSOLUTE
Unix-socket target, never a plaintext TCP listener.
No role/custom domain can come from Host/forwarded headers or
JWT extra claims. Even a successful candidate returns NO real
subscriber/device data, MFAVerified=false and business_access=false;
all real business APIs remain HTTP401. The synthetic disposable
CI reader must NEVER be copied to real database/server and
approver-label alone does not prove authentic approval/MFA.
Production secrets manager, trusted connection lifecycle,
session revocation, JWKS pin rotation, MFA and whole-VPS backup
are still mandatory independent security gates.


## R7.9 no-physical-cable and no-provider-firewall threat clarification

A remote SSH read-only C320 session is allowable
without a local serial/L1 connection only where
operator-authorized separate read-only credentials,
independently checked SSH host identity, PRIVATE
management VPN/route and encrypted private
capture are proved. The script rejects public
OLT IPs, ambient ssh config, ssh-agent/password,
host-key acquisition from the same untrusted
connection, proxy commands/forwarding and all
other CLI commands. Its local boolean assertions
alone are NOT an independent audit. Actual device
firmware's SSH key and noninteractive exec
capability remains UNVERIFIED. Firmware/provisioning
writes continue to require separate recovery,
version-specific tests and maker-checker approval.

A VPS that has no optional host firewall MAY
participate ONLY when private listener binding
and authorized encrypted VPN/isolated network
ingress are independently enforced and probed.
The external provider security-group API is
NOT an application dependency. Avoid raw
public UDP 8472 VXLAN, open Kubernetes
6443/10250, leaked K3s tokens, accidental
cross-provider etcd, unmanaged dual-stack
ingress, network overlap and fake privacy
claims behind a public route/NAT. Independent
out-of-band rescue and offsite complete restore
remain actual prerequisites before live K3s.


## R8.0 private JWT→actual bounded device inventory threat boundary

The new private lab inventory handler refuses missing
or invalid pinned-signed JWT (401), unsupported
role/wrong tenant/POP (403), and DB unavailable (503),
with no bearer, issuer, approver or unscoped data
in its response or logs. Host and extra JWT claims
cannot select a tenant/role or bypass sealed SQL.
A dedicated NOLOGIN function owner receives
targeted FORCE-RLS SELECT on the device table
only; its function rechecks SAME-tenant AND
same-POP conditions against active membership,
explicit POP grant, unrevoked and unexpired status.
A separate NOLOGIN EXECUTE-only query role
receives no additional table SELECT.
An independently provisioned restricted login
is created ONLY on disposable CI Postgres.
The caller still has to prove its own pinned
JWT and independently trusted MFA+enrollment
before actual users; knowing arbitrary
issuer+subject would make unrestricted
direct function access a membership oracle
if future operators granted query role to
untrusted actors. NEVER expose it directly.
A single SQL statement/snapshot and
post-query Rust capability check reduce
TOCTOU risk for this virtual lab,
but production still requires session
revocation and trusted IdP claims policies.
R8.0 remains READ ONLY and lab-loopback-only,
not a production RBAC acceptance test.


## R8.1 structural protobuf is NOT cryptographic device identity

Threat: untrusted USP `from_id`, `to_id`,
header message ID or even a valid
GetResp protobuf could impersonate
a registered physical agent. R8.1
unconditionally treats all of them
as claims, never security principal.
A single remote binary fixture
may be parsed only in an explicitly
opted-in private nonroot loopback
testing process and returns zero
identifiers/parameter values in HTTP.
Faux HTTP X-Agent-Id and tenant headers
are ignored. Explicit protobuf wire
pre-scan forbids duplicate scalar/
oneof and unsupported fields,
unexpected Msg body, session
records, reported signatures/TLS
and unknown extensions. Rust enforces
bounded body/nested counts.
K3s-bound mode mounts only
non-operational health; untrusted
real `/v1/usp` remains HTTP503.
Token/certificate verification,
real MQTT broker topic tenant ACL,
TLS binding, durable replay across
workers, real message encryption/
segmentation, approved controller
session and physical agent capability
verification are NOT IMPLEMENTED
and MUST precede any real USP
operational endpoint or upgrade.


## R8.2 synthetic CWMP SOAP HTTP-only threat controls

Untrusted SOAP source fields, HTTP Host, tenant headers
and forged mTLS claims NEVER prove a real CPE identity.
The local proof permits exactly one fixed fake CPE
manufacturer/OUI/product/serial/event/correlation;
the read-only request has one fixed allowed path
and fixed ID; the reply parser rejects fake correlation,
duplicate/unrequested/secret paths and all writes.
No raw fake SOAP identity, returned SoftwareVersion
or fault private text enters HTTP output.
Global HTTP 64 KiB bounds include ALL newly
mounted routes (a discovered initial draft
mistakenly put the Axum layer before new
routes; the new HTTP oversize test caught
and caused its correction). A second explicit
opt-in, loopback-only bind, K3s absence
and unconditional real `/cwmp` HTTP503
prevent silent device enrollment.
This IS NOT device-level mTLS proof
or production session replay protection.


## R8.3 device adoption threat-model refinement and trusted barriers

Threats: fake online state; unauthorized ISP or
POP data; forged Host/role/issuer; CSRF against
a user-visible local demo; credential capture
in a prototype registration form; unsafe
production registration or private IP leakage;
replayed registration of conflicting devices.
Controls: fake-only LAB-/VIRTUAL-
strict input, no IP/serial/password fields
in the anonymous demo, same-host +
same-origin + X-IPAT-Demo-Only writes,
2 KiB bounded JSON, no real network
calls, statuses always UNKNOWN and
NOT_MEASURED. Persisted drafts require
a genuine PINNED SIGNED RS256 access
token and own separately DBA-approved
current tenant-admin membership for
metadata-only inserts, or own admin /
NOC exact approved POP membership for
restricted reads. Separate nonroot
0600 owner-only config files and
Unix socket-only dedicated reader/
registrar service accounts; roles
are EXECUTE-only with no direct
tenant/device/subscriber table access.
Functions have fixed search_path,
forced RLS table/membership policies,
active tenant/expiry/revocation
checks and strict RFC1918-only
optional management IP.
Registration is repeat-idempotent
ONLY when identical metadata;
all new drafts default pending,
unknown and unmeasured, with NO
automatic online/approval transition.
These are a lab proof boundary:
the DB definer function relies on
the caller's genuine signed JWT
verification and DOES NOT itself
prove MFA or trusted human
enrollment. Live production and
real device writes remain NO_GO.


## R8.4 reviewer threat model and MFA assertion limit

Threat: a device requester with tenant_admin
(or even ALSO security_admin) must not
self-approve metadata; enforce exact issuer+subject
mismatch inside the trusted PostgreSQL function.
Threat: JWT `role`, `tenant_id`, `amr`
from an unsigned/unpinned token or proxy
Host/header never grants review. The verifier
accepts `signed_mfa_claim` ONLY from an
RS256 JWT meeting pinned issuer/audience/key
and short lifetime, with exact bounded
`amr: ["mfa"]` semantics. This is NOT evidence
a real user's upstream MFA has been configured
or actually used; production deployment remains
blocked until audited actual IdP proof.
Threat: revoked reviewer, wrong tenant, duplicate
or racing review, changed idempotency,
tampered reason, and untrusted output are
denied through SQL role separation, FORCE
RLS, row lock, atomic append-only audit,
bounded validation and safe HTTP output.
No firmware/physical adapter may consume
metadata review approval as permission
for high-risk operations. Reviewer routes
are absent by default, on public K3s and
without separately restricted nonroot
Unix-socket DB identity. Independent
whole-host/PG recovery remains a
production blocker.


## R8.5 actual human identity vs signed amr threat boundary

An ACTUAL HUMAN with provisioned independent MFA
and approved IdP enrollment has NOT yet
authenticated to the owner's production IPAT.
An attacker might supply an independently
self-signed `amr:mfa` token, a different
kid/audience/issuer, fake high-privilege
role/tenant claims, a symlinked or group-readable
RSA public key, a forged Host or stale/overlong
token. Original Rust standalone nonroot
`oidc-mfa-preflight` verifies EXACT pinned
RS256 issuer/kid/audience/exp/iat/nbf,
<=15-minute lifespan and bounded signed
`amr:mfa`, with private safe public key
provenance required. Reject interactive TTY
bearer input, >8KiB bearer, root runtime,
unrequested opt-in, insecure owner PEM mode
and symlinks/hardlinks; no claim/token/subject/
role or tenant is printed or authorized.
Even a PASS is NOT real independent operator
MFA enrollment, authorization, login or
permission to contact equipment.
Approve and verify real human
MFA via the IdP before enabling
any actual customer device or admin APIs.


## R8.6 browser OIDC PKCE proof threat boundary

Untrusted login redirects, token headers, Host, state
replay and leaked authorization codes are explicitly
negative-tested. Cryptographic OS entropy produces
three independent random 256-bit state, nonce and
PKCE verifier; SHA256 S256 sends ONLY challenge, never
verifier. Pending browser state is capped at 16,
TTL 300 seconds, cookie HttpOnly/SameSite=Lax,
callback Host and cookie/state match enforced
in constant time, state consumed before returning
503. No subject, tenant, auth code, verifier or
credential appears in HTTP body or logs.
This lab cookie intentionally lacks Secure on a
strictly localhost HTTP-over-owner-SSH-tunnel proof.
It cannot be reused as the customer/public cookie.
Independent approved actual TLS, signed nonce-checked
ID token, confidential OAuth exchange, session
rotation, CSRF defenses, secure __Host- cookie and
MFA enrollment remain unimplemented external gates.


## R8.7 OIDC ID-token-to-access-token mix-up threat barrier

The offline original Rust BFF verifier rejects a
signed ID token that is not explicitly for the
approved browser client even if its issuer is
correct, rejects an access token for the wrong
IPAT service, and verifies signed identity
agreement, nonce and SHA256 at_hash in constant
time. Both tokens require valid independently
pinned RS256 kid/signature and explicit bounded
signed MFA; ID auth_time limited to five minutes.
No untrusted jku/x5u, session minting or
implicit tenant/POP claims. These checks must
remain isolated until real human MFA provider
semantics and confidential HTTPS code redemption
have been separately verified. A synthetic signed
test identity alone is NOT a real MFA event
and cannot unlock Device Manager or equipment.


## R8.8 opaque browser session threat model, actual enforced subset

Threats: forged signed MFA, token substitution,
misbound nonce/access token, stolen browser cookie,
CSRF, cross-company/POP replay, stale membership
and stale session after token expiry.
New separate original Rust code requires
R8.7 pinned genuine signed pair BEFORE
a synthetic session can be requested,
issues 256-bit OS-random cookie and
independent CSRF, stores only digests,
constant-time compares CSRF, validates
bounded real JWT expiry, enforces five-
minute idle plus capacity, supports
revocation and fail-closed rotations.
UNMOUNTED actual Rust/Pg bridge requires
a separate genuine sealed SQL tenant/POP
lookup on issue AND every synthetic
read/write; untrusted JWT role/tenant
cannot bypass SQL. Actual disposable
PostgreSQL two-ISP regression and
ephemeral genuine RSA token-pair tests
are CI admission gates.
REMAINING: independently validated
live IdP confidential HTTPS exchange,
real human MFA and correct provider
claims, actual TLS/Secure-cookie delivery
and strict origin verification at
real router, durable HA/revocable
server sessions, audit and real
device enrollment. No live app
route was changed to permit access.


## R8.9 unmounted session-backed candidate read threat model

Threat: a stolen/stale session or forged
tenant/POP selector could list a different
ISP's devices. Control: original identity
cookie authenticates only the verified
issuer/subject, and each request also
executes current sealed PostgreSQL exact
membership and POP-bound list within one
database snapshot. No cached client role,
untrusted Host tenant, broad implicit owner
grant, direct table access, management IP,
credential or invented health data are
included. Deny missing/untrusted origin,
expired cookie, missing/revoked/expired
company membership, wrong role or POP.
A single real user may separately hold
membership in two companies: access to
each MUST depend on its separate
current approved database grant.
The synthetic signed MFA lab issuer
IS NOT actual independently verified
human identity/MFA. This code MUST NOT
be mounted on a public/device listener
or given real privileges before the
confidential OIDC code flow, safe HTTPS,
approved membership enrollment and
audited real login are verified.


## R9.0 first real OLT network contact: plaintext Telnet and spoofed banner

Threats: public TCP321 is unencrypted; the endpoint might be
NAT/port-forwarded, impersonated or an unexpected firmware/service.
Neither an IAC negotiation nor an untrusted 'ZTE' text banner
proves hardware model, host identity, account scope or health.
An actual private VPS TCP TIMEOUT further prevents claiming
the control-plane worker can reach this site.
New tested operator-only preflight enforces exact numeric global
IPv4, TCP321, nonroot explicit consent, exactly one socket,
at most 512 inbound bytes and ZERO outbound application bytes.
Output is sanitized to booleans/UNKNOWN; optional export is
outside Git in owner 0700 directory and exclusive 0600 file.
NO credential, raw banner, device API, CLI or secret store.
No production/public dashboard is authorized by the observed
public Telnet endpoint. Use independently validated encrypted
site-management routing or actual authenticated vendor
SSH/SNMPv3 if supported, plus MFA/approval, before real read.


## R9.1 threat boundary: metadata approval must not become device access

Threats include treating a reviewed inventory row as permission to
contact hardware, stale secure-path evidence, silently replaced
device identity, privilege escalation through a browser cookie,
cross-tenant evidence reuse and a reviewer fabricating health.
Controls: four explicit append-only expiring gates, exact same
independently approved security reviewer identity, active own tenant
and membership checks, forced RLS, separate NOLOGIN owner/EXECUTE
roles, idempotent evidence requests and latest-verdict fail closed.
The safe session projection omits management IP, raw evidence,
attester identity and credentials. connectivity remains unknown,
health remains not_measured and last_verified_at remains NULL.
Even read_probe_eligible=true performs zero network I/O and cannot
authorize firmware or write operations.


## R9.2 permanent request is not device authorization

Readiness, metadata approval and an authenticated
session are all independent mandatory conditions.
An own-tenant exact POP NOC session with correct CSRF
may only propose one immutable, PRIVATE, nonexecutable
request; the SQL function separately revalidates all
conditions at insert time. Dedicated owner/EXECUTE
and reader NOLOGIN role separation, FORCE RLS,
same-transaction audit, unique per-candidate
idempotency, no UPDATE/DELETE and always-NULL
published_at prevent this software milestone
from becoming a device-write or network-execution
route. Later blocked/expired evidence cannot
be overridden by any historical intent;
future worker MUST revalidate independently
before physical I/O. No real credentials,
OLT public Telnet, management addresses,
evidence hashes or reviewer details are
exposed to the proposed browser-facing API.

## R9.6 production-like OLT protection and lab planner boundary

Treat owner DEV-01 as actively serving distribution and subscribers.
No unauthenticated Telnet public endpoint may accept even temporary
management passwords, nor may public TCP banner imply trusted hardware.
The R9.6 synthetic lab planner rejects unknown fields, physical
addresses and raw secrets; same-origin loopback and explicit demo
header are NOT production identity or authorization. No network
actuation, credential storage, dispatch, device adoption or firmware
function is attached. Real privilege requires signed session/MFA,
fresh DB tenant+POP membership, maker/checker and secure route.

## R9.7 owner tenant draft authorization (DISPOSABLE LAB ONLY)

Migration 0010 rejects public Telnet method and RouterOS6 WireGuard,
excludes all keys/addresses/credentials, checks active own tenant-admin
membership and exact own candidate POP at insert and listing time,
uses FORCE RLS and separate NOLOGIN SECURITY DEFINER owner/EXECUTE,
and writes a unique same-transaction immutable audit. Identity claim
text alone is never authentication; external signed OIDC MFA plus fresh
opaque session and independent authorizations are mandatory before
any mount. No actual VPN worker or public device dispatch exists.

## R9.8 BFF proposal restrictions

No public or lab HTTP route invokes R9.8 draft proposal. It denies
missing trusted origin, CSRF and stale or incorrect signed-session
identity via existing sealed vault+fresh restricted member lookup;
SQL migration 0010 repeats own active tenant+candidate POP. Genuine
live IdP/MFA and actual separate writer provisioning have NOT been
end-to-end verified; this remains unmounted and lab-only.

## R9.9 disclosed temporary OLT credentials and direct-root request

Owner-supplied default/factory OLT credentials must be considered
compromised after chat disclosure. Never transmit them on currently
exposed public plaintext Telnet, or copy into repository or logs.
Recommend prompt rotation via trusted site console/isolated network,
removal of WAN-facing Telnet forwarding under console-backed change,
and dedicated restricted read-only credentials kept exclusively in
an approved encrypted local/managed secret store. No actual changes
were made to live C320, MikroTik, firewall or root SSH policy.

Existing effective SSH lab hardening snippet explicitly denies root
SSH (`PermitRootLogin no`), while existing key-authenticated nonroot
`openai` remains reachable and has sudo-group membership. Root
shell via interactive sudo is preferred to restoring direct root SSH.
Do not switch `PermitRootLogin yes` or make emergency SSH/firewall
edits before independent actual console login and rollback proof.

## R9.10 legacy ZTE private SSH compatibility risk

The observed private SSH server offers weak legacy ssh-rsa host-key
signature and CBC cipher suites; no global OpenSSH policy downgrade,
known-host verification bypass, SSH-DSS or public Telnet credential
transport is authorized. A narrowly scoped per-process lab-only
compatibility invocation negotiated to host-key verification, then
stopped without credentials. Independently verify actual OLT RSA
SHA256 fingerprint using trusted local console/site inventory and
prove private last-hop trust BEFORE even the proposed temporary
account can be used. Rotate user-shared factory credentials on a
trusted channel before enrolling an actual read-only account.

## R9.11 bounded private SSH physical preflight and dashboard gates

A real owner-Mac credential-free legacy SSH handshake is permitted as
historical evidence only, under a per-run explicit opt-in, exact
private host+port, and fixed timeout. Process-local ssh-rsa/AES128-CBC
compatibility must never be reused globally or with disclosed factory
credentials. Unauthenticated server key is UNTRUSTED pending
independent owner verification. Private lab JSON/BFF shows false
for all admission gates, zero device commands and no automatic
provisioning. Do not use this preview as genuine tenant auth.

## R9.11 separate-private-port canary control

Parallel canary `127.0.0.1:3002` requires explicit opt-in and
rejects OIDC, scoped identity, registry/reviewer and public K3s
settings; it may NEVER be treated as Tenant Admin authentication.
The normal production/public API does not mount its physical
historical evidence route and remains deny-by-default. Do not bind
an alternate public hostname or create provider firewall changes.

## R9.11 canary runtime observed security controls

On actual owner VPS, user service showed NoNewPrivileges=yes,
ProtectHome=read-only, ProtectSystem=strict, MemoryMax=256MiB,
CPUQuota=20%, and only 127.0.0.1:3002 listener. No root or firewall
changes. Genuine business endpoints returned HTTP401; historical
physical evidence GET HTTP200 is PRIVATE LAB ONLY and POST 405.
Factory C320 credentials were NEVER used by this dashboard or VPS.

## R9.12 simulated tunnel wizard is NOT site authority

R9.12 private lab CSRF/loopback validation does not substitute for
real tenant MFA. Every option is labeled synthetic; even all-positive
simulation returns BLOCKED for real owner identity, site plan,
independent approval and hardware SSH identity. Strict deserialization
refuses injection of real endpoints or secret material. No network
executor is bound and no credentials are retained.

## R9.13 legacy read-only interop remains gated

A narrowly scoped, explicit RSA host-key / AES128-CBC SSH invocation
may be prepared offline for observed older ZTE compatibility but MUST
only follow independent fingerprint proof, restricted dedicated
public-key account, approved private route and live no-impact gate.
Factory/default privileged accounts are rejected by the first-read
collector. The actual current VPS route lookup is DEFAULT_ROUTE_ONLY;
never conclude an RFC1918 destination is isolated merely because
`ip route get` returns a route. No weak SSH client setting is global.

## R9.13 owner-only ephemeral encrypted reverse SSH transport check

A bounded zero-credential reverse Unix-socket port forward from owner
Mac into the existing nonroot VPS demonstrated private SSH banner
reachability. Unix socket parent is 0700, VPS SSH host trust remains
strict, and the relay was stopped/deleted. No public TCP listener,
provider firewall change, SSH global downgrade, RouterOS alteration,
OLT login or factory-password transport occurred. This is only a
credential-free LAB transport observation: trusted final hop,
independent OLT RSA identity, MFA and owner change approval remain
NOT VERIFIED, therefore all actual remote read operations denied.

## R9.14 physical site evidence storage separation

Physical site evidence digests only, no actual raw secrets, addresses,
credentials, keys, routes or job payloads, are stored under independent
append-only FORCE RLS PostgreSQL role. Caller must authenticate via
real signed OIDC MFA outside SQL, which repeats live approved
security_admin own tenant and independent applicant/reviewer.
Projected six-gate metadata stays nonexecutable even if all synthetic
values are set verified; revoked/expired latest gates fail closed.

## R9.15 no central push; private/public route semantics

Site A MAY create/rotate only its own listener/peer after genuine
reviewed authorization. Router B changes stay at Site B in an
owner-controlled console/GUI import path; dashboard never sends
configuration to the remote router. Reject shared subnet overlaps,
extra fields/credentials, unverified private endpoints and unbounded
peer routes at preflight. Site A and B must each custody their own
private key; only public peer material is passed in future pairing
workflow. No default route, broad RFC1918 routes, PPPoE modifications
or local customer VLANs in generated minimal management peer plans.
Current lab plan returns zero network actions and no configuration.

R9.15 bounded direct-private point-in-time VPS handshake reached the
owner-reported OLT SSH transport without credentials/commands and
stopped at UNVERIFIED RSA host key. Repeat observation via separate
sources is not OOB proof. No privileged OLT login until independently
obtained console host RSA public key is matched, site last-hop trust
is evidenced, account authorization is separately bounded and live
baseline/recovery is recorded. Direct/private does not bypass these
gates or require an unnecessary tunnel.

R9.15 owner-Mac prior RouterOS endpoint's pinned SSH key no longer
matches the network-presented host RSA key. An attempted batch-mode,
publickey-only version query stopped at SSH host key rejection before
authentication. No host pin override, password retry or router action
is authorized until independent trusted console verification of the
router identity; do not assume it is the exact C320 site gateway.

R9.15 offline pairing preview accepts ONLY distinct canonical 32-byte
WireGuard public keys and validated private/public topology. All
Site B RouterOS review commands are disabled; a site owner must
explicitly apply changes on B, under independently reviewed rollback.
Never capture Site B's WireGuard private key or accept default/wide
AllowedIPs exported by version-dependent RouterOS tooling.

## R9.16 DEV-only Site A X25519 public key and no-push peer review

Actual owner VPS generated a dev-only nonroot X25519 keypair entirely
inside owner-only 0700 outside-repository folder (key files 0600).
The private key never enters browser, chat, repo or B peer package.
No production secrets backup/vault is verified, so this dev key is
NOT acceptable for active live-tenant WireGuard pairing. The lab
Rust public endpoint opens only a fixed `public.key` filename with
no-follow/owner/mode constraints. Matching backend accepts strictly
PUBLIC B key, canonical IPv4 narrow routes and no unknown fields,
returning disabled manual B review only. Public key exchange is NOT
identity authentication; independently verified B identity, signed
Tenant Admin MFA, true site reachability, approved firewall policy,
audit/rollback and OLT key isolation remain mandatory.

R9.16 actual restricted deployment evidence: current nonroot private
preview reads ONLY DEV Site A public key from an owner 0700 folder,
actual `private.key` file stays 0600 and never reaches browser, Git,
B peer package or logs. The Rust preview and dev key owner are the
SAME operating-system principal for lab simplicity. This is NOT
production-grade key isolation: future commercial hub must separate
key-vault/privileged network-worker identity from web/BFF identity,
with independently tested encrypted backups and scoped secret release.
Actual UDP port 51820 had NO listener at latest local inspection.
The DEV-only panel cannot provision real WireGuard or claim a safe
last hop from an address matching RFC1918 text alone.

## R9.17 no compulsory VPN; direct protocol requires proof

A direct private/public management address MUST NOT be treated as
trusted from routability or RFC1918 alone. Validate actual adapter,
firmware, independent host key/TLS certificate or SNMPv3 authPriv
identity, restricted source and dedicated read-only account, live
baseline and audited signed MFA before active worker dispatch. Never
fallback to unverified HTTPS, `-k`, plaintext public Telnet or
factory/default privileged credentials. Optional WireGuard/IPsec
remains a separate reviewed network control, never a condition for
EVERY device connection. One actual owner-VPS TLS443 noauth preflight
failed TCP connection without credentials or HTTP requests; existing
private SSH banner remains UNTRUSTED device-identity evidence.

## R9.19 — Penolakan fungsi fisik sampai seluruh kontrol nyata tersedia

GET private lab C320 action catalog memisahkan hasil parser offline,
fitur firmware yang belum teruji dan perubahan berdampak tinggi.
Setiap POST action ke private LAB mengembalikan HTTP403, termasuk
pembacaan. Browser tidak dapat menaikkan hak atau menyatakan status
adopsi; tidak ada alamat OLT/kredensial diterima oleh endpoint ini.
Worker produksi yang akan datang harus memverifikasi identitas host
melalui konsol tepercaya, role baca-saja, jalur manajemen terisolasi,
MFA signed, persetujuan independen, lease per-device, batas laju dan
audit dengan bukti dari DB terisolasi tenant, bukan nilai boolean UI.
