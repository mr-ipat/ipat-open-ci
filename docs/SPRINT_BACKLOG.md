# IPAT — Seven-Day MVP Backlog & Implementation Slices v0.1

**Plan date:** 2026-09-25; target = seven **development days** of integrated laboratory effort. Dates/capacity depend on team availability; calendar dates not promised. **Statuses are PLANNED; no source code/physical tests have been executed in this documentation milestone.**

## 1. Sprint objective, roles, definition of done

**Sprint goal:** demonstrate tenant-safe frontend↔backend auth + original Rust CWMP Inform and one parameter RPC (simulator first) + defined native USP boundary/one simulator flow + device read-only/PPPoE controlled demo where physical access exists + 3 evidence-based diagnostic rules + backup/restore and safe worker state. User-facing workflows can be reduced to CLI/minimal UI if necessary, but no security-critical shortcut may be masked as done.

**Responsible functions (staffing to assign):** Architect/tech lead (architecture integration); Rust protocol engineer (CWMP/USP); product/frontend/full stack (auth/tenant UI); network engineer (physical lab, OLT/MikroTik); SRE (CI/dev infra/backup/K3s); QA/security reviewer (negative tests and write approvals). Staffing is not assumed to be six available full-time individuals.

**Definition of done per story:** file path/commit, migration (if applicable), tested functionality and named exact device/simulator, automated tests + manual verification runbook, sanitized evidence/run ID, observability and failure case, doc/status updates. `Blocked` ≠ `Done`, scaffold-only ≠ completed integration.

**No-go safety controls:** never use production subscriber credentials; no write without lab backup/permission/approval; never use unsecured real RouterOS interfaces; stop release when any delivered path leaks tenant data or bypasses approval.

## 2. Work breakdown ordered by critical path

| Task | Priority | Planned owner | Deliverables / planned paths | Acceptance / dependencies |
|---|---|---|---|---|
| S1-00 repo foundation | P0 | Architect | `Cargo.toml`, workspace apps/crates, `web/`, `migrations/`, `tests/`, `deploy/compose/`, CI and docs | `cargo fmt`, `cargo test` and integration test entrypoint **when code exists**; docs tracked; avoid empty stubs as success |
| S1-01 platform+tenant data model | P0 | Rust + DB | `tenant-core`, persistence migrations, verified domain/membership model | Two synthetic tenants and resource joins enforce tenant invariant; ADR-005 pending final |
| S1-02 identity, RBAC+ABAC | P0 | Security + frontend | `authz-core`, Axum middleware, session config, filtered menu | AC-01/02 UI/direct URL/API/POP negatives; Keycloak proposed pending version pin |
| S1-03 job/outbox and approval | P0 | Rust + DB | `provisioning-core`, `jobs`/`outbox` migrations, worker lease/fencing tests | duplicate delivery/timeout transitions; `unknown` state manual hold; immutable approval plan |
| S1-04 original CWMP | P0 | Rust protocol | `cwmp-protocol`, `cwmp-gateway`, simulator fixtures | AC-03 simulator Inform+InformResponse and 1 tested parameter read; fuzz/bounds/unit parsing |
| S1-05 USP boundary + PoC | P1 | Rust protocol | `usp-protocol`, `usp-controller`, pinned protobuf schemas, simulator | AC-04 one authenticated/correlated message if transport readiness allows; label protocol-only otherwise |
| S1-06 device physical intake | P0 | Network engineer | `DEVICE_MATRIX.md`, lab assets and sanctioned access checklist | Exact model/firmware, backups/management channels; unavailable → BLOCKED, not validated |
| S1-07 OLT read-only adapter | P1 | Network+Rust | `adapters-zte`, `adapters-cdata`, mock fixtures | Basic inventory/read of one actual adapter only if physical/method confirmed; otherwise simulator clearly marked |
| S1-08 MikroTik PPPoE flow | P0 conditional | Network+Rust | `adapters-mikrotik`, CSV validation, dry-run, approval and small job test | AC-05 negative CSV/no-dry-run-write, optional physical write only after recovery/approval |
| S1-09 subscriber/topology | P1 | Full stack+Rust | `inventory-core`, minimal views/fixtures | subscriber→PPPoE→ONT→OLT→distribution model, tenant-filtered |
| S1-10 diagnostics | P1 | Rust+Network | `diagnostic-core`, deterministic fixtures, basic UI/CLI | AC-06 3 distinct hypotheses, source/time/unknown guard |
| S1-11 observability and release | P0 | SRE+QA | structured trace/log/metrics, runbook, evidence index | redaction test, operator steps, source SHA, first end-to-end demo |
| S1-12 backup/restore | P0 | SRE+DB | restore script/runbook (planned) and sanitized evidence | AC-07 actual isolated restore; not merely backup creation |
| S1-13 heterogeneous node | P2 conditional | SRE | `deploy/ansible`, `helm`, `gitops` + node lifecycle runbook | AC-08 only when second node available; otherwise architecture + scripted plan not counted as passing test |

## 3. Day-by-day integration plan

| Day | Main execution (parallel tracks only if personnel available) | End-of-day checkpoint / evidence |
|---|---|---|
| D1 | Freeze v0.1 scope+ADR proposal list; instantiate workspace/CI, capture exact lab inventory and access; seed two tenants; choose simulator fixtures | Compiling repository foundation; device `untested` row detail recorded; unresolved hardware/USP broker blocked visibly |
| D2 | Migrations/tenant context + authz negative tests; CWMP SOAP parser, safe limits and Inform simulator | Both tenant cases pass for first API path; parse valid/invalid Inform; no claim of physical interoperability |
| D3 | OIDC session + entitlement/menu slices; CWMP session and one safe RPC against simulator; begin outbox/job states | AC-01/02 initial negative run, AC-03 simulator run and sanitized evidence |
| D4 | Adapter skeleton tied to observed hardware, MikroTik read-only if authorized, immutable CSV diff/dry-run; normalized inventory/topology | Physical-read result separately tagged; fake/stale observations labeled; dry-run leaves router unchanged |
| D5 | Worker lease/idempotency/approval small workflow; 3 deterministic incident rules; USP native module+simulator PoC (parallel) | AC-05 simulator/physical gate, AC-06, AC-04 PoC evidence or clearly documented blocker |
| D6 | Integrated cross-module E2E, adversarial tenant test, retry/timeout/crash injection; first actual isolated PostgreSQL restore | Repeat AC-01..07; no security bypass; first measured p95 and queue metrics if available |
| D7 | Stabilize/fix; demo tenant-safe triage/provisioning/CWMP; heterogeneous node join **only if ready**; document verification, issue log and next milestone | Acceptance report pass/fail/blocked by AC; actual physical tuple evidence, status + ADR changes; MVP only, not production |

**Critical path:** repository + two-tenant isolation + authorization + durable job safety **before** any real device write. CWMP Inform/RPC is required protocol slice. Physical OLT and USP broker intricacies are parallel and conditional; they must not delay the tenant safety gate or cause fabricated compatibility claims.

## 4. Acceptance test tasks and exact expected negative cases

| Test task | Minimal scenarios | Oracle |
|---|---|---|
| TEST-TENANT | A accesses B via device id, subscriber id, joined topology, raw SQL view, job ID, search/export, host/header spoof, worker payload | Forbidden or indistinguishable not-found per endpoint disclosure policy; **zero** B records or side effects |
| TEST-ROLE | Helpdesk direct URL/REST/export/POP outside assignment, hidden menu snapshot | No forbidden menu and backend policy denies all routes |
| TEST-CWMP | Inform valid, unknown ID, wrong credential, malformed XML/XXE/oversize, allowed RPC, unexpected fault | Only authenticated exact enrolled device creates state; RPC test result recorded per simulator/firmware |
| TEST-USP | Wrong endpoint/topic/tenant, replay, one correlated response or notification | Authenticated authorized identity only; PoC scope explicit |
| TEST-JOBS | Duplicate submit/key, duplicate RabbitMQ delivery, worker crash after device write, expired/self approval, modified diff | No repeat when safely known; ambiguous effect `Unknown` and manual check; no write without valid approval |
| TEST-DIAG | Simulated multi-subscriber uplink, single-ONT optical, PPPoE auth and CWMP-silent-only | Different reasoned hypotheses and insufficient evidence for fiber diagnosis |
| TEST-OPS | Backup→isolated restore, no raw secrets in logs, optional node join/drain | Integrity evidence; sanitized logs; node conditional status correct |

## 5. Cut-line / scope management if capacity is constrained

- **Never cut:** two-tenant backend deny-by-default security tests, protocol endpoint identity binding, job dry-run/no write bypass, truthful result statuses, docs/incident evidence. If safety checks fail, do not demo real write.
- **P0 core lab slice:** CWMP simulator Inform+1 safe RPC, basic OIDC/menu/API, PostgreSQL tenant model+job outbox, synthetic diagnostic evidence, backup restore.
- **Defer from demo (do not pretend done) in this order if blocked:** actual USP broker interop beyond simulator, multi-OLT physical telemetry, graphical topology polish, second hetero node, batch real changes without lab readiness. Keep their **architecture** and open issues because product MUST still requires them.
- **Seven days is a target, not completion guarantee**; preserve exact pass/fail/blocked per AC and tag physical vs simulator in QA report.

## 6. Post-S1 epics & sequencing

| Epic | Dependencies | Release gate |
|---|---|---|
| E-M1-CWMP | `TC-CWMP-01/02` results and secure CPE onboarding | Prioritized RPC/profile interoperability with per-device regression |
| E-M1-USP | MQTT/broker ADR and actual agent inventory | Authenticated multi-device/tenant Controller with trace/retry/conformance suite |
| E-M1-OLT-MIKROTIK | Physical lab access, vendor docs and security policy | Per-model/firmware feature capability, safe write/reconcile/rollback tests |
| E-M2-TENANT-DOMAIN | ADR-005/014, security review | Verified custom domain and hard multi-tenant tests, plan enforcement |
| E-M2-DIAGNOSTICS | Real topology/event data after pilot | Evaluation dataset, operator feedback, freshness and false-positive metrics |
| E-M3-RESILIENCE | Measured sizing and ADR-010 | K3s multi-node tests, DB failover/PITR RPO/RTO, backup/object/queue HA |
| E-M3-SECURITY | End-to-end policy coverage | Threat-model closure, penetration test, incident-response tabletop |
| E-M3-NATIVE-FIREWALL (SHOULD/LATER) | ADR-018 proposed; root-config restore PASS; actual console/rescue still unverified, ADR-017 CNI OPEN | Pure dual-stack firewall-policy Rust dry-run first; later privileged nftables agent only after immutable diff, ABAC/dual approval, CNI coexistence review, isolated rollback drill and independent fresh SSH/IPv4/IPv6 tests; never manage third-party hosting firewall APIs |
| E-M4-COMMERCIAL | Legal/contract decisions & verified readiness | Tenants/packages/support and privacy readiness, billing only separately scoped |

## 7. Reporting template (use on D7)

```text
Sprint commit SHA:
Lab topology and exact devices:
AC-01: PASS/FAIL/BLOCKED; evidence:
...
AC-08: PASS/FAIL/BLOCKED; second-node context:
Physical validated tuples: [list only if evidence exists]
Simulator-only results: [list]
Security failures / high-risk stop conditions:
Performance measurements (environment, workload, p50/p95/p99):
DB restore evidence and data-integrity check:
Architecture decisions revised:
Next priority / owner / blockers:
```


## R4.9 actual S1-04 subtask progress

The offline synthetic Inform admission portion of S1-04 now compiles in a separate `cwmp-admission` Rust crate, with **11 unit tests PASS** on actual Ubuntu 26.04. It is *not* an HTTPS/mTLS adapter, production sessions, a real RPC, physical ONT testing or full AC-03 acceptance; S1-04 remains **IN PROGRESS**. No security shortcuts or live deployment are authorized while trusted TLS enrollment and out-of-band network recovery remain blocked. The independent S1-05 native USP controller still has no runtime implementation.


## R5.0 native USP simulator milestone status

The distinct native Rust `usp-core` synthetic controller boundary and explicit optional `usp-controller` loopback health-only binary compile and have 12 + 3 synthetic unit tests passing on actual Ubuntu 26.04. The controller's real USP protobuf Record/Msg and broker/MTP trust path are NOT IMPLEMENTED; a locally correlated struct is not a TR-369 wire message. **S1-05 remains IN PROGRESS and PRD AC-04 is not met.** Version/schema pinning and actual authenticated wire-level simulator are the next MUST subtask. Never expose a public USP ingress or approve ADR-007 broker choice without the required security comparison.


### R5.1 lab data-boundary slice
- MUST: isolated, explicitly opted-in synthetic PostgreSQL 16.9 schema/RLS/role tests with negative cross-tenant cases; independent restored synthetic database row-checksum and RLS checks. Do not claim live backend persistence or production HA.
- SHOULD: trusted OIDC-to-tenant verification inside backend, non-superuser pool with transaction-local scope, deny on invalid context and post-transaction connection reuse.
- LATER: tenant-safe backup access controls, production PostgreSQL HA/PITR, independent host recovery and actual AC-07 customer-data restore evidence.


### R5.2 diagnostic synthetic work
- MUST within this isolated slice: verified source+timestamp synthetic observations, 3 differentiated distribution/access/PPPoE scenario tests, a CWMP missing-only insufficient-evidence guard, no cross-tenant/POP correlation or auto-remediation, and contradictory/stale negative tests.
- SHOULD next: actual authenticated topology and normalized read-only OLT/router/CWMP/USP signal integration, DB-backed provenance with row isolation, deterministic replay and operator-facing audit evidence.
- LATER after field evidence: accuracy/uncertainty calibration, downstream impact completeness, production alert routing and controlled remediation approvals.

### R5.3 offline safe job core
- MUST (simulator-only): tenant/router-scoped immutable synthetic plan and key; self-approval denial; approval TTL, 60-second fenced synthetic worker lease, no duplicate claim on globally shared router, expired-lease `Unknown` **with router quarantine**, and negative tests. Eight Rust tests and three static contracts passed on isolated Ubuntu/Mac before GitHub review.
- STILL MUST for S1-03 / AC-05: actual verified operator/service identity, persisted PostgreSQL outbox and transactional fencing, independently verified RouterOS inventory and dry-run diff, audited two-person approvals, side-effect uncertainty reconciliation, redacted operator evidence. Current simulator must never be wired to a live writer.
- LATER: load/failure injection with multiple workers and a real database/broker on recovery-approved isolated infrastructure; before any physical PPPoE write, owner-approved test backups, access and maintenance window.

### R5.4 lab-only durable job/outbox progress
- MUST in this isolated slice: executable additive lab-only PostgreSQL migration for tenant+POP job/outbox tables, forced RLS/no runtime DML, scoped router FK, exact idempotency and immutable plan digest, synthetic bounded approval/lease state transitions, ambiguous router quarantine and same-transaction outbox trigger. Run negative integration tests and logical new-database restore in disposable PostgreSQL 16.9 CI only.
- STILL MUST before actual S1-03/AC-05: trusted OIDC session and membership, verified POP from database, signed/verified worker identity, approved roles, actual global physical router registry, nonprivileged purpose-limited SQL mutation API, publisher and crash-safe claim/reconcile with redacted audit and real device read-only diff. No actual PPPoE write allowed.
- LATER: independent PostgreSQL host/PITR and offsite recovery, authenticated multi-worker crash/failover and benchmark, real physical interoperability, production release security review.

### R5.5 infrastructure safety critical path
- MUST now: independently verify canonical Mac/GitHub/Ubuntu source, existing encrypted source recovery, live host read-only conditions and fail-closed external recovery/perimeter/ADR gates; record result without installing services or changing host/provider firewall.
- MUST external before any privileged work: actual out-of-band login, separate-host encrypted full restore, dedicated per-node IPv4+IPv6 source-restricted ingress and tested rollback, independent PostgreSQL PITR/HA readiness and private K3s networking architecture sign-off. No shared external group editing or hosting-provider integration.
- SHOULD on disposable separately recoverable machines: independently tested PostgreSQL physical base backup+WAL restore, native nftables failure/rollback drill with CNI coexistence, pinned isolated K3s bootstrap/restore and node crash handling. LATER: measured production multi-node HA, real OIDC/POP identity, audit/security review and customer-data acceptance.

### R5.6 next K3s milestone — real target-OS disposable node, not live VPS
- MUST first: pin an official stable K3s binary and checksum; use a disposable GitHub Ubuntu 26.04 host to run real embedded-etcd K3s with private-only API, single-node readiness, CoreDNS, a disposable test pod/internal DNS and temporary local etcd snapshot. Enforce non-GitHub refusal and CI-only sandbox guards.
- STILL BLOCKED before actual VPS install: real independent working rescue console, complete encrypted separately restorable host image/data and full independent recovery, dedicated dual-stack effective perimeter controls without editing shared external groups, approved ADR-017 private CNI/control-plane topology and tested independent rollback. Static/CI success does not waive these live security and disaster-recovery requirements.
- NEXT after actual disposable node proof: test controlled K3s systemd lifecycle and **second-machine** datastore snapshot restore, isolated nftables+CNI coexistence, source-scoped IPv4/IPv6 ingress and interrupted node recovery; then deploy health-only control-api without exposing synthetic CWMP/USP/RouterOS features.

### R5.7 K3s recovery progress
- DONE in isolated laboratory: real Ubuntu 26.04 QEMU K3s systemd source node; CoreDNS/pod DNS; embedded-etcd snapshot plus secret-safe server-token transfer; restore to a different VM; stale Node/pod cleanup; post-restart fresh-pod health proof; post-restore snapshot; nftables default-drop coexistence; intentional SSH lockout and precise timed rollback.
- MUST before live-node install: real out-of-band console login, full independently restorable live-host recovery, dedicated effective IPv4+IPv6 perimeter, signed ADR-017 CNI/private node network/datastore design and ADR-018 decision if native host firewall will apply.
- SHOULD next after R5.7 merge: use the recovered disposable K3s environment for IPAT Helm/deployment manifests, pod security, service accounts/network policy and application health checks without exposing CWMP/USP or real device writes.

### R5.8 MUST: disposable K3s health-only Rust app deployment
Build original Rust `control-api` and separate synthetic `usp-controller` into non-root scratch OCI images; validate exact private Helm manifests with negative mutation tests; deploy them inside the **already isolated** ephemeral Ubuntu 26 K3s job, verify actual health and deny-by-default routes, record precise CI and encrypted merged-source recovery. SHOULD next: independently instrument and test real OIDC-issued membership/POP claims before enabling data APIs and complete isolated multi-node/private-CNI trials. LATER/production: only after independent OOB rescue, full-host recovery, dedicated dual-stack ingress, approved ADR-017/018 and stateful DB PITR may any live server services be installed or exposed.

### R5.9 web access boundary
- MUST: source-controlled, explicitly enabled Mac-local browser preview,
  actual Rust HTTP/CSP/denied-request test, fail-closed SSH forwarding,
  six negative source/deployment contracts and exact-source encrypted backup.
- SHOULD: decide and approve ADR-006 frontend/OIDC provider and ADR-014
  verified custom domains; build authenticated login/membership/POP test
  before showing real tenant-specific menus or customer data.
- BLOCKED for public deployment: actual usable independent rescue console,
  whole VPS separate-host restore, verified dedicated IPv4+IPv6 perimeter,
  signed ADR-017 private cluster topology, production PostgreSQL HA/PITR
  and high-risk authorization audits. An information-only local browser
  is not permission to install live K3s or publish the API.

### R6.0 device testing preparations

- MUST (deliverable): eight exact approved target slots in the strictly
  local read-only lab dashboard; zero real hardware enrollment status;
  offline exact model/HW revision/firmware metadata schema with safe
  private staging, strict unknown/secret/placeholder/address rejection,
  Rust HTTP tests and real CI regression.
- SHOULD (only with authorized real hardware): capture each tested unit's
  board/model/firmware evidence and isolated management method out of Git;
  implement its first verified read-only adapter or authenticated CWMP
  Inform and independently test positive tenant identity and negative
  cross-tenant paths before any true device enrollment.
- BLOCKED (not claim complete): any actual physical device is connected,
  USP support, true OLT/RouterOS adapter support, subscriber view,
  privileged actions, public customer dashboard or commercial compatibility.
  Secrets, actual device IPs and serials must not enter chat or Git.

### R6.1 DEV-08 targeted real router test
- MUST now: register operator-*reported* RB951Ui-2HnD RouterOS
  7.23.7 in DEV-08, leaving physical enrollment and compatibility
  at zero. Add one dedicated safe/offline-by-default HTTPS REST
  first-read probe with strict TLS and secretless output; exercise
  malicious/wrong model/firmware, private address, permissions and
  unauthorised-operation negatives with no physical I/O.
- MUST before *actual physical* read: approved non-disruptive
  customer-router test scope, independent router recovery/backup,
  isolated Mac-to-router private path, www-ssl TLS certificate
  validation, restricted single-purpose account and separate
  two-flag explicit one-GET operator execution.
- LATER: reviewed physical identity evidence + tenant-bound
  backend onboarding; full Rust adapter, managed config, Wi-Fi,
  PPPoE, customer and firmware functions require independently
  tested RBAC+ABAC, per-firmware checks and controlled writes.
  No claim that all features are ready.

### R6.2 native Rust RouterOS domain and evidence bridge
- MUST in laboratory: implement standalone reusable Rust
  routeros-core normalizer for bounded exact DEV-08 read-only
  response, negative ambiguous/mismatched/secret/duplicate tests;
  add closed-schema offline evidence parser and non-network
  local CLI; verify cross-language Python synthetic payload
  stripping + forged enrollment denial and pinned Rust CI.
- MUST for the first *real* physical test: operator supplies
  independent dedicated private management route, actual
  least-privileged REST account, valid trusted RouterOS TLS
  certificate, customer permission and tested non-disruptive
  recovery. Only run existing Mac one-GET R6.1 helper after
  both explicit local approvals and record reviewed physical
  evidence before changing DEV-08 compatibility status.
- LATER: trusted per-tenant device assignment, OIDC/MFA,
  production Rust network connector and isolated read-only
  API. Wi-Fi, PPPoE, firewall, updates and device writes
  need their own scopes, reviews and physical tests.

### R6.3 unexpected router SSH host-key change — block authentication
- MUST: retain old known_hosts record unchanged; never send
  the user-posted password or automate accepting the new
  untrusted public endpoint fingerprint.
- MUST: independently compare new observed public RSA key
  to the **same actual** router over a separate trusted
  direct-LAN management channel with known device hardware;
  verify any expected legitimate key regeneration, and
  rotate already-shared credentials using a trusted path.
- COMPLETE (pre-CI): implement single-host, zero-credential
  SSH fingerprint read-only validator with default mismatch
  exit 4, no hidden known_hosts rewrite, optional strict
  owner-controlled independent proof file, mocked negative
  tests and exact-target live unauthenticated denial test.
- BLOCKED: actual RouterOS SSH login/read, any physical
  support claim or customer-router configuration until
  host identity, limited account, safe read-only scope
  and equipment non-disruption are independently verified.

### R6.4 first SSH read readiness while owner LAN identity is pending

- MUST: one exact disabled-by-default single DEV-08
  public-key-only SSH read-only test path; prevent all
  login before independent trusted-LAN RSA host identity
  proof, safe recovery, dedicated restricted key and
  three explicit operator flags. Old pinned host key
  must remain untouched and SHA-1 downgrade is denied.
- MUST: validate strictly three harmless RouterOS
  resource identity fields and return redacted private
  *unreviewed* evidence only; reuse Rust resource identity
  policy and extend Rust closed-schema output validator
  without permitting fabricated tenancy/writes.
- MUST: the private browser shows a previous check's
  blocked host-key state and zero actual enrolled devices
  without management endpoint information or simulated
  success. Run R6.4 negative/mock and cross-language
  synthetic contract in disposable CI and unchanged
  real Ubuntu VPS checkout.
- BLOCKED ON OPERATOR: actual trusted-LAN fingerprint,
  safe backup/recovery, rotated exposed account credential,
  separate limited SSH public-key account and explicit
  non-disruptive single-device authorization. Until
  proven, do not run real SSH, claim compatibility
  or enable managed PPPoE/Wi-Fi/config features.

### R6.6 original ACS first-RPC milestone and follow-on release gates

- DONE (synthetic): one-parameter bounded
  SOAP/CWMP 1.0 GetParameterValues serializer,
  strict value/fault parser and wrong method,
  namespace, type, correlation, DTD and
  oversize rejection tests.
- DONE (synthetic): existing sealed trusted
  peer + tenant + lease admits Inform, truly
  empty CPE POST, one correlated read or
  numeric CWMP fault, and explicit session
  close/abort without promoting raw values
  to physical trust.
- DONE (loopback-only): opt-in actual Rust
  Axum HTTP parser process on fixed 127.0.0.1
  with unconditional /cwmp 503 deny and
  temporary real HTTP safety regression.
- MUST NEXT: full cryptographically
  authenticated HTTPS client mTLS adapter
  and operator-approved durable tenant/device
  enrollment (never trust request headers);
  actual CWMP empty-POST/response/fault
  HTTP binding, timeouts, persisted replay/
  lease and multi-pod device owner locks.

- MUST RELEASE: RLS-scoped runtime audit,
  one exact ONT model/firmware live lab
  Inform + independently verified parameter
  RPC and failure/restore tests. Without
  these, FR-009/010 and physical AC-03
  stay partial/blocked.
- SHOULD: safe parameter discovery, wider
  negotiated CWMP versions and per-device
  profile after exact interoperability.
- LATER: customer-facing writes, firmware
  operations and broad parameter campaigns
  only with change approval and rollback.

### R6.7 real mutually authenticated TLS gate (lab only)
- MUST delivered lab: real rustls TLS1.3
  client-CA-verified handshake, fixed
  127.0.0.1:3433, opt-in and private
  file checks, real OpenSSL/cURL
  synthetic CA positive/negative
  tests, no public /cwmp access.
- MUST next: per-device pinned
  public-key certificate/issuer,
  revocation/expiry+rotation,
  independently audited tenant
  enrollment and actual secure
  transition to the sealed
  CWMP admission Rust state.
- MUST before pilot: time-bound
  authenticated CWMP network
  InformResponse + CPE empty
  POST + read RPC; PostgreSQL
  tenant-specific persisted
  replay/sessions, privileges
  and audit, and at least one
  actual ONT model/firmware test.
- SHOULD: finite handshake
  concurrency/timeouts/load

  and certificate rotation drills.
- LATER: firmware and mass writes
  after approvals/recovery tests.

### R6.8 tiga dashboard lab yang bisa diperiksa

- MUST LAB: tiga halaman
  visual platform, tenant
  dan NOC, fixture jelas
  sintetis, tidak menyimpan
  role/cookie/API access,
  akses hanya melalui
  private Mac SSH tunnel
  nonroot.
- MUST SECURITY LAB:
  backend /v1/platform,
  /v1/tenant dan
  /v1/operations fail
  closed (401) termasuk
  header palsu semua
  metode; pure Rust
  role/POP policy
  negatif lintas tenant,
  tanpa bulk-write.
- MUST NEXT: IdP
  OIDC/MFA plus verified
  tenant membership/domain,
  real backend-protected

  menu/route policy dan
  audit, database RLS
  + isolated subscriptions,
  baru buat dashboard
  tenant sungguhan.
- MUST NEXT: sambungkan
  inventaris/ACS/USP
  yang identitas dan
  model/firmware perangkatnya
  telah diuji agar
  operasional bukan
  status contoh.
- SHOULD: saat ADR-006
  disetujui, frontend
  Next.js/TypeScript
  modular, komponen
  desain dan E2E
  test pada domain tenant.
- LATER: billing,
  topology real-time
  dan multi-vendor
  automasi berisiko
  dengan approval
  dan rollback.

### R6.9 signed token boundary for three dashboard workspaces

- DONE synthetic: independently pinned RS256 public-key
  validator checks signature, fixed issuer/audience/kid,
  exp/nbf/iat and bounded lifetime; rejects forged
  tokens and attacker-controlled JOSE key URLs.
- DONE synthetic: optional private JWT proof route
  accepts a genuinely signed test token but
  NEVER creates tenant/role membership or opens
  Platform/Tenant/NOC business endpoints.
- MUST NEXT: real independently trusted Keycloak/OIDC
  discovery and JWKS rotation, Authorization
  Code+PKCE, MFA and host-only cookies/CSRF;
  server-sourced tenant/POP membership binding
  with full resource API enforcement and RLS.
- MUST NEXT: genuinely authenticated Platform
  Tenant Admin and operations data integration,
  two independently active synthetic tenants,
  hidden unauthorized menu plus direct URL/API
  cross-tenant/POP IDOR regression suite.
- MUST before pilot: real approved domain
  verification, approved audited operator
  actions, device/telemetry data ingestion

  and independent recovery/security signoff.
- SHOULD: reusable OIDC test IdP via disposable
  environment, session expiry/revocation and
  documented JWKS rollover drill.
- LATER: commercial branding/package/billing
  workflows and high-risk mass provisioning
  after reviewed approval paths exist.

### R7.0 next dashboard phase and conditional estimates

- DONE for lab candidate: explicit
  `identity_memberships` tenant+OIDC
  issuer/subject/approved role,
  `identity_pop_grants` exact composite
  foreign key, separated `platform_principals`,
  FORCE RLS and zero app-runtime
  grants/policies; disposable
  PostgreSQL negative suite and CI
  integration.
- MUST next: approved real IdP
  Keycloak/discovery+JWKS lifecycle,
  Authorization Code+PKCE,
  MFA/account lifecycle, HTTP session
  CSRF/state/nonce and verified
  per-domain redirect/cookie rules.
- MUST next: trusted subject→membership
  lookup from independently
  approved database, expiry/revocation/
  tenant state/POP, backend RBAC+ABAC
  and server-provided hidden menus
  with negative tenant+POP+API tests.
- MUST later: actual inventory/NOC
  data, device onboarding from

  authenticated ACS/USP, observability
  and action-specific approvals.
- Planning only: login/MFA lab
  1–2 weeks; integrated admin/tenant/
  NOC baseline 4–6 weeks;
  physical ISP pilot 8–12 weeks,
  contingent on device access and
  production safety gates.
- Production NO_GO pending real
  recovery/perimeter and signed
  architecture decisions.

### R7.1 ZTE C320 requested physical onboarding and firmware extension

- DONE synthetic candidate: bounded Rust vendor-format read-only
  inventory/version parsers, fixed-command allowlist, owner-only
  offline input importer, non-executable firmware review gate
  and red full-dashboard PRD gap notification.
- MUST NEXT (real DEV-01): verified exact C320 chassis/card
  revisions and current running versions; authorized private
  management method, trusted host identity and least-privileged
  read-only account; independently prepared operator recovery.
- MUST ACCEPT FR-016: exactly one verified real chassis safe
  inventory read, redacted evidence, isolated tenant device
  mapping and negative no-write audit; keep untested until then.
- PROPOSED HIGH-RISK LATER: sign off new exact-firmware update
  scope and tests, official image provenance, per-card compatibility,
  service impact and onsite rollback, independent maker-checker.
  No implementation or execution approval for firmware today.

### R7.2 C320 firmware preflight / field dependency

- MUST offline delivered: owner-private
  fixed file names/modes, no link
  SHA-256 check with explicit
  opt-in and no firmware actuator;
  nine synthetic positive/negative
  contract tests and CI.
- MUST physical read next: actual
  owner-authorized direct trusted
  C320 management, read-only chassis/
  cards/running versions and basic
  safe POP/tenant context; capture
  real redacted evidence in private
  operator files, not Git/chat.
- MUST prior to any firmware pilot:
  official release notes for exact
  control/uplink/PON cards, licensed
  image provenance, signed vendor
  artifact if offered and independently
  verified hashes; real configuration
  recovery, spare rollback path,
  healthy alarm/customer traffic
  baseline, two independent human
  approvals and approved outage window.

- Firmware execution remains LATER,
  separate ADR/security review and
  explicit per-device authorization.
  Do not use unproven old vendor CLI
  commands for current actual firmware.


## R7.5 owner-approved ordering (ADR-020)

MUST NOW: existing strict private loopback prototype; physical DEV-01
identity and restricted first read-only evidence only after owner/reviewer
preflight; original CWMP/USP simulator and verified identity-to-tenant/POP
API + server filtered menu tests. Keep FR-001/002/003 and AC-01/02 S1
tenant/POP isolation and authorization tests even with only one private URL.
Zero actual tenant customer data before trusted authentication.

SHOULD NEXT: dashboard lab data sourced through verified subject,
server policy and RLS, then observation normalization and safe diagnostics.

DEFERRED TO M2 AFTER WORKING PRIVATE LAB: FR-004/AC-09 verified
subdomains/custom domains, per-domain certificates, trusted Host routing,
cookies, CSRF and OIDC callback isolation (ADR-014 still OPEN).
This is an approved scheduling decision, NOT removal of a requirement.
Do not enable a shared PUBLIC tenant endpoint as a temporary shortcut.


## R7.6 next integrated private-lab dependency (ADR-021)

MUST: distinct stable Fadly tenant ID and operator-approved issuer+
subject+role+POP lookup before any real tenant dashboard; verify
signed token issuer as well as subject and reject all unapproved,
revoked, expired, cross-tenant, cross-issuer and cross-POP candidates.
Synthetic Rust function is reference policy ONLY. Next MUST is a
separately authenticated, audited DB-bound restricted membership
adapter and private login MFA test, followed by server-filtered menus
and backend/DB/job denial, before exposing actual customer data.

MUST separately for physical lab: exact DEV-01 chassis/cards/build,
independent trusted read-only access and backup; TC-OLT-01 NOT RUN.
LATER after working lab: owner-approved public custom domain
hub.example.invalid for Fadly company and future IPAT corporate ipat.id
ONLY after DNS/TLS ownership and independent SSH management recovery
gate. Do not modify existing SSH host, DNS, root firewall or K3s.


## R7.7 identity-read path: synthetic milestone, next P0 blocker

Delivered candidate: disposable Postgres 0004 narrow exact identity
lookup owned by NOLOGIN non-BYPASSRLS function role, dedicated NOLOGIN
executor role, no privileges to live app runtime. CI runs negative
wrong issuer/sub/tenant/role/POP, revoked/expired/suspended and
privilege/RLS checks; no DNS or real infrastructure operations.
P0 NEXT: operator-approved audited real membership provisioning,
MFA IdP and trusted Rust server adapter, server-controlled menu,
business API and transaction-local tenant/POP RLS complete negative
AC-01/02. Do not call a database function directly with
user-controlled JWT claims/host or enable role membership as a
temporary bypass. Parallel: actual independently safe read-only
ZTE C320 inventory prerequisites.


## R7.8 integrated private identity-path result and next real gate

MUST lab delivery: real Rust route joins pinned signed JWT,
disposable PostgreSQL restricted lookup and scoped read-only
menu computation without activating business endpoints or
trusting Host/tenant/role claims. CI proves real generated
RS256 JWT+actual Axum+actual isolated PostgreSQL role
with positive/negative cross-tenant, cross-role/POP and
bad token tests. The exact CI result MUST be recorded
after execution, not inferred from code.

MUST NEXT: operator-trusted identity provider with MFA,
audited actual human membership enrollment/revocation,
production-reviewed restricted PostgreSQL user/migrations
after independent whole-host recovery, server-controlled
menu for all three real dashboards and authorization
on real API/DB/jobs. Physical ZTE C320 independent-console
actual board/firmware read remains separate blocker.
SHOULD: formal versioned key rotation and CSRF/logout
when public tenant domains are approved. LATER domain
branding hub.example.invalid/ipat.id with ownership/TLS
and management SSH route separation.


## R7.9 owner-approved remote transport and provider-neutral K3s slice

MUST source: fixed remote ZTE C320 private SSH
read-only guarded collector, strict owner
private identity/key files, independent hostpin,
two static SHOW commands, bounded capture and
synthetic mock SSH→REAL Rust parser test.
MUST independent interop next: owner-only private
management route, pin verification from trusted
channel, exact firmware/board and vendor CLI
support; run first ACTUAL approved remote read
with no live subscriber impact and redact
private evidence into DEVICE_MATRIX.
Fallback candidate SNMPv3 must independently
verify exact vendor firmware and vendor MIB.

MUST source: VPS-provider-neutral OFFLINE K3s
single-server or WireGuard-private multi-worker
topology planner rejecting internet-exposed
address proposals, CIDR overlap, unsafe
cross-cloud etcd assumptions and hidden
secrets/provider firewall API dependencies.
NEXT independently test second real
heterogeneous VPS overlay peering,
authorized 6443/8472 traffic only in
the private tunnel, node join/drain,
and offsite whole-host recovery.
No real root installation on the original
VPS while rescue/restore gates fail.


## R8.0 accelerated offline-before-devices system integration

MUST now: actual Rust `/lab/auth/devices` joins
signed pinned JWT, existing tenant/POP membership,
new sealed FORCE-RLS device query and verified
read-only Rust policy. Synthetic test operator
has legitimate memberships for two distinct
ISP UUIDs, but cannot mix their devices or
POP scopes. Add actual disposable PostgreSQL
function/role/tenant negative tests plus signed
HTTP end-to-end CI and on-VPS locked
Rust workspace tests. Ensure feature defaults
OFF and real business data APIs remain 401.

MUST after: operator-approved actual MFA OIDC
and real scoped PostgreSQL login, completely
isolated full business REST and UI data
bindings, actual ACS/USP simulators with
versioned firmware-specific protocol fixtures,
real router/OLT integrations only once available.
Independent actual offsite whole-host restore
is a hard prerequisite before production
K3s and public TLS routing. SHOULD prepare
virtual diagnostic/provisioning cross-protocol
scenarios and second hetero node network tests.
LATER real firmware upgrade with separate
maker-checker and independently proven
device recovery.


## R8.1 virtual native USP binary slice and next guarded gates

MUST software now: genuine BBF v1.4
read-only no-session Get and
GetResp prost field mapping,
independently hand-encoded actual
binary golden fixtures, duplicate
oneof/unknown field/oversize
fail-closed parser, and actual
loopback private Rust Axum binary
POST inspection with no identity
claims or values returned.
Wire-to-synthetic-controller domain
must deny cross-tenant mock peer,
wrong peer and replay. Validate
the same locked workspace on
actual Ubuntu26 VPS and CI,
preserving existing CWMP/SQL/K3s.
MUST next before real USP agent:
trusted device enrollment,
separate MQTT MTP and persistent
replay/queue, controller TLS
identity and certificate chain,
supported firmware/data model
and TR-369 conformance tests.
SHOULD next add original ACS
trusted simulated device
mTLS Inform→InformResponse
end-to-end (without real ONT),
then incrementally authorized
dashboard data integration
and virtual diagnostics.
LATER public customer listener,
actual ONT/OLT/router
interop and approved
disruptive firmware campaign
only after independent DR
and maker-checker gates.


## R8.2 accelerated original CWMP physical-device-free integrated slice

MUST source: actual original Rust Axum
local SOAP CWMP InformResponse proof, one
static read-only GetParameterValues request,
strict correlated parameter/fault response
without raw value exposure, immutable
fake-only identity gate, 64 KiB global
HTTP body limit, separate opt-in and
permanent production `/cwmp` denial.
MUST tests: genuine compiled Rust
unit and actual Python urllib→HTTP
roundtrip for positives and forged
identity/headers, wrong SOAP method,
unapproved parameter, DTD and oversized
negative paths on nonroot Ubuntu26.
SHOULD next: authorized stateful
virtual device multi-request test
with durable correlation simulator.
MUST later before real ONT: trustworthy
HTTPS peer and real immutable tenant/
device enrollment, durable sessions
and actual VSOL/ZTE firmware-matched
interop; real USP MQTT MTP and
tenant SaaS remain parallel MUST work.


## R8.3 priority escalation: real visible adoption workflow before hardware

MUST NOW: user-visible linked Device Manager
add/list/filter/delete, truthful pending and
unknown states, actual bounded private Rust
HTTP demo, a distinct signed token+SQL
sealed tenant-admin pending registry and
two-company NOC POP-limited read, genuine
ephemeral PostgreSQL actual mutation/read
tests, real compiled Rust end-to-end
HTTP/static browser tests and four CI
jobs. This supersedes further isolated
protocol enhancements while owner lacks
a visible interface.
MUST NEXT: true approved MFA user login,
admin/tenant/NOC server-bound dynamic menus,
the actual company dashboard binding to
per-tenant persistent candidate rows,
independently reviewed maker/checker
adoption approval and append-only audit,
private management endpoint ownership
proof, bounded workers and evidence-based
health from actual ZTE C320 and ONT/RouterOS
protocol adapters (firmware specific).
SHOULD NEXT: run a disposable second-provider
private K3s node / asynchronous queue
measurement only after independent
host recovery/isolated network gates.
MUST BEFORE PRODUCTION: independent
real whole-host/PG/K3s recovery,
customer secret handling, native USP
MQTT MTP real agent identities,
customer TLS/domain and complete
interoperability/regression matrix.
No simulation should masquerade
as customer production readiness.


## R8.4 next priority — independent reviewer for staged hardware intake

MUST software: extend genuine signed identity
with exact bounded `amr:mfa`; sealed independent
PostgreSQL reviewer security_admin role, same
tenant exact membership, explicit distinct
issuer+subject from requester, bounded reason,
row-locked single-decision metadata change and
append-only audit. Only separate reviewer
login may EXECUTE the review/queue functions.
MUST tests: actual disposable PostgreSQL 16
positive/negative maker-checker, role isolation,
revocation, idempotency, cross-tenant denial;
Rust actual signed JWT+MFA using distinct
fake humans and real restricted PG; both
private and public endpoints fail closed
without prerequisites. This does NOT assert
actual human MFA.
MUST following: real approved human MFA IdP,
secure browser session/BFF and real
authenticated company dashboard joined
to the existing PostgreSQL candidate
registry; then independent verified
vendor/model/firmware read-only evidence.
SHOULD: dynamic review menu only for
actual signed-in security admins, NOC
telemetry freshness and audit evidence
for read-only collectors.
LATER: firmware execution after
independent recovery, production cluster,
whole-host/database offsite DR.


## R8.5 independent real IdP signing and MFA claim readiness

MUST: bounded original Rust nonroot real
pinned issuer+key+audience+short JWT
signed `amr:mfa` preflight taking
short-lived actual bearer from private
protected FD, never granting role or
asserting real human MFA enrollment.
CI MUST generate independent fresh
ephemeral RSA keys and actual process
stdin tests covering missing opt-in,
wrong kid, key or MFA, insecure
PEM modes/symlinks and token leakage,
while preserving all R8.3/R8.4
two-tenant security tests.
MUST NEXT: independently approved
and enrolled actual human IdP with
documented Keycloak-compatible exact
AMR mapper, true browser MFA
challenge test and server-side
OIDC Code+PKCE secure browser BFF;
then actual tenant/POP device
registry/reviewer workbench.
Do NOT turn signed-claim checks
into unverified production endpoints.


## R8.6 browser login enabling priority ahead of real device admission

MUST completed source candidate: original Rust PKCE
OS-random 256-bit state/nonce/verifier, S256, exact
owner-controlled Keycloak-candidate authorization
endpoint, fixed strictly local registered redirect,
bounded state TTL, one-use callback, signed
OIDC prerequisite and fail-closed HTTP503 with no
fake session. MUST tests: RFC7636 test vector,
random uniqueness, malicious Host/cookie/query,
wrong/replayed/expired state, actual compiled
Rust/Python HTTP 303/503, CI regression
for existing signed reviewer/two-tenant SQL.
MUST next external + software: independently
approved real operator MFA enrollment, TLS
confidential server-side OAuth callback
code redemption and nonce-checked ID token,
secure host-only session rotation, actual
DB membership→role+POP verified
dashboard rendering and server authorization.
Then complete maker-checker UI and controlled
read-only physical device identity checks.
No status may claim real login/adoption
based on this lab flow alone.


## R8.7 original OIDC offline signed two-token bridge

DONE subject to full feature/postmerge CI:
original Rust offline separate verified ID JWT+
access JWT pair with distinct audiences, nonce,
at_hash, issuer/subject agreement, explicit
signed MFA on both, bounded auth_time and strict
negative real RSA synthetic fixture tests.
MUST next: independently approved human IdP MFA
metadata, confidential HTTPS backchannel token
exchange, secure host-only BFF session with
CSRF/logout and separately current restricted
tenant/POP SQL role check, actual signed-in
device review UI and narrow approval/audit.
MUST after review: real vendor firmware-matched
read-only device adapter with source integrity;
no fabricated device condition.


## R8.8 signed identity→sealed SQL→opaque BFF groundwork

MUST in software-before-device laboratory:
real signed ID/access pair bound to
original challenge nonce; OS-random
separate opaque and anti-CSRF tokens,
digests-only storage, capacity/idle/
crypto expiry, rotation and deny-
by-default request-level exact
restricted PostgreSQL tenant/POP
membership checks. Add real
disposable SQL+Rust integration to
GitHub CI (not mere mocks).
MUST next before real commercial
login: external independently approved
real MFA IdP, exact provider code
flow at_hash review, confidential
HTTPS PKCE exchange, trusted
customer TLS/Host+Origin, actual
server session middleware, genuine
production PostgreSQL restricted
memberships and reviewer UI.
MUST next before equipment:
real approved C320 first-read
private target/fingerprint and
model/firmware collection,
documented ONT actual CWMP/USP
versions, approved physical
identity/recovery and evidence-
derived health; no unreviewed
firmware changes. Multi-host
K3s/whole-host+DB recovery
remains blocked on its own
external gates.


## R8.9 exact BFF session→tenant device registry read integration

MUST current milestone: original
session-cookie identity verifier,
independent current active
issuer/subject/tenant/role/POP
membership plus sealed real
device candidate list from ONE
PostgreSQL statement/snapshot.
Genuine disposable CI tests
must prove the exact separate
two-company grants, cross-tenant/
wrong-POP/forged-session/origin/
expiry denies, no device secrets
and no public route.
MUST next: actual independently
proven human MFA OIDC issuer,
confidential HTTPS PKCE exchange,
production safe session transport
and approved DB roles; build
authenticated tenant admin/NOC
device list/review UI with
backend RBAC and truly hidden
non-permitted menu. The current
fake-only private device workbench
MUST stay visibly fake until
these prerequisites are real.
SHOULD next: trusted device
read-only protocol profiles plus
evidence freshness, separately
from later firmware write approval.


## R9.0 precise actual OLT management critical path

MUST NOW: capture the owner's authorized single-endpoint no-login
Mac and VPS network evidence independently, recognize public
Telnet plaintext and source-specific timeout, preserve redacted
owner-private proof and date-labeled historic preview state.
MUST NEXT: establish independently VERIFIED secure private
site-to-IPAT management routing; reproduce exact nonroot VPS
source reachability, independently fingerprint the actual
management peer, determine real C320 model/cards/firmware,
then perform dedicated authorized read-only inventory
with encrypted evidence and actual tenant/POP acceptance.
Do NOT assume the old R7.9 SSH candidate works on actual
firmware or reuse public Telnet with passwords.
SEPARATE MUST: complete true human MFA/secure real browser
BFF, audit/approval, durable authorized device registry
and timestamped genuine health from real protocol evidence.
LATER: narrowly approved firmware write only after
actual backup, tested independent recovery and dual approval;
production K3s/PG/DR external gates remain unchanged.


## R9.1 adoption readiness before read-only physical probe

MUST: persist immutable tenant/candidate evidence for secure path,
device identity, read-only account and recovery plan; cap evidence
validity; require already approved maker-checker metadata and current
security-admin membership; expose a safe current tenant/POP readiness
projection to the unmounted signed-session bridge; keep all network
adapters and write actuators disconnected.

MUST TEST: real disposable PostgreSQL role isolation/forced RLS,
positive four-gate path, blocked and expired gate fail-closed,
idempotency, wrong reviewer, cross-tenant, pending candidate,
revocation and exact POP; actual signed synthetic OIDC pair plus
opaque session reading the real restricted PostgreSQL projection.

NEXT MUST: durable read-probe intent and worker claim model that
revalidates fresh R9.1 gates before claim. Adapter execution remains
disabled until the actual private path, device fingerprint/model/
firmware and dedicated real read-only credentials are independently
verified.


## R9.2 achieved source; future physical critical path

MUST now: immutable audited per-candidate
nonexecuting intent and exact active NOC POP
and four-gate SQL rechecks with sealed roles;
real disposable multi-company SQL and signed
opaque-session CSRF integration are mandatory
CI gates. MUST NEXT for physical OLT/ONT:
actual confidential verified human MFA IdP
HTTPS BFF, real site-to-worker encrypted
management path and source allowlist
(the actual Ubuntu VPS still timed out on
the earlier public network observation),
independent real C320 host identity/model/
firmware and constrained read-only account,
physical operator recovery; THEN separate
audited durable worker execution approval
and atomic per-device lease with fresh
readiness rechecks. Firmware and writes
stay disabled. Full independent production
DR and public commercial SaaS remain open.
