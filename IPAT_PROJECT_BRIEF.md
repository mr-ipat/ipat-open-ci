# IPAT — Project Master Brief
**Product:** IPAT (`IP@` visual mark)
**Expanded name:** Integrated Provisioning, Automation & Telemetry
**Positioning:** Commercial, multi-tenant ISP network-management, provisioning, diagnostics and automation platform.
**Status:** Approved design baseline for PRD v0.1. This is NOT a completed PRD and does not imply device compatibility has been verified.
**Initial sprint:** 7 days, aiming for an integrated laboratory MVP/pilot, NOT production-grade completion.
**Working language:** Indonesian for discussion/documentation unless otherwise decided; code, identifiers, APIs, and technical standards in English.

## 1. Binding product decisions
1. Develop an ORIGINAL ACS/CWMP (TR-069) engine in Rust; do not use GenieACS as the IPAT production engine. Other implementations may only be consulted for interoperability comparisons and subject to applicable license requirements.
2. TR-369 / USP is REQUIRED in the architecture from day one; implement a separate native USP Controller module and a shared device-management abstraction. MQTT is an initial transport candidate, to be confirmed by standards-based design. No claim of completed TR-369 support until conformance/interoperability tests pass.
3. Server OS: **Ubuntu Server 26.04 LTS**. Backend: Rust with Tokio and Axum; proposed frontend: Next.js/TypeScript; PostgreSQL; identity: Keycloak (OIDC/MFA); queues: RabbitMQ; monitoring: Prometheus/Grafana. These are proposed component choices subject to PRD/ADR confirmation.
4. Start as a **modular monolith** plus separately deployed infrastructure/protocol/worker services where needed. Use clear internal module boundaries and asynchronous queues; do not prematurely split into numerous independently managed microservices.
5. Build an architecture for heterogeneous horizontal scaling on VPS and bare-metal: K3s, capacity-aware pod placement, resource requests/limits, KEDA/HPA where appropriate, bounded worker concurrency, backpressure and per-device locking. Adding nodes must not double-execute provisioning tasks. Exact equality of CPU utilization across differently sized servers is NOT guaranteed.
6. Use infrastructure as code: Ansible for Ubuntu/node configuration; K3s node join; Helm + GitOps for workloads; Terraform for VPS providers supporting APIs. Secrets outside Git. Design documented **add-node, validate-node, drain-node, remove-node, restore** procedures and scripts.
7. Separate application scaling from stateful data. PostgreSQL primary/standby replication and PITR backups are distinct from worker scaling. Database replicas do not linearly distribute write load. A DB high-availability plan with tested failover is required for commercial production.
8. Commercial **multi-tenant SaaS**, one codebase, isolated company dashboards, optional white labeling and custom domains. Illustrative only: `kangnet.ipat.id` and `nengnet.ipat.id`; domain ownership/registration NOT established. Include a separate platform-owner admin interface and company-specific tenant interfaces.
9. Tenant isolation is mandatory across UI, API, database access, ACS/USP device assignment, telemetry, queues, artifacts, secrets, search, notifications, background jobs, and backups. Proposed hybrid data architecture: separate platform metadata from operational tenant data; default tenant database strategy to be finalized in PRD based on scale and operational trade-offs. Platform operators must not automatically have access to tenants' device credentials.
10. RBAC + ABAC, deny-by-default, least privilege, auditable approvals for high-risk operations, MFA. A role cannot SEE menus/categories outside its entitlements, and must also be unable to retrieve them via direct URLs, API requests, searches, notifications, exports or worker jobs. Enforce on backend; hiding a button alone is not security. Tenant context must be verified, not trusted from user-controlled headers.
11. Diagnostics are first-class: topology-aware event correlation / root-cause hypotheses separating distribution path, OLT/PON/ONT, router/PPPoE, and client problems; always show evidence, freshness and uncertainty. Never misidentify an absent TR-069 heartbeat as proof of a cut fiber. Do not allow automatic high-impact remediation without approved policies and tested safeguards.
12. Product differentiator versus GenieACS: unified multi-vendor device management plus OLT/router integrations, subscriber views, diagnostics, automation, SaaS/tenant controls and operations—not an unverified claim of superior compatibility, reliability or performance.

## 2. Physical device test matrix (initial)
- OLT: **ZTE C320**; **C-DATA OLT** (exact model/firmware to be recorded before an adapter is called supported).
- ONT: **VSOL ONT**, **ZTE ONT** (exact models and firmware TBD); other brands later.
- Distribution routers: **MikroTik x86, CCR and RB**; customer routers: **MikroTik RB**. Note the RouterOS version and available management interfaces per device.
- **VSOL GPON OLT** was discussed as a future/earlier target but is NOT part of the currently confirmed physical pilot list unless real test access is reconfirmed.
- Record matrix by vendor, exact model, firmware, protocol, feature, test date, outcome, limitations and evidence. Labels: untested, partial, validated. Do not infer support from a different firmware/model.

## 3. Core functional coverage
- Original ACS TR-069: secure HTTP(S)/CWMP endpoint, SOAP/XML, Inform handling, sessions, identity, parameter discovery/read/write, task queue, faults and interoperability tests; later full protocol methods as prioritized.
- Native TR-369/USP design + proof of concept with simulator/compatible agent; separate Controller engine, common normalized device model, correlation IDs and protocol abstraction.
- OLT adapters: ZTE C320, C-DATA (read-only telemetry/discovery first; controlled write actions only when validated), SNMP and supported vendor channels.
- MikroTik distribution: inventory, secure RouterOS API/REST where version allows, PPPoE secrets/session read, controlled bulk create/update with CSV validation, dry run, audit, idempotency and per-router rate limiting.
- MikroTik customer RB inventory/management following physical tests and suitable secure access path.
- Subscriber 360: subscriber ↔ PPPoE ↔ CPE/router ↔ OLT/PON ↔ distribution link associations.
- Topology-aware diagnostics with fault domains, incident dashboard, alerts, evidence and impact estimation.
- Tenant/subscription/platform admin: create tenants, assign verified domains, branding, plans/quotas, usage, tenant-scoped roles; do not implement billing transactions before explicit scope/approval.
- Audit, secret management, encrypted connections, disaster recovery, metrics, observability, deployment automation.

## 4. Authorization roles (proposed; finalize in PRD)
Platform owner admin (commercial management, not automatic tenant device access). Per tenant: tenant admin, system admin, security admin, NOC manager, NOC engineer, provisioning officer, helpdesk, field technician, auditor. Service identities separate. Permissions must be scoped by tenant, region, POP, device, subscriber and action when appropriate. Approvals and time-bound elevated access for dangerous operations.

## 5. Initial infrastructure sizing (PROVISIONAL)
- First all-in-one **development/lab/pilot** node: **16 vCPU, 64 GiB-class RAM, ~1 TB NVMe SSD**, Ubuntu Server 26.04 LTS, reliable private network and external backups. Hardware and disk forecasts require live measurements; VPS vCPU is not equivalent to dedicated CPU in all environments.
- 16 vCPU / 128 GB RAM / ~2 TB NVMe if running substantial database + telemetry + workloads on one pilot machine, subject to budget and I/O needs; scaling out is preferable for resilience.
- Production target: multiple worker nodes; redundant ingress/control plane; independent DB HA (primary+standbys) and separate tested backups with defined RPO/RTO. One pilot node is NOT highly available.
- Sizing must be revisited after collecting expected tenants, online ONTs, Inform rates, USP sessions, retention, poll intervals, jobs/hour and SLOs.

## 6. Sprint 1: seven-day realistic goal
Deliver the source repository, architecture/ADRs, local installation, tenant-aware auth/menu/API policy checks, early Rust CWMP service (e.g. Inform and a minimal interoperable parameter RPC), USP module boundary/protocol PoC, read-only initial device connectors, basic topology/subscriber model, limited rule-based diagnostic demo, safe MikroTik PPPoE demo, tests, deployment scripts, and operator docs as achievable. Prioritize demonstrable end-to-end slices over broad empty scaffolding.
- External physical compatibility and complex load/failover tests depend on access to devices and infrastructure. If missing, test simulators and label results accordingly.
- NOT seven-day guarantees: full TR-069/TR-369 spec coverage; certified interoperability; 100% root-cause accuracy; production-grade HA and security audit; mature billing, autoscaling across all clouds, or device-wide firmware upgrades.

## 7. First acceptance scenarios
1. Tenant Kangnet cannot read or mutate Nengnet's devices/subscriber data via UI, direct URL, API, search, job or export.
2. Helpdesk cannot see prohibited menu/categories AND receives backend denial when trying APIs directly; correct tenant/POP scope for allowed actions.
3. A supported lab ONT performs a CWMP Inform to IPAT and an explicitly tested parameter operation succeeds; record model/firmware and full CWMP logs with secrets redacted.
4. MikroTik lab router's PPPoE secrets can be read; safe bulk changes have dry-run, rate limits, approvals where needed and idempotency tests.
5. Simulated distribution uplink failure correlates multiple affected subscribers; isolated ONT/PPPoE failures produce different hypotheses with evidence/uncertainty.
6. A second heterogeneous compute node joins using documented tooling and takes eligible jobs without duplicate execution; publish measured results rather than promising precise 90→45→30% CPU transitions.
7. Database backup and restore are tested; production failover acceptance is a later milestone unless HA infrastructure is actually provisioned.

## 8. Source-of-truth workflow for ChatGPT Projects
This document is the INITIAL transferred baseline, not a substitute for a complete PRD. Store this file in the IPAT ChatGPT Project and version the canonical documents in Git:
- `docs/PRD.md` — requirements, scope, milestones, and acceptance criteria
- `docs/ARCHITECTURE.md` — component/dataflow/HA/multi-tenant architecture
- `docs/DEVICE_MATRIX.md` — verified combinations and test evidence
- `docs/SECURITY.md` — tenant isolation, roles, ABAC and threat model
- `docs/DECISIONS.md` — architecture decision records and status
- `docs/PROJECT_STATUS.md` — work completed, blockers, next priority
- `docs/DEPLOYMENT.md` — Ubuntu provisioning, bootstrap/join/drain, backup/restore
When a decision changes, update the corresponding source-of-truth document AND PROJECT_STATUS. Start each new Project chat by consulting the project files, not assuming all historical messages will be fetched reliably. Do not paste credentials, production tokens, or complete private device configurations into prompts or committed documents.

## 9. Immediate next task
Create **IPAT PRD v0.1** in the new ChatGPT Project, identifying assumptions, dependencies, architecture boundaries, seven-day MVP vs later commercial milestones, per-module acceptance criteria, testing risks, scalability/tenancy/security requirements, and exact device information still to be collected. Freeze the agreed scope before generating large volumes of code.
