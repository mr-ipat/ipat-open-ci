# IPAT — Integrated Provisioning, Automation & Telemetry

IPAT (`IP@`) is a planned commercial multi-tenant ISP network operations platform. This repository is **work in progress**, currently an integrated laboratory MVP effort, **not production-ready**.

**Developer:** Mr. iPat · [Project attribution](AUTHORS.md)

## Official product documentation v0.1

- [Project binding brief](IPAT_PROJECT_BRIEF.md)
- [Product requirements and acceptance criteria](docs/PRD.md)
- [R5.1 synthetic PostgreSQL tenant RLS and isolated logical restore](docs/POSTGRES_TENANT_R51.md)
- [R5.2 synthetic evidence-led Rust diagnostics and negative scenarios](docs/DIAGNOSTICS_R52.md)
- [R5.3 sealed non-executable provisioning job simulator and test evidence](docs/PROVISIONING_SIMULATOR_R53.md)
- [R5.4 disposable PostgreSQL job/outbox isolation and restore test plan](docs/POSTGRES_JOB_OUTBOX_R54.md)
- [R5.5 read-only production readiness checks, recovery and staged DB/firewall/K3s plan](docs/PRODUCTION_INFRA_RECOVERY_R55.md)
- [R5.6 real disposable Ubuntu 26.04 K3s node, networking smoke and etcd snapshot](docs/K3S_UBUNTU26_R56.md)
- [R5.7 cross-host K3s restore, stale-node reconciliation and precise nft rollback](docs/K3S_CROSS_HOST_RECOVERY_R57.md)
- [R5.8 isolated health-only Rust apps, private Helm and real K3s smoke plan](docs/K3S_APPLICATION_PACKAGING_R58.md)
- [R5.9 local browser preview through SSH, strict guard and public-web prerequisites](docs/WEB_PRIVATE_PREVIEW_R59.md)
- [R6.0 eight planned device test slots and private offline metadata intake](docs/DEVICE_TESTING_R60.md)
- [R6.1 owner-reported MikroTik RB951Ui-2HnD and strictly gated first read-only REST test](docs/MIKROTIK_CUSTOMER_R61.md)
- [R6.2 original Rust RouterOS read-only normalization and offline private evidence validation](docs/ROUTEROS_RUST_R62.md)
- [R6.3 SSH host-key mismatch safety gate and independent customer router identity verification](docs/MIKROTIK_SSH_HOST_TRUST_R63.md)
- [R7.4 audited PRD gaps for Platform/Tenant/NOC dashboards](docs/DASHBOARD_PRD_AUDIT_R74.md)
- [R7.4 isolated C320 laboratory first-read safety runbook](docs/C320_ISOLATED_LAB_R74.md)
- [R7.5 approved rollout order: private integrated lab first, verified customer domains later](docs/LAB_FIRST_DOMAIN_LATER_R75.md)
- [R7.6 Fadly intended custom domain, SSH hostname collision and issuer-bound menu lab](docs/DOMAIN_INTENT_FADLY_R76.md)
- [R7.7 restricted disposable PostgreSQL identity lookup with negative RLS/privilege tests](docs/R77_SCOPED_IDENTITY_LOOKUP.md)
- [R7.8 joined private signed OIDC→restricted PostgreSQL→scoped server menu (synthetic CI proof)](docs/R78_PRIVATE_IDENTITY_TO_POSTGRES_MENU.md)
- [R7.9 remote-only C320 read candidate and VPS-provider-neutral private K3s planning](docs/C320_REMOTE_AND_K3S_PROVIDER_NEUTRAL_R79.md)
- [R8.0 synthetic pre-device signed-JWT to real restricted PostgreSQL NOC tenant/POP inventory](docs/R80_PREDEVICE_AUTHENTICATED_INVENTORY.md)
- [R8.1 original USP v1.4 genuine protobuf private read-only virtual agent](docs/R81_NATIVE_USP14_PROTOBUF_PRIVATE_VIRTUAL_AGENT.md)
- [R8.2 original Rust CWMP 1.0 real SOAP HTTP fixed virtual ONT (lab only)](docs/R82_CWMP_REAL_SOAP_VIRTUAL_ONT_PRIVATE_LAB.md)
- [R8.3 visible Device Manager with interactive Add/List/Status and separately gated PostgreSQL pending-adoption registry](docs/R83_DEVICE_WORKBENCH_AND_STAGED_ADOPTION.md)
- [R8.4 staged signed MFA claim and PostgreSQL independent maker-checker metadata review (LAB only)](docs/R84_SIGNED_MFA_MAKER_CHECKER_DEVICE_REVIEW_LAB.md)
- [R8.5 original Rust independent real IdP pinned signed MFA claim preflight (NO live login)](docs/R85_INDEPENDENT_REAL_IDP_SIGNED_MFA_ADMISSION_PREFLIGHT.md)
- [R8.6 Rust private OIDC S256 PKCE browser start/callback guard (CALLBACK ALWAYS DENIED)](docs/R86_PRIVATE_BROWSER_OIDC_PKCE_BEGIN_FAIL_CLOSED.md)
- [R8.7 original Rust pinned OIDC ID+access JWT nonce/at_hash signed pair validation (offline, NO SESSION)](docs/R87_PINNED_OIDC_ID_TOKEN_NONCE_AT_HASH_OFFLINE.md)
- [R8.8 original Rust offline opaque BFF session and sealed real PostgreSQL scoped identity bridge (NOT real login)](docs/R88_OFFLINE_SIGNED_PAIR_SEALED_SQL_SESSION_FOUNDATION.md)
- [R8.9 signed opaque BFF session to sealed PostgreSQL tenant/POP inventory (unmounted, not real login)](docs/R89_OPAQUE_SESSION_SQL_DEVICE_MANAGER_BRIDGE.md)
- [R9.0 owner-authorized first public ZTE-candidate TCP/Telnet network observation; actual VPS path blocked (NO LOGIN)](docs/R90_REAL_ZTE_CANDIDATE_TELNET_NETWORK_FIRST_CONTACT.md)
- [R9.1 adoption readiness gates before any physical read-only probe](docs/R91_DEVICE_ADOPTION_READINESS_GATES.md)
- [R9.2 durable nonexecuting first-read request and independent audit](docs/R92_IMMUTABLE_NONEXECUTABLE_READ_INTENT.md)
- [Technical architecture](docs/ARCHITECTURE.md)
- [Physical device and firmware test matrix](docs/DEVICE_MATRIX.md)
- [Security, tenant isolation and threat model](docs/SECURITY.md)
- [Architecture decision register](docs/DECISIONS.md)
- [Deployment/restore requirements](docs/DEPLOYMENT.md)
- [Seven-day sprint backlog](docs/SPRINT_BACKLOG.md)
- [Actual project status and verification evidence](docs/PROJECT_STATUS.md)
- [2026-09-25 Ubuntu lab server read-only inspection](docs/LAB_SERVER_READ_ONLY_2026-09-25.md)
- [Restricted laboratory stage-1 bootstrap and no-snapshot safety plan](deploy/scripts/lab/README.md)
- [Stage-2 SSH key-only hardening proposal and six-minute recovery timer](deploy/scripts/lab/STAGE2-SSH.md)
- [Verified Stage-2 SSH results and read-only K3s prerequisites](docs/LAB_K3S_READ_ONLY_2026-09-25.md)
- [R4.5 encrypted temporary Mac backup, real isolated restore and historical external-ingress observations](docs/LAB_ENCRYPTED_BACKUP_EDGE_R45.md)
- [R4.6 verified FileVault and live IPv6 exposure; generic perimeter dependency (historical evidence only)](docs/EDGE_SECURITY_GROUP_R46.md)
- [R4.7 root-config direct-encrypted streaming preparation and host recovery gate](docs/ROOT_CONFIG_STREAM_R47.md)
- [R4.8 optional first-party host firewall architecture and safety gates](docs/FIREWALL_CONTROL_PLANE.md)
- [R4.9 original Rust offline CWMP authenticated-identity boundary and bounded session simulator](docs/CWMP_ADMISSION_R49.md)
- [R5.0 separate native Rust USP Controller boundary and strictly synthetic tenant-safe correlation](docs/USP_SYNTHETIC_R50.md)

**Authority:** The approved Project Master Brief is binding. In `DECISIONS.md`, `PROPOSED` and `OPEN` items require explicit approval/evidence. A documentation draft, test fixture or protocol placeholder does not imply implementation, certification, device support or production readiness.

## Binding technical requirements

- Ubuntu Server 26.04 LTS, backend Rust/Tokio/Axum, original Rust TR-069/CWMP engine (not GenieACS).
- Native TR-369/USP Controller is mandatory as a separate boundary; initial MTP/broker require confirmation.
- Heterogeneous K3s worker scaling, bounded queues/leases and idempotent high-impact operations.
- PostgreSQL with independently designed/tested commercial HA, PITR and external backups.
- End-to-end multi-tenant isolation; verified identity, RBAC+ABAC deny-by-default; unauthorized UI menus invisible and backend/API requests rejected.
- Evidence-aware network diagnostics across distribution, OLT/PON/ONT, router/PPPoE and subscriber layers.
- Physical compatibility is always per exact model, firmware, interface and proven feature.

## Current laboratory boundaries (not a production release)

`crates/tenant-core` and `crates/authz-core` have synthetic tenant/policy tests. `apps/control-api` serves a loopback-only three-workspace **synthetic** dashboard with per-workspace red PRD gaps, while real business API paths still return HTTP401. The OIDC signature laboratory and unexposed candidate PostgreSQL membership schema are NOT an approved real login or server-side tenant/POP entitlement runtime.

`crates/cwmp-protocol` has bounded original Rust CWMP parser/RPC simulator tests. `apps/cwmp-gateway` has authentic TLS 1.3/mTLS cryptographic **loopback laboratory** tests, but its /cwmp route remains HTTP503 rather than an enrolled tenant-bound physical ACS. The native USP Controller boundary and normalized domain, diagnostics and provisioning remain simulator-level, without verified USP MTP or actual OLT/ONT interoperability. The C320 adapter accepts strict private **offline** synthetic evidence only; the R7.4 local readiness helper can never authorize connection or firmware writes.

On a prepared development host: `cargo fmt --all -- --check && cargo test --workspace --locked`; run local demo with `cargo run -p control-api`. See `docs/PROJECT_STATUS.md` for **actual** test results; never infer success solely from source presence.

- [R6.4 restricted SSH first-read laboratory path and explicit host identity safety](docs/MIKROTIK_SSH_R64.md)
- [R6.5 actual customer router access alternatives and independently verified WinBox preparation](docs/MIKROTIK_CUSTOMER_R65_PREP.md)
- [R6.6 original Rust CWMP bounded read RPC, sealed synthetic session and opt-in loopback HTTP gateway](docs/ACS_CWMP_R66.md)
- [R6.7 pengujian TLS 1.3 mTLS asli berbasis CA sintetis pada gateway ACS Rust yang hanya menerima localhost](docs/ACS_MTLS_R67.md)
- [R6.7 status kesiapan produk: laboratorium privat, bukan ACS/USP/SaaS produksi](docs/PRODUCT_READINESS_R67.md)
- [R6.8 tiga pratinjau dashboard Platform Admin, Tenant Admin dan NOC, dengan API nyata tetap terkunci](docs/DASHBOARDS_R68.md)
- [R6.9 pinned RS256 OIDC signature lab and deny-by-default Platform/Tenant/NOC auth boundary](docs/IDENTITY_OIDC_R69.md)
- [R7.0 PostgreSQL kandidat keanggotaan tenant, peran dan POP, plus jadwal bersyarat tiga dashboard](docs/DASHBOARD_MEMBERSHIP_R70.md)
- [R7.1 PERINGATAN MERAH: status PRD DEV-01 ZTE C320 fisik dan firmware belum siap, Rust parser offline saja](docs/PRD_DEVIATIONS_R71.md)
- [R7.2 DEV-01 ZTE C320 local SHA-256 firmware integrity check, NO OLT upgrade and full physical prerequisites](docs/C320_FIRMWARE_INTEGRITY_R72.md)
