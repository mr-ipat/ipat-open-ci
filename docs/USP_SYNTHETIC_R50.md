# R5.0 — native Rust USP Controller boundary and protected synthetic correlation

**Date:** 2026-09-25 (Asia/Jakarta). Status: **Rust synthetic domain tests PASS; actual TR-369/USP protocol support NOT YET IMPLEMENTED**. Review alongside binding PRD FR-013/014 and AC-04, original architecture ADR-002 (native standalone USP required), ADR-007 (MQTT initial MTP merely proposed) and SECURITY T-05 (USP spoof/replay).

## 1. Exactly what is delivered

- New `crates/usp-core` is a Rust in-memory, transport-independent **synthetic simulator** of trusted agent registration, tenant-bound read-only planning and request/reply correlation. Agent enrollment binds one exact synthetic `endpoint_id`, tenant and pinned synthetic client-SPKI SHA-256; duplicate agents and reused identities across enrollments reject.
- `VerifiedAgent` and `TrustedOperator` intentionally have **no public constructors**, so untrusted MQTT topic names, request headers or a user-supplied endpoint cannot create an authenticated device or privileged operator. The only fabrications live inside `#[cfg(test)]` unit tests; a future real TLS/OIDC/broker adapter must be independently tested before these boundaries become usable.
- A validated **synthetic read-only** parameter plan targets a constrained `Device.`-prefixed fixture path and issues a bounded opaque local request ID. The simulated reply must match the enrolled tenant, pinned verified peer, endpoint ID and exact in-flight correlation, enforce message/payload limits and reject replay and saturation without silent eviction. No actual USP Record or Msg is serialized or parsed, and no device configuration write path is present.
- New `apps/usp-controller` boots a **loopback-only optional health endpoint** only when `IPAT_RUN_OFFLINE_USP_LAB=1` is explicitly set in a local lab. Its default code path refuses startup, its only route is `/healthz`, and every other route returns `503` (including a request with spoofed tenant/agent headers). Three Axum oneshot router tests exercise the health and no-protocol-route behavior. The process has **not** been launched on the live VPS or made public.

## 2. Trust and standard limitations

**This is not yet TR-369/USP wire compatibility or a real native controller deployment.** There is no pinned Broadband Forum USP protobuf schema, amendment profile, USP Record/Msg serialization, selected MTP/broker, mTLS trust anchor, USP controller credential or actual vendor agent tested. `Device.` fixture paths are syntax-restricted test data, not an assertion of a real supported data-model feature. A synthetic correlation-only flow **does not satisfy** PRD AC-04's compatible agent or protocol PoC acceptance requirement.

The next real USP milestone must first pin the applicable official schema/protocol version, create a native Rust protobuf Record/Msg module, verify trust binding at a separate audited MTP/broker boundary with strict topic ACL and independent tenant membership, then run an actual wire-level synthetic agent interaction with bounded replay/durable audit evidence. MQTT is still **PROPOSED**, not implicitly approved just because the Rust modular boundary now exists. Device support claims require exact model, firmware and feature/transport evidence.

Both request and replay sets are **in-memory and reset on process restart** in this restricted simulator. Real operation needs durable request IDs, retry/timeout/fencing, persistent replay state, tenant isolation on queues and one consistent answer to ambiguous device side effects. Platform roles and high-risk approvals are not currently connected to the synthetic unit tests. The future runtime MUST NOT allow users to turn synthetic proofs or health-only handlers into a public USP endpoint.

## 3. Reproduce without exposing services

On the Ubuntu 26.04 non-root workspace:

```bash
cd ~/workspaces/ipat
cargo fmt --all -- --check
cargo test --workspace --locked --offline
cargo test -p usp-core --locked --offline
cargo test -p usp-controller --locked --offline
```

Running tests uses Axum's in-process router without binding a network port. The real Ubuntu isolated pre-merge checkout passed **12 `usp-core` synthetic tests and 3 `usp-controller` private router tests**, alongside existing 43 Rust tests: total **58 passing**. The source-only review checks and GitHub CI plus post-merge canonical source backup are additional finalization gates.

Do not start `cargo run -p usp-controller` or create systemd/Kubernetes exposure on the live lab while recovery-console and network safety gates remain unresolved. No host firewall rules, provider perimeter, K3s cluster, database schema or actual ONT/USP agent access is changed by this milestone.

## 4. Next engineering queue

**MUST:** actual official USP protocol profile/schema and real wire-level simulator with cryptographically verified enrollment, native protobuf record/message validation, durable request/replay store, protocol-specific negative tenant and broker ACL tests; keep native Controller separate from ACS as approved ADR-002.

**SHOULD:** integrate production-capable authenticated OIDC and durable PostgreSQL multi-tenant backend with RLS/backup, then real simulation across CWMP and USP normalized device model. This requires schema/migration and separate isolated restore evidence.

**LATER:** MTP and firmware-specific live USP agent interop after model/firmware and routing inventory, meaningful resilience/load tests and eventual production HA. Do not claim real USP support or operator GUI before these tests and deployments.


## Final R5.0 integration verification (post-merge)

PR #31 **MERGED** as private GitHub `main` `1a41f4afbb1aaa40605fb9718bb1c402ddf1ac0a`. The exact commit was verified and synchronized to the real Ubuntu 26.04.1 VPS and authorized Mac. GitHub main CI `36139345001` returned **SUCCESS**. The real Ubuntu canonical checkout passed `cargo fmt --all -- --check`, **58 Rust unit/synthetic tests**, and **34 Python static lab safety checks**; the opt-in loopback health binary was not launched on the live VPS. Latest source was backed up into encrypted Mac Restic snapshot `adebecc4`, independently restored with SHA-256 verification; the previously acquired privileged selected root config snapshot `abaa9827` was also independently restored. Full Restic `check --read-data` verified **15 snapshots/28 packs** with no errors; temporary test plaintext removed.

This evidence confirms source, pure simulator domain and read-only backup checks **only**. A real USP protobuf Record/Msg, MTP, authorized agent, real parameter read, physical device support, full host/DB restore and K3s firewall/cluster deployment **remain unimplemented/unverified**. The GitHub history retains the actual CI and limitations instead of claiming standard conformance or production readiness.
