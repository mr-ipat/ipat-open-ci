# R4.9 — Native CWMP offline tenant-enrollment and session admission

**Date:** 2026-09-25 (Asia/Jakarta). Status: **offline synthetic laboratory PASS, network gateway NOT IMPLEMENTED**. Built from the binding IPAT brief, current PRD FR-009/010 and AC-03, architecture trust chain, SECURITY SEC-04/T-03/T-04, DECISIONS ADR-001/009 and current GitHub project status.

## 1. Implemented, testable native Rust boundary

`crates/cwmp-admission` links the existing **original** bounded CWMP 1.0 SOAP Inform parser/serializer (`cwmp-protocol`) with the current immutable `tenant-core::TenantId`. This is not GenieACS.

- An audited (future) operator enrollment record binds a unique OUI/product-class/serial tuple, **one tenant**, and a pinned client-SPKI SHA-256. Same device duplicate and a reused certificate across device enrollments are rejected.
- `AuthenticatedPeer` has **no public constructor**: an attacker-supplied HTTP header, SOAP `DeviceId` or hostname cannot mint a transport-authenticated peer. Synthetic proof creation is present **only within unit tests**. This is intentionally *unusable from an external listener* until an independently verified mTLS adapter and actual authorized enrollment store are implemented.
- Admission parses bounded XML without DTD, checks an existing enrollment, compares a **trusted** routing tenant and pinned verified peer identity, requires a CWMP `ID` in this restricted synthetic flow, then creates an in-memory per-device lease and namespaced `InformResponse`. Invalid or unverifiable identity yields **no session and no response**.
- Repeated correlation IDs and overlapping active Inform attempts for the same device are rejected; total enrollments, active leases and replay entries are bounded and **fail closed** at capacity, rather than silently discarding replay protection. Completing a lease requires the original authenticated peer and opaque local ticket.
- Only sanitized event counts and pure response XML are exposed from the admission object. No device password, SOAP credentials, subscriber data, actual serial/fingerprint debug logger, database mutation, network listener or vendor-device write path exists in this crate.

## 2. Trust-boundary restrictions and known gaps

**Not a public ACS.** The future mTLS edge must validate actual CA trust, client-certificate chain, expiry/revocation/purpose and verified tenant/device enrollment; the sealed `AuthenticatedPeer` interface will only then be opened to that narrowly reviewed TLS adapter. Do not introduce a public `AuthenticatedPeer::new` or accept a spoofable `X-Client-Cert`/tenant header. Internal identity/tenant mismatch diagnostics must map to a **uniform public denial**, without leaking whether a serial/certificate/tenant exists.

**Not a production CWMP session engine.** This in-memory synthetic model cannot persist anti-replay across restart, handle real CWMP transport retry semantics, negotiate other CWMP versions, implement parameter RPC, device-originated empty POST/ACS response lifecycle, accurate SOAP faults, session timeouts or durable enrollment. It conservatively rejects a reused CWMP ID; a real adapter needs standards-tested retries and durable replay/idempotency state before it can be exposed. It does not satisfy FR-009 HTTPS authenticated transport, all FR-010 requirements or full PRD AC-03.

**No live exposure:** the actual Ubuntu server's SSH and existing network configuration remain unchanged; no HTTP ACS listener, K3s, PostgreSQL, host nftables or shared external perimeter rule was installed or modified. Exact physical ZTE/VSOL device models/firmware have not been inventoried or tested. Simulator evidence is not physical interoperability evidence.

## 3. Reproduce on the existing Ubuntu 26.04 laboratory (read-only source execution)

```bash
cd ~/workspaces/ipat
cargo fmt --all -- --check
cargo test --workspace --locked --offline
cargo test -p cwmp-admission --locked --offline
```

These commands compile and test using the user's existing non-root Rust installation; they do **not** start listeners or modify firewall/network settings. The isolated pre-merge checkout on actual Ubuntu was already verified using `cargo test --workspace --offline` and all **43** Rust unit/simulator tests (23 existing basic/CWMP, nine firewall-policy, **eleven new CWMP admission**) passed. Also three Mac/CI source-only trust-boundary review checks were added, verifying the test-only proof constructor stays sealed and no HTTP listener or externally supplied certificate-header fallback appears in the module. Final canonical main/CI re-verification and recorded SHA are required after PR merge.

## 4. Next acceptance gates (not claimed completed)

**MUST:** implement a real, authenticated TLS edge in a private integration environment with verified real client certificate, bounded request bodies and timeout/rate-limit handling; a secure enrollment backend; durable session/replay records and redacted audit. Prove independent cross-tenant and rogue-certificate rejection end to end. Only then enable any CWMP HTTP listener.

**SHOULD:** simulator CWMP `GetParameterValues` session transaction and a safe network-transport fixture (not a public service), then standards/version selection and explicit actual ONT model/firmware testing. Native USP Controller remains a separate mandated module; the controller/broker security choice ADR is still open.

**LATER:** production-scale shared distributed session ownership, resilient store and per-model physical interoperability/certification claims, only after sufficient evidence and recovery gates.


## R4.9 verified post-merge historical evidence

PR #30 merged to private GitHub `main` `0e354e5445fc9ed3a1d6989f4ef2ae8712923afc`. Actual final main CI `36137997641` passed. Exact private GitHub/Mac/actual Ubuntu source SHAs were independently matched. Real Ubuntu `cargo fmt --check`, **43 Rust unit/synthetic tests**, and **31 lab static checks** passed. The canonical source snapshot `167fe785` and separately captured selected-root-config snapshot `abaa9827` were decrypted and isolated-restore checked; Restic full read-data verification covered **14 snapshots/26 packs** at that milestone. No real authenticated CWMP HTTP listener, durable device/session store, SOAP RPC beyond synthetic parsing or physical ONT testing has been implemented; the later R5.0 standalone native USP core does not change these limitations.
