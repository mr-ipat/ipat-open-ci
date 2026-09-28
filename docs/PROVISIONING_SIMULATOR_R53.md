# IPAT R5.3 — sealed, non-executable provisioning job simulator
**Date:** 2026-09-25 Asia/Jakarta · **Scope:** offline Rust simulator; no live RouterOS, queue, database or public API.

## Files and capability
- `crates/provisioning-core/src/lib.rs`: bounded (128-operation) synthetic bulk plan registry, tenant-scoped opaque references, exact plan+proposer+tenant idempotency, independent checker approval expiring within one hour, synthetic scoped workers, fenced 60-second maximum leases and per-router mutual exclusion.
- `deploy/scripts/lab/test_provisioning_synthetic_review.py`: three static guard tests against production proof constructors/transport exposure, plus bounded approval and lease constants.
- `Cargo.toml` and `Cargo.lock`: one local workspace crate and existing tenant-core only. No new external dependency.
- `.github/workflows/ci.yml`: static review and full locked Rust workspace, plus unchanged isolated PostgreSQL 16.9 RLS/restore job.

## Security boundary
- `VerifiedActor` and `VerifiedWorker` fields are private; there are **no production constructors**. Unit tests manufacture *synthetic* proofs. They do not prove OIDC, MFA, actual two-person identities, real router ownership or authenticated workers.
- The proposal contains **no PPPoE password, RouterOS connection or executable command**. This is an immutable synthetic proposed-operation list, **not a router-read diff** and not evidence of physical device capability.
- Duplicate idempotency keys with changed operation/proposer are rejected; different-tenant status access is hidden. Each claimed router is globally serialized in this in-memory simulation, even if separate tenants accidentally reference the same physical ID.
- Any expired lease enters `Unknown`; the router stays quarantined so *other* jobs cannot execute until a future audited reconciliation design is built. Failed/late worker completion and retry are rejected. There is no manual release API yet.
- Caller-provided synthetic timestamps, in-memory job ownership, unverified device identifiers and non-durable fencing cannot be connected to a live executor. `authz-core` continues to deny real `BulkPppoeWrite` unconditionally.

## Reproduce isolated tests
On a non-production checkout of Ubuntu 26.04.1 with pinned preinstalled Rust and cached dependencies:
```bash
cargo fmt --all -- --check
cargo test --workspace --locked --offline
python3 -m unittest discover deploy/scripts/lab -p test_provisioning_synthetic_review.py -v
```
No database migration is required for the offline simulator; R5.1 SQL migration remains the previously merged lab-only file. Do not create a public job endpoint or enable writes by treating this module as a durable queue.

## Verified pre-merge evidence
The separate nonprivileged Ubuntu 26.04.1 isolated checkout executed locked/offline workspace tests: **76/76 PASS** (68 existing + 8 new). `cargo fmt --check` and three Mac Python static contracts **PASS** after quarantine correction. CI result and canonical post-merge synchronization are separate finalization gates.

## Next MUST before any actual write
Implement trusted OIDC identity/service verification, review approval-role matrix, durable PostgreSQL outbox with transactional leases and fenced worker token, verified per-tenant global device ownership, real RouterOS read-only diff, crash/reconciliation/audit and independent restore tests. No real provisioning is approved by R5.3.

## Verified merged checkpoint (supersedes pre-merge checklist)
- PR #37 MERGED to private `main` `f4e2f8d0ed27f1bf1eeb039d2a751f0d4a5ad174`. Both GitHub jobs succeeded on PR run `36149621245` and post-merge run `36149777499`. The PostgreSQL RLS/logical restore ran solely in a disposable PostgreSQL 16.9 GitHub service container.
- That exact revision matched GitHub, Mac and the actual Ubuntu 26.04.1 lab VPS nonprivileged source checkout. Real VPS `cargo fmt --check`, **76/76 offline Rust tests**, **37/37 lab Python source contracts** and **5/5 DB migration static contracts** PASSED. Nothing was installed on the VPS as a service.
- Exact merged source encrypted Restic snapshot `18416643` restored independently with SHA-256 validation, historical partial config was re-restored, and the separate privileged selected-root-readable config snapshot `abaa9827` restored and validated; full Restic data read passed. A subsequent docs-only merge advances source HEAD and needs a new encrypted source capture. Full host/DB/cluster recovery and real physical device interop remain unverified.
