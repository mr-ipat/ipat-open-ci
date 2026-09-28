# IPAT R5.4 — disposable PostgreSQL job and transactional outbox laboratory

**Developer:** Mr. iPat
**Scope:** isolated synthetic PostgreSQL 16.9 CI service only. No live database, device commands, worker, HTTP endpoint, real OIDC adapter or cluster deployment.

## Delivered paths and data boundary
- `deploy/db/migrations/0002_lab_job_outbox.sql` adds tenant- and POP-scoped provisioning jobs and outbox events after the existing R5.1 migration. The only normal runtime privilege on these new tables is SELECT, still restricted by `FORCE ROW LEVEL SECURITY`, tenant transaction scope and POP transaction scope. The NOLOGIN schema owner has a separate RLS policy for trusted synthetic migration/trigger operations.
- Composite `(tenant_id,router_id,pop_id)` foreign key restricts job↔device assignment; per-tenant unique idempotency keys and immutable synthetic plan digest prevent accidental silent request changes. A global partial unique index permits only one `leased` or `unknown` job for the **same synthetic router UUID**. This is not proof that a hardware router UUID cannot be spoofed or re-enrolled by another tenant.
- A defensive trigger rejects wrong transitions, self-approval by exact synthetic subject string, approvals longer than one hour, leases longer than 60 seconds, late completion and changes to immutable plan attributes. An expired lease moves to `unknown` and continues to quarantine the router until a separately designed audited recovery process exists.
- An AFTER INSERT/UPDATE trigger generates an outbox row within the **same PostgreSQL transaction**; failed/rolled-back changes create no durable event. Outbox carries only event name, immutable plan digest and synthetic IDs, not RouterOS credentials or subscriber secrets. There is **no publisher**, real worker, endpoint or external execution capability.

## Synthetic reproducible verification
Only in a freshly provisioned disposable PostgreSQL 16.9 instance at 127.0.0.1, with the explicit CI opt-in variables used by `.github/workflows/ci.yml`, first run the original R5.1 suite to create synthetic tenants and verify its original separate-database restore. Then run the new R5.4 suite on that same throwaway database:
```bash
python3 -m unittest discover deploy/db/tests -p test_migration_contract.py -v
python3 -m unittest discover deploy/db/tests -p test_job_migration_contract.py -v
# Disposable GitHub-hosted PostgreSQL service ONLY:
python3 -m unittest discover deploy/db/tests -p test_postgres_rls_integration.py -v
python3 -m unittest discover deploy/db/tests -p test_job_outbox_integration.py -v
```
The job test suite is explicitly gated to the exact synthetic database/host and requires the first suite's migration. It exercises tenant+POP negative read scenarios; read-only runtime; invalid key, immutable diff and cross-tenant router references; approval and lease guards; conflicting router claims; unknown-state quarantine; transaction rollback; and a new logical `pg_dump`→`pg_restore` database copy with SHA-256 comparison and post-restore RLS checks.

## Non-claims, next acceptance gates and rollback
A disposable privileged PostgreSQL **test harness** drives synthetic state changes. The runtime account cannot submit, approve, claim, mutate or publish jobs. SQL RLS with client-settable custom settings alone **does not authenticate** OIDC membership or an assigned POP, and the schema cannot cryptographically authenticate approvers/workers or validate actual physical router ownership. Neither a real atomic worker lease across nodes nor an external side-effect/no-double-write guarantee is proven merely by these SQL fixtures. Approval rule thresholds in ADR-009 and tenancy layout ADR-005 remain awaiting formal acceptance. Outbox integrity is limited to database transactions; no dispatcher or broker exists.

Do not apply the lab SQL to any running IPAT VPS/customer database or connect synthetic tests to non-disposable storage. A failed CI run is a failure, not evidence of successful R5.4 execution. Current live network, external shared perimeter, host firewall, SSH and K3s are unchanged. Until independent console/whole-host/DB recovery prerequisites pass, do not install PostgreSQL/K3s on the real VPS.

**Next MUST:** verify OIDC signature/issuer/audience/session/tenant membership through a reviewed identity adapter; enforce POP in actual API and DB transaction wrapper; identify routers through a unique trusted hardware registry; add restricted durable writer roles with high-risk approval and audit, reviewed transactional claim/reconciliation, outbox publisher with retry/dedup and full crash-injection tests in isolated infrastructure. Real RouterOS write remains forbidden.

## Verified executed GitHub, Ubuntu and Mac milestone evidence
- [Feature PR #39](https://github.com/mr-ipat/ipat/pull/39) MERGED to private `main` commit `4026a77847c2d4c26c981ad843221d76c14ef5ee`. Actual PR CI `36153298906` and real post-merge CI `36153496947` BOTH succeeded in both jobs. Real disposable PostgreSQL 16.9 executed R5.1 **5/5** original integration/restore tests and R5.4 **7/7** new transactional job/outbox integration/restore tests. Dedicated new-database `pg_dump`→`pg_restore` data checksum and tenant+POP RLS readback passed.
- Private GitHub, Mac, actual Ubuntu 26.04.1 nonprivileged checkout were synchronized to exactly the same reviewed SHA. Real Ubuntu verified `cargo fmt --check`, **76/76 Rust locked offline tests**, **37/37 lab static** and **5/5 + 5/5** SQL migration static safety checks PASS. No new live database daemon, app listener, external device connection, firewall or K3s was added.
- Encrypted Mac Restic snapshot `53f2a224` contains exactly this merged source SHA. A complete Restic pack data read, isolated checksum-verified latest-source and historical readable-config restores, and a separate privileged selected-root readable-config snapshot `abaa9827` recovery check succeeded, with private plaintext restore cleanup. A later docs-only SHA requires a separate new backup. Full VM recovery, offsite independent host rebuild, external PostgreSQL PITR and out-of-band console proof remain outstanding.
