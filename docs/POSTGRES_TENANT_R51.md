# IPAT R5.1 — synthetic PostgreSQL tenant RLS and isolated logical restore

**Scope:** separate disposable GitHub Actions PostgreSQL 16.9 container only, not the live Ubuntu VPS. This milestone begins to implement the data boundary described in `ARCHITECTURE.md` and **PROPOSED ADR-005**, without treating that proposal as final product architecture.

## Delivered source
- `deploy/db/migrations/0001_lab_tenant_rls.sql`: first **LAB-ONLY** SQL migration for separate platform metadata (`ipat_platform.tenants`) and tenant operational data (`ipat_ops.devices`, `ipat_ops.subscribers`). Both operational tables use composite `(tenant_id,id)` primary keys and `ENABLE/FORCE ROW LEVEL SECURITY`; subscriber→device relationships use a composite same-tenant FK. Distinct schema owner and constrained non-superuser/non-BYPASSRLS runtime role; runtime receives only scoped table DML. `tenant_id` is read from transaction-local PostgreSQL `ipat.tenant_id`, which must originate in a **future trusted API adapter** after real OIDC membership verification, never from request headers.
- `deploy/db/tests/test_postgres_rls_integration.py`: **opt-in ephemeral-only** integration tests using two fully synthetic tenants. Tests an unscoped runtime returning zero rows, tenant A/B row isolation, cross-tenant INSERT/UPDATE failures, denied `TRUNCATE`/platform schema access, malformed tenant setting failures, `FORCE RLS`/runtime role flags, and a binary `pg_dump` restored into a **second clean database in the same ephemeral CI cluster** with synthetic source-vs-restore row checksum comparison and RLS rechecks.
- `deploy/db/tests/test_migration_contract.py`: five independent source-safety assertions; migration integration job is deliberately separate from Rust unit tests. No database software, daemon, port, account or firewall will be installed or changed on the live VPS by this PR.

## Run locally (ONLY on an explicitly disposable PostgreSQL instance)
The CI job is the reproducible integration environment. It starts a throwaway PostgreSQL 16.9 service and uses **synthetic, hard-coded CI-only placeholder** authentication inaccessible to actual IPAT deployments. Never use this sample credential in any live environment. Run after setting `IPAT_PG_EPHEMERAL_TEST=1`, `PGHOST=127.0.0.1`, `PGDATABASE=ipat_synthetic`, and separately configured synthetic `PGUSER`, `PGPASSWORD`, `IPAT_PG_SYNTHETIC_PASSWORD`; the Python suite fails to proceed on other database names/hosts and checks that the target migration does not already exist. Only a trusted disposable test container should run this exact fixture.

```bash
python3 -m unittest discover deploy/db/tests -p test_migration_contract.py -v
# Ephemeral CI container only, after explicit synthetic environment setup:
python3 -m unittest discover deploy/db/tests -p test_postgres_rls_integration.py -v
```

## Security and acceptance limitations
This only tests PostgreSQL RLS behavior under synthetic connections. **The application still lacks a trusted OIDC runtime binding, non-leaking connection pool, immutable tenant-context enforcement, production-safe migration tooling and tenant backup segregation.** PostgreSQL GUC variables can be set by SQL clients; RLS alone is not a defense if arbitrary user SQL/SQL injection is possible. The separate restored DB shares roles and host with its source, so it is a **synthetic isolated database logical-restore drill**, not independently rebuilt infrastructure, PostgreSQL PITR or a full production AC-07 acceptance. PostgreSQL owner/superuser and logical dump access can see all tenants and need separately reviewed controls.

**No server change:** K3s, live PostgreSQL, host native firewall, external perimeter, and any customer CPE/OLT remain untouched pending recovery-console and architecture gates. Tests executed and CI outcomes must be updated in `PROJECT_STATUS.md` only after actual results are observed.


## Actual GitHub-hosted isolated integration evidence

The initial PR #33 job `postgres-rls-restore` used a real throwaway PostgreSQL **16.9 server image**, PostgreSQL client 16.15 on an isolated GitHub-hosted Ubuntu 24.04 runner. The five ACTUAL integration tests **PASS** in [workflow 36141744263](https://github.com/mr-ipat/ipat/actions/runs/36141744263), including deliberately denied RLS writes, runtime role limitations, cross-tenant FK, transaction-scoped isolation, malformed tenant and separate *new-database* `pg_dump`→`pg_restore` with identical synthetic records checksum and scoped policy reread. The expected negative-case database errors are part of intentional tests, not production incidents. CI also passed preexisting Rust/unit job. Migration/fixture static regression check was subsequently added to the Rust CI job before final merge; verify its result in the next CI run.

**What this does NOT prove:** runtime API claims/trust, session/connection pool isolation, Linux deployment, real subscriber data, external/off-host PostgreSQL backup retention, independently rebuilt DB host, PITR, HA or production acceptance. The CI-only synthetic password is a disposable test fixture and must never be reused as a deployment password.


## Post-merge verified checkpoint

PR **#33** merged to private `main` SHA `7b69e6eb5851eb370beec76933ea82f32d5cae88`. Actual post-merge GitHub Actions [workflow 36142084702](https://github.com/mr-ipat/ipat/actions/runs/36142084702) returned **SUCCESS** for both original workspace/unit job and isolated PostgreSQL RLS/restore job (5 real database tests), with five additional static SQL-safety-contract tests in the main job. The canonical SHA matched GitHub, the authorized Mac and actual Ubuntu 26.04.1 host. The real Ubuntu source checkout independently passed Rust formatting, **58/58 Rust synthetic/unit tests**, 34 existing Python lab static checks and 5 new DB static checks (the actual database integration tests ran only inside the disposable GitHub PostgreSQL service; PostgreSQL is NOT installed on the live VPS).

Restic snapshot `5ca4ed6a` encrypted the exact merged Git source; its checksum-verified isolated restore and the earlier partial readable-config restore passed. Independently re-restoring the actual selected privileged root configuration snapshot `abaa9827` also passed, including the expected root `sudoers` member, managed SSH key-only configuration and private test cleanup. The full encrypted repository `restic check --read-data` read **17 snapshots/32 packs with zero errors**.

A subsequent documentation-only PR will move `main` to a new SHA. Encrypt/revalidate the new canonical source after that merge; do not interpret older source snapshot SHA as the final current HEAD. Nothing changed on live VPS except fast-forwarding the nonprivileged Git workspace. Host firewall, K3s and PostgreSQL server are NOT installed/modified.
