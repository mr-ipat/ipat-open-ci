#!/usr/bin/env bash
# Mr. iPat / IPAT: disposable GitHub Actions physical backup/restore rehearsal.
# NEVER run against a live server or persistent VPS; synthetic CI fixtures only.
set -Eeuo pipefail
umask 077
[[ "${GITHUB_ACTIONS:-}" == true &&
   "${IPAT_PG_EPHEMERAL_TEST:-}" == 1 &&
   "${PGHOST:-}" == 127.0.0.1 &&
   "${PGPORT:-}" == 5432 &&
   "${PGDATABASE:-}" == ipat_synthetic &&
   "${PGUSER:-}" == postgres &&
   "${PGPASSWORD:-}" == local_ci_synthetic_only ]] || {
  printf '%s\n' 'REFUSED: CI disposable synthetic PostgreSQL only' >&2
  exit 4
}
[[ -x /usr/lib/postgresql/16/bin/pg_ctl ]] || {
  printf '%s\n' 'Missing isolated CI-only PostgreSQL 16 host binaries' >&2
  exit 4
}
container="$(docker ps --filter ancestor=postgres:16.9 --format '{{.ID}}')"
[[ "$container" =~ ^[a-f0-9]{12,64}$ ]] || {
  echo 'Expected exactly one disposable PostgreSQL 16.9 service container' >&2
  exit 4
}
# The source is the disposable synthetic database created in earlier CI steps.
psql -XAt -v ON_ERROR_STOP=1 -c \
  "SELECT CASE WHEN to_regclass('ipat_ops.job_outbox') IS NOT NULL THEN 1 ELSE 0 END" |
  grep -Fxq 1
query="SELECT 'j:'||tenant_id||':'||id||':'||state FROM ipat_ops.provisioning_jobs
 UNION ALL SELECT 'o:'||tenant_id||':'||job_id||':'||event_type
 FROM ipat_ops.job_outbox ORDER BY 1"
source_hash="$(psql -XAt -v ON_ERROR_STOP=1 -c "$query" | sha256sum | awk '{print $1}')"
hostdir="$(mktemp -d /tmp/ipat-ci-physical.XXXXXXXX)"
started=0
cleanup() {
  if (( started )); then
    sudo -u postgres /usr/lib/postgresql/16/bin/pg_ctl -D "$hostdir" \
      -m immediate -w stop >/dev/null 2>&1 || true
  fi
  # Never accept an arbitrary deletion path.
  if [[ "$hostdir" == /tmp/ipat-ci-physical.* && -d "$hostdir" ]]; then
    sudo rm -rf -- "$hostdir"
  fi
}
trap cleanup EXIT
# Create physical backup within container to use its local replication HBA,
# then copy it to the separate ephemeral runner's PostgreSQL server process.
docker exec -u postgres -e PGPASSWORD=local_ci_synthetic_only "$container" \
  pg_basebackup -h 127.0.0.1 -U postgres \
    -D /tmp/ipat-ci-basebackup -F plain -X stream -c fast
docker exec -u postgres "$container" pg_verifybackup /tmp/ipat-ci-basebackup
docker cp "$container:/tmp/ipat-ci-basebackup/." "$hostdir/"
/usr/lib/postgresql/16/bin/pg_verifybackup "$hostdir"
sudo chown -R postgres:postgres "$hostdir"
# This is an independent disposable POSTGRES SERVER PROCESS on the CI runner,
# but NOT a separately resilient machine, offsite recovery or production PITR.
sudo -u postgres /usr/lib/postgresql/16/bin/pg_ctl -D "$hostdir" \
  -l "$hostdir/server.log" \
  -o '-c listen_addresses=127.0.0.1 -p 5544 -c unix_socket_directories=/tmp' \
  -w start >/dev/null
started=1
restored_hash="$(PGPORT=5544 psql -XAt -v ON_ERROR_STOP=1 -c "$query" \
  | sha256sum | awk '{print $1}')"
[[ -n "$source_hash" && "$source_hash" == "$restored_hash" ]] || {
  echo 'FAIL: synthetic physical restored records hash mismatch' >&2
  exit 1
}
# Scoped RLS must also hold on the separately started server.
unscoped="$(PGPORT=5544 PGUSER=ipat_app_runtime \
  psql -XAt -v ON_ERROR_STOP=1 \
    -c 'SELECT count(*) FROM ipat_ops.provisioning_jobs' | tr -d '[:space:]')"
[[ "$unscoped" == 0 ]] || {
  echo 'FAIL: restored runtime role unexpectedly sees unscoped jobs' >&2
  exit 1
}
echo 'EPHEMERAL_POSTGRES_PHYSICAL_BACKUP_VERIFY_AND_SEPARATE_SERVER_RESTORE=PASS'
echo 'EPHEMERAL_POSTGRES_RESTORED_JOB_OUTBOX_SHA256_AND_RLS=PASS'
echo 'NOT_PRODUCTION_PITR_OR_INDEPENDENT_FAILURE_DOMAIN'
