-- Mr. iPat / IPAT R5.4: disposable PostgreSQL 16 synthetic job/outbox lab.
-- Requires 0001_lab_tenant_rls.sql; never apply on a real/live database.
-- Trusted simulator migration owner drives transitions; app runtime READ ONLY.
BEGIN;
-- POP binding is part of the physical router reference, not a request header.
CREATE UNIQUE INDEX devices_tenant_router_pop_ref
 ON ipat_ops.devices (tenant_id,id,pop_id);
CREATE TABLE ipat_ops.provisioning_jobs (
 tenant_id uuid NOT NULL REFERENCES ipat_platform.tenants(id),
 id uuid NOT NULL,
 router_id uuid NOT NULL,
 pop_id text NOT NULL CHECK (length(pop_id) BETWEEN 1 AND 128),
 idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
 plan_digest text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
 requested_by text NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 128),
 approved_by text CHECK (approved_by IS NULL OR length(approved_by) BETWEEN 1 AND 128),
 approval_expires_at timestamptz,
 lease_owner text CHECK (lease_owner IS NULL OR length(lease_owner) BETWEEN 1 AND 128),
 lease_epoch bigint NOT NULL DEFAULT 0 CHECK (lease_epoch >= 0),
 lease_until timestamptz,
 state text NOT NULL DEFAULT 'awaiting_approval'
   CHECK (state IN ('awaiting_approval','approved','leased','unknown','completed','rejected')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_id,id),
 UNIQUE (tenant_id,idempotency_key),
 CONSTRAINT job_router_same_tenant_pop_fk FOREIGN KEY (tenant_id,router_id,pop_id)
   REFERENCES ipat_ops.devices(tenant_id,id,pop_id),
 CONSTRAINT no_synthetic_self_approval CHECK
   (approved_by IS NULL OR approved_by <> requested_by)
);
ALTER TABLE ipat_ops.provisioning_jobs OWNER TO ipat_schema_owner;
-- Even across tenants, a shared synthetic router UUID cannot hold two leases.
-- Physical router ownership/canonical IDs MUST still be independently verified.
CREATE UNIQUE INDEX one_unresolved_job_per_router_uuid
 ON ipat_ops.provisioning_jobs(router_id) WHERE state IN ('leased','unknown');
CREATE TABLE ipat_ops.job_outbox (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL DEFAULT gen_random_uuid(),
 job_id uuid NOT NULL,
 pop_id text NOT NULL CHECK (length(pop_id) BETWEEN 1 AND 128),
 event_type text NOT NULL
   CHECK (event_type IN ('awaiting_approval','approved','leased','unknown','completed','rejected')),
 plan_digest text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 published_at timestamptz, -- never published by this simulator
 PRIMARY KEY (tenant_id,id),
 UNIQUE (tenant_id,job_id,event_type),
 CONSTRAINT outbox_job_same_tenant_fk FOREIGN KEY (tenant_id,job_id)
   REFERENCES ipat_ops.provisioning_jobs(tenant_id,id)
);
ALTER TABLE ipat_ops.job_outbox OWNER TO ipat_schema_owner;
-- Never expose arbitrary job/outbox SQL writes to the normal runtime role.
GRANT SELECT ON ipat_ops.provisioning_jobs,ipat_ops.job_outbox TO ipat_app_runtime;
ALTER TABLE ipat_ops.provisioning_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.provisioning_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.job_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.job_outbox FORCE ROW LEVEL SECURITY;
-- NOLOGIN owner gets RLS permission only for trigger/migration-controlled writes.
CREATE POLICY jobs_schema_owner ON ipat_ops.provisioning_jobs
 FOR ALL TO ipat_schema_owner USING (true) WITH CHECK (true);
CREATE POLICY outbox_schema_owner ON ipat_ops.job_outbox
 FOR ALL TO ipat_schema_owner USING (true) WITH CHECK (true);
-- Runtime SQL sees only its transaction-scoped tenant AND assigned POP.
-- Actual credential/membership/POP verification is NOT part of this migration.
CREATE POLICY jobs_scoped_read ON ipat_ops.provisioning_jobs
 FOR SELECT TO ipat_app_runtime USING (
  tenant_id = NULLIF(current_setting('ipat.tenant_id',true),'')::uuid
  AND pop_id = NULLIF(current_setting('ipat.pop_id',true),'')
 );
CREATE POLICY outbox_scoped_read ON ipat_ops.job_outbox
 FOR SELECT TO ipat_app_runtime USING (
  tenant_id = NULLIF(current_setting('ipat.tenant_id',true),'')::uuid
  AND pop_id = NULLIF(current_setting('ipat.pop_id',true),'')
 );
-- Guard every state transition, immutable plan and constrained lease.
-- This checks data invariants, NOT actual human/service identity.
CREATE FUNCTION ipat_ops.guard_synthetic_job() RETURNS trigger
LANGUAGE plpgsql SET search_path = '' AS $fn$
DECLARE now_utc timestamptz := pg_catalog.clock_timestamp();
BEGIN
 IF TG_OP = 'INSERT' THEN
  IF NEW.state <> 'awaiting_approval' OR NEW.approved_by IS NOT NULL
   OR NEW.approval_expires_at IS NOT NULL OR NEW.lease_owner IS NOT NULL
   OR NEW.lease_until IS NOT NULL OR NEW.lease_epoch <> 0 THEN
   RAISE EXCEPTION 'lab job must start as unsigned draft';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.tenant_id,NEW.id,NEW.router_id,NEW.pop_id,NEW.idempotency_key,
        NEW.plan_digest,NEW.requested_by,NEW.created_at)
    IS DISTINCT FROM
    ROW(OLD.tenant_id,OLD.id,OLD.router_id,OLD.pop_id,OLD.idempotency_key,
        OLD.plan_digest,OLD.requested_by,OLD.created_at) THEN
  RAISE EXCEPTION 'immutable synthetic job payload changed';
 END IF;
 IF NEW.state = OLD.state THEN
  RAISE EXCEPTION 'no mutable in-place job fields';
 END IF;
 IF OLD.state = 'awaiting_approval' AND NEW.state = 'approved' THEN
  IF NEW.approved_by IS NULL OR NEW.approved_by = OLD.requested_by
   OR NEW.approval_expires_at IS NULL OR NEW.approval_expires_at <= now_utc
   OR NEW.approval_expires_at > now_utc + interval '1 hour'
   OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
   OR NEW.lease_epoch <> 0 THEN
   RAISE EXCEPTION 'synthetic approval invariant failed';
  END IF;
 ELSIF OLD.state = 'awaiting_approval' AND NEW.state = 'rejected' THEN
  IF NEW.approved_by IS NOT NULL OR NEW.approval_expires_at IS NOT NULL
   OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL
   OR NEW.lease_epoch <> 0 THEN
   RAISE EXCEPTION 'invalid synthetic rejection';
  END IF;
 ELSIF OLD.state = 'approved' AND NEW.state = 'leased' THEN
  IF OLD.approval_expires_at <= now_utc
   OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
   OR NEW.approval_expires_at IS DISTINCT FROM OLD.approval_expires_at
   OR NEW.lease_owner IS NULL OR NEW.lease_epoch <> OLD.lease_epoch + 1
   OR NEW.lease_until IS NULL OR NEW.lease_until <= now_utc
   OR NEW.lease_until > now_utc + interval '60 seconds'
   OR NEW.lease_until > OLD.approval_expires_at THEN
   RAISE EXCEPTION 'synthetic lease invariant failed';
  END IF;
 ELSIF OLD.state = 'leased' AND NEW.state IN ('unknown','completed') THEN
  IF NEW.approved_by IS DISTINCT FROM OLD.approved_by
   OR NEW.approval_expires_at IS DISTINCT FROM OLD.approval_expires_at
   OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
   OR NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch
   OR NEW.lease_until IS DISTINCT FROM OLD.lease_until
   OR (NEW.state = 'unknown' AND OLD.lease_until > now_utc)
   OR (NEW.state = 'completed' AND OLD.lease_until <= now_utc) THEN
   RAISE EXCEPTION 'synthetic completion/reconciliation invariant failed';
  END IF;
 ELSE
  RAISE EXCEPTION 'forbidden synthetic job state transition';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION ipat_ops.guard_synthetic_job() OWNER TO ipat_schema_owner;
REVOKE ALL ON FUNCTION ipat_ops.guard_synthetic_job() FROM PUBLIC;
CREATE TRIGGER enforce_synthetic_job_state
 BEFORE INSERT OR UPDATE ON ipat_ops.provisioning_jobs
 FOR EACH ROW EXECUTE FUNCTION ipat_ops.guard_synthetic_job();

-- An outbox row is written in the SAME transaction as its job transition.
CREATE FUNCTION ipat_ops.emit_synthetic_job_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $fn$
BEGIN
 INSERT INTO ipat_ops.job_outbox (tenant_id,job_id,pop_id,event_type,plan_digest)
 VALUES (NEW.tenant_id,NEW.id,NEW.pop_id,NEW.state,NEW.plan_digest);
 RETURN NEW;
END
$fn$;
ALTER FUNCTION ipat_ops.emit_synthetic_job_event() OWNER TO ipat_schema_owner;
REVOKE ALL ON FUNCTION ipat_ops.emit_synthetic_job_event() FROM PUBLIC;
CREATE TRIGGER synthetic_job_transactional_outbox
 AFTER INSERT OR UPDATE OF state ON ipat_ops.provisioning_jobs
 FOR EACH ROW EXECUTE FUNCTION ipat_ops.emit_synthetic_job_event();
COMMIT;
