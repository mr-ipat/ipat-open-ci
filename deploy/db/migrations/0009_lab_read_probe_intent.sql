-- R9.2 PRIVATE/disposable-only durable READ-PROBE REQUEST, never executable.
-- Even a recorded request cannot contact hardware: NO dispatcher, broker,
-- worker, credential or management address exists in this migration.
BEGIN;
CREATE TABLE ipat_ops.device_read_probe_intents (
 tenant_id uuid NOT NULL,
 candidate_id uuid NOT NULL,
 intent_id uuid NOT NULL DEFAULT gen_random_uuid(),
 request_id uuid NOT NULL,
 pop_id text NOT NULL CHECK (length(pop_id) BETWEEN 1 AND 128),
 requester_issuer text NOT NULL,
 requester_subject text NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 readiness_checked_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 state text NOT NULL DEFAULT 'awaiting_separate_execution_review'
  CHECK (state='awaiting_separate_execution_review'),
 must_revalidate_before_execution boolean NOT NULL DEFAULT true
  CHECK (must_revalidate_before_execution=true),
 PRIMARY KEY (tenant_id,intent_id),
 UNIQUE (tenant_id,candidate_id),
 UNIQUE (tenant_id,requester_issuer,requester_subject,request_id),
 FOREIGN KEY (tenant_id,candidate_id)
  REFERENCES ipat_ops.device_candidates(tenant_id,id)
);
ALTER TABLE ipat_ops.device_read_probe_intents OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.device_read_probe_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.device_read_probe_intents FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.device_read_probe_intents FROM PUBLIC,ipat_app_runtime,
 ipat_identity_query,ipat_device_registry_execute,ipat_device_review_execute,
 ipat_device_readiness_execute;

CREATE TABLE ipat_ops.device_read_probe_intent_audit (
 tenant_id uuid NOT NULL,
 event_id uuid NOT NULL DEFAULT gen_random_uuid(),
 intent_id uuid NOT NULL,
 event text NOT NULL DEFAULT 'nonexecutable_intent_recorded'
  CHECK (event='nonexecutable_intent_recorded'),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 published_at timestamptz,
 CHECK (published_at IS NULL),
 PRIMARY KEY (tenant_id,event_id),
 UNIQUE (tenant_id,intent_id),
 FOREIGN KEY (tenant_id,intent_id)
  REFERENCES ipat_ops.device_read_probe_intents(tenant_id,intent_id)
);
ALTER TABLE ipat_ops.device_read_probe_intent_audit OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.device_read_probe_intent_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.device_read_probe_intent_audit FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.device_read_probe_intent_audit FROM PUBLIC,ipat_app_runtime,
 ipat_identity_query,ipat_device_registry_execute,ipat_device_review_execute,
 ipat_device_readiness_execute;

CREATE ROLE ipat_read_intent_owner NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_read_intent_execute NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA ipat_platform TO ipat_read_intent_owner,ipat_read_intent_execute;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_read_intent_owner;
GRANT SELECT,INSERT ON ipat_ops.device_read_probe_intents TO ipat_read_intent_owner;
GRANT SELECT,INSERT ON ipat_ops.device_read_probe_intent_audit TO ipat_read_intent_owner;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_device_adoption_readiness(
 text,text,uuid,text,text) TO ipat_read_intent_owner;
CREATE POLICY intent_owner_select ON ipat_ops.device_read_probe_intents
 FOR SELECT TO ipat_read_intent_owner USING (true);
CREATE POLICY intent_owner_insert ON ipat_ops.device_read_probe_intents
 FOR INSERT TO ipat_read_intent_owner WITH CHECK (true);
CREATE POLICY intent_audit_owner_select ON ipat_ops.device_read_probe_intent_audit
 FOR SELECT TO ipat_read_intent_owner USING (true);
CREATE POLICY intent_audit_owner_insert ON ipat_ops.device_read_probe_intent_audit
 FOR INSERT TO ipat_read_intent_owner WITH CHECK (true);

-- The app MUST FIRST verify signed MFA+opaque browser session and current
-- CSRF and is the ONLY future permitted holder of the distinct EXECUTE role.
-- SQL still independently checks current NOC exact POP, all four live gates,
-- candidate approval and not-previously-probed status.
CREATE FUNCTION ipat_platform.request_lab_read_probe_intent(
 p_issuer text,p_subject text,p_tenant uuid,p_candidate uuid,
 p_request uuid,p_pop text
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
DECLARE created uuid; old_intent ipat_ops.device_read_probe_intents%ROWTYPE;
BEGIN
 IF p_issuer IS NULL OR length(p_issuer)=0 OR p_subject IS NULL
    OR length(p_subject)=0 OR p_tenant IS NULL OR p_candidate IS NULL
    OR p_request IS NULL OR p_pop IS NULL OR
    length(p_pop) NOT BETWEEN 1 AND 128 OR
    p_pop !~ '^[A-Za-z0-9_.-]+$'
 THEN RETURN NULL; END IF;
 -- One writer at a time for this exact tenant/candidate pair; this lock
 -- does NOT prevent later evidence revocation. Execution MUST revalidate.
 PERFORM pg_advisory_xact_lock(hashtextextended(
   p_tenant::text || ':' || p_candidate::text, 0));
 IF NOT EXISTS (
   SELECT 1 FROM ipat_platform.list_lab_device_adoption_readiness(
     p_issuer,p_subject,p_tenant,'noc_engineer',p_pop) r
   WHERE r.id=p_candidate AND r.pop_id=p_pop
     AND r.metadata_approved AND r.secure_management_path
     AND r.device_identity AND r.readonly_account
     AND r.recovery_plan AND r.read_probe_eligible
 ) THEN RETURN NULL; END IF;
 -- Enforce one permanent nonexecutable intent per exact candidate in
 -- this lab schema. Never turn idempotency retries into a new action.
 SELECT * INTO old_intent FROM ipat_ops.device_read_probe_intents
 WHERE tenant_id=p_tenant AND candidate_id=p_candidate;
 IF FOUND THEN
   IF old_intent.request_id=p_request AND old_intent.pop_id=p_pop
      AND old_intent.requester_issuer=p_issuer
      AND old_intent.requester_subject=p_subject
   THEN RETURN old_intent.intent_id; END IF;
   RETURN NULL;
 END IF;
 IF EXISTS (SELECT 1 FROM ipat_ops.device_read_probe_intents
   WHERE tenant_id=p_tenant AND requester_issuer=p_issuer
     AND requester_subject=p_subject AND request_id=p_request)
 THEN RETURN NULL; END IF;
 INSERT INTO ipat_ops.device_read_probe_intents(
  tenant_id,candidate_id,request_id,pop_id,requester_issuer,requester_subject
 ) VALUES(p_tenant,p_candidate,p_request,p_pop,p_issuer,p_subject)
 RETURNING intent_id INTO created;
 -- Same transaction: immutable PRIVATE AUDIT row, NOT a published
 -- network-execution outbox. No worker role or broker grants exist.
 INSERT INTO ipat_ops.device_read_probe_intent_audit(tenant_id,intent_id)
 VALUES (p_tenant,created);
 RETURN created;
END $body$;
ALTER FUNCTION ipat_platform.request_lab_read_probe_intent(
 text,text,uuid,uuid,uuid,text) OWNER TO ipat_read_intent_owner;
REVOKE ALL ON FUNCTION ipat_platform.request_lab_read_probe_intent(
 text,text,uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.request_lab_read_probe_intent(
 text,text,uuid,uuid,uuid,text) TO ipat_read_intent_execute;

-- NOC list is restricted per own tenant and exact approved POP, with no
-- address, evidence, reviewer, login secret, execution lease or broker topic.
CREATE FUNCTION ipat_platform.list_lab_read_probe_intents(
 p_issuer text,p_subject text,p_tenant uuid,p_pop text
) RETURNS TABLE(intent_id uuid,candidate_id uuid,pop_id text,state text,
                must_revalidate_before_execution boolean,requested_at timestamptz)
 LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
 SELECT i.intent_id,i.candidate_id,i.pop_id,i.state,
  i.must_revalidate_before_execution,i.requested_at
 FROM ipat_ops.device_read_probe_intents i
 JOIN ipat_platform.list_lab_device_adoption_readiness(
   p_issuer,p_subject,p_tenant,'noc_engineer',p_pop) r
  ON r.id=i.candidate_id AND r.pop_id=i.pop_id
 WHERE i.tenant_id=p_tenant AND i.pop_id=p_pop
 ORDER BY i.requested_at DESC,i.intent_id
 LIMIT 100
$body$;
ALTER FUNCTION ipat_platform.list_lab_read_probe_intents(
 text,text,uuid,text) OWNER TO ipat_read_intent_owner;
REVOKE ALL ON FUNCTION ipat_platform.list_lab_read_probe_intents(
 text,text,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_read_probe_intents(
 text,text,uuid,text) TO ipat_identity_query;
COMMIT;
