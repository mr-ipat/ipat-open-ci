-- R9.7 disposable-only per-tenant connection-choice DRAFT, not tunnel config.
-- No real endpoints, credentials, keys, route or executable outbox allowed.
BEGIN;
CREATE TABLE ipat_ops.tenant_connection_drafts (
 tenant_id uuid NOT NULL,
 candidate_id uuid NOT NULL,
 draft_id uuid NOT NULL DEFAULT gen_random_uuid(),
 request_id uuid NOT NULL,
 pop_id text NOT NULL CHECK(pop_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
 method text NOT NULL CHECK(method IN('direct_secure','wireguard','ipsec')),
 gateway text NOT NULL CHECK(gateway IN('routeros7','routeros6','linux','none')),
 state text NOT NULL DEFAULT 'awaiting_separate_review'
  CHECK(state='awaiting_separate_review'),
 provisioning_enabled boolean NOT NULL DEFAULT false CHECK(provisioning_enabled=false),
 requested_issuer text NOT NULL, requested_subject text NOT NULL,
 requested_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 CHECK(NOT(method='wireguard' AND gateway IN('routeros6','none'))),
 CHECK(NOT(method='ipsec' AND gateway='none')),
 PRIMARY KEY(tenant_id,draft_id), UNIQUE(tenant_id,candidate_id),
 UNIQUE(tenant_id,requested_issuer,requested_subject,request_id),
 FOREIGN KEY(tenant_id,candidate_id) REFERENCES ipat_ops.device_candidates(tenant_id,id)
);
ALTER TABLE ipat_ops.tenant_connection_drafts OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.tenant_connection_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.tenant_connection_drafts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.tenant_connection_drafts FROM PUBLIC;
CREATE TABLE ipat_ops.tenant_connection_draft_audit (
 tenant_id uuid NOT NULL, draft_id uuid NOT NULL,
 event text NOT NULL DEFAULT 'nonexecutable_draft_recorded'
  CHECK(event='nonexecutable_draft_recorded'),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY(tenant_id,draft_id), FOREIGN KEY(tenant_id,draft_id)
  REFERENCES ipat_ops.tenant_connection_drafts(tenant_id,draft_id)
);
ALTER TABLE ipat_ops.tenant_connection_draft_audit OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.tenant_connection_draft_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.tenant_connection_draft_audit FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.tenant_connection_draft_audit FROM PUBLIC;
CREATE ROLE ipat_connection_draft_owner NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_connection_draft_execute NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA ipat_platform TO ipat_connection_draft_owner,ipat_connection_draft_execute;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_connection_draft_owner;
GRANT SELECT ON ipat_platform.tenants,ipat_platform.identity_memberships,
 ipat_ops.device_candidates TO ipat_connection_draft_owner;
GRANT SELECT,INSERT ON ipat_ops.tenant_connection_drafts,
 ipat_ops.tenant_connection_draft_audit TO ipat_connection_draft_owner;
CREATE POLICY connection_member_select ON ipat_platform.identity_memberships
 FOR SELECT TO ipat_connection_draft_owner USING (true);
CREATE POLICY connection_candidate_select ON ipat_ops.device_candidates
 FOR SELECT TO ipat_connection_draft_owner USING (true);
CREATE POLICY connection_draft_select ON ipat_ops.tenant_connection_drafts
 FOR SELECT TO ipat_connection_draft_owner USING (true);
CREATE POLICY connection_draft_insert ON ipat_ops.tenant_connection_drafts
 FOR INSERT TO ipat_connection_draft_owner WITH CHECK (true);
CREATE POLICY connection_audit_select ON ipat_ops.tenant_connection_draft_audit
 FOR SELECT TO ipat_connection_draft_owner USING (true);
CREATE POLICY connection_audit_insert ON ipat_ops.tenant_connection_draft_audit
 FOR INSERT TO ipat_connection_draft_owner WITH CHECK (true);

-- Separate EXECUTE-only caller MUST prove genuine BFF identity, MFA and CSRF;
-- SQL independently repeats active tenant admin and exact candidate POP.
CREATE FUNCTION ipat_platform.propose_lab_connection_draft(
 p_issuer text,p_subject text,p_tenant uuid,p_candidate uuid,
 p_request uuid,p_pop text,p_method text,p_gateway text
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
DECLARE created uuid; prior ipat_ops.tenant_connection_drafts%ROWTYPE;
BEGIN
 IF p_issuer IS NULL OR length(p_issuer)=0 OR p_subject IS NULL
    OR length(p_subject)=0 OR p_tenant IS NULL OR p_candidate IS NULL
    OR p_request IS NULL OR p_pop IS NULL OR
    p_pop !~ '^[A-Za-z0-9_.-]{1,128}$' OR
    p_method IS NULL OR p_method NOT IN ('direct_secure','wireguard','ipsec')
    OR p_gateway IS NULL OR p_gateway NOT IN ('routeros7','routeros6','linux','none')
    OR (p_method='wireguard' AND p_gateway IN ('routeros6','none'))
    OR (p_method='ipsec' AND p_gateway='none')
 THEN RETURN NULL; END IF;
 IF NOT EXISTS(
    SELECT 1 FROM ipat_platform.identity_memberships m
    JOIN ipat_platform.tenants t ON t.id=m.tenant_id AND t.state='active'
    JOIN ipat_ops.device_candidates d ON d.tenant_id=t.id
       AND d.id=p_candidate AND d.pop_id=p_pop
    WHERE m.tenant_id=p_tenant AND m.issuer=p_issuer
      AND m.subject=p_subject AND m.role='tenant_admin'
      AND m.revoked_at IS NULL AND m.created_at<=statement_timestamp()
      AND m.expires_at>statement_timestamp()
      AND length(btrim(m.approved_by))>0
 ) THEN RETURN NULL; END IF;
 -- Candidate-scoped concurrency; draft is immutable and never actionable.
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant::text||p_candidate::text,0));
 SELECT * INTO prior FROM ipat_ops.tenant_connection_drafts
 WHERE tenant_id=p_tenant AND candidate_id=p_candidate;
 IF FOUND THEN
   IF prior.request_id=p_request AND prior.requested_issuer=p_issuer
      AND prior.requested_subject=p_subject AND prior.pop_id=p_pop
      AND prior.method=p_method AND prior.gateway=p_gateway
   THEN RETURN prior.draft_id; END IF;
   RETURN NULL;
 END IF;
 INSERT INTO ipat_ops.tenant_connection_drafts(
  tenant_id,candidate_id,request_id,pop_id,method,gateway,
  requested_issuer,requested_subject
 ) VALUES(p_tenant,p_candidate,p_request,p_pop,p_method,p_gateway,
          p_issuer,p_subject) RETURNING draft_id INTO created;
 INSERT INTO ipat_ops.tenant_connection_draft_audit(tenant_id,draft_id)
 VALUES(p_tenant,created);
 RETURN created;
END $body$;
ALTER FUNCTION ipat_platform.propose_lab_connection_draft(
 text,text,uuid,uuid,uuid,text,text,text)
 OWNER TO ipat_connection_draft_owner;
REVOKE ALL ON FUNCTION ipat_platform.propose_lab_connection_draft(
 text,text,uuid,uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.propose_lab_connection_draft(
 text,text,uuid,uuid,uuid,text,text,text) TO ipat_connection_draft_execute;
-- Separate read role cannot submit, mutate or retrieve credentials (none stored).
CREATE FUNCTION ipat_platform.list_lab_connection_drafts(
 p_issuer text,p_subject text,p_tenant uuid
) RETURNS TABLE(draft_id uuid,candidate_id uuid,pop_id text,
 method text,gateway text,state text,provisioning_enabled boolean)
 LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
 SELECT d.draft_id,d.candidate_id,d.pop_id,d.method,d.gateway,
        d.state,d.provisioning_enabled
 FROM ipat_ops.tenant_connection_drafts d
 JOIN ipat_platform.tenants t ON t.id=d.tenant_id AND t.state='active'
 JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
 WHERE d.tenant_id=p_tenant AND p_issuer IS NOT NULL
   AND length(p_issuer)>0 AND p_subject IS NOT NULL
   AND length(p_subject)>0 AND m.issuer=p_issuer
   AND m.subject=p_subject AND m.role='tenant_admin'
   AND m.revoked_at IS NULL AND m.created_at<=statement_timestamp()
   AND m.expires_at>statement_timestamp()
   AND length(btrim(m.approved_by))>0
 ORDER BY d.pop_id,d.draft_id LIMIT 100
$body$;
ALTER FUNCTION ipat_platform.list_lab_connection_drafts(text,text,uuid)
 OWNER TO ipat_connection_draft_owner;
REVOKE ALL ON FUNCTION ipat_platform.list_lab_connection_drafts(
 text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_connection_drafts(
 text,text,uuid) TO ipat_identity_query;
COMMIT;
