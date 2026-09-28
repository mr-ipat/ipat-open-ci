-- R8.4 REVIEW-ONLY in independent disposable PG. Never touch actual ISP DB
-- without real OIDC MFA provenance, enrollment and independent DR signoff.
-- Approved below means ONLY verified metadata review; not physical adoption.
BEGIN;
ALTER TABLE ipat_platform.identity_memberships
  DROP CONSTRAINT identity_memberships_role_check;
ALTER TABLE ipat_platform.identity_memberships
  ADD CONSTRAINT identity_memberships_role_check CHECK
  (role IN ('tenant_admin','noc_engineer','helpdesk','auditor','security_admin'));
CREATE ROLE ipat_device_review_owner NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_device_review_execute NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA ipat_platform TO ipat_device_review_owner,ipat_device_review_execute;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_device_review_owner;
GRANT SELECT ON ipat_platform.tenants,ipat_platform.identity_memberships
 TO ipat_device_review_owner;
GRANT SELECT,UPDATE(adoption_state) ON ipat_ops.device_candidates
 TO ipat_device_review_owner;
CREATE POLICY review_own_membership_read ON ipat_platform.identity_memberships
 FOR SELECT TO ipat_device_review_owner USING (true);
CREATE POLICY review_candidates_select ON ipat_ops.device_candidates
 FOR SELECT TO ipat_device_review_owner USING (true);
CREATE POLICY review_candidates_update ON ipat_ops.device_candidates
 FOR UPDATE TO ipat_device_review_owner USING (true)
 WITH CHECK (adoption_state IN ('approved','rejected')
   AND connectivity='unknown' AND health='not_measured'
   AND last_verified_at IS NULL);
CREATE TABLE ipat_ops.device_candidate_reviews(
 tenant_id uuid NOT NULL,
 candidate_id uuid NOT NULL,
 review_id uuid NOT NULL DEFAULT gen_random_uuid(),
 request_id uuid NOT NULL,
 decision text NOT NULL CHECK(decision IN('approved','rejected')),
 reason text NOT NULL CHECK(length(reason) BETWEEN 12 AND 180
    AND reason ~ '^[A-Za-z0-9 _.,:/()-]+$'),
 reviewer_issuer text NOT NULL,
 reviewer_subject text NOT NULL,
 reviewed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY(tenant_id,candidate_id),
 UNIQUE(tenant_id,reviewer_issuer,reviewer_subject,request_id),
 UNIQUE(review_id),
 FOREIGN KEY(tenant_id,candidate_id)
   REFERENCES ipat_ops.device_candidates(tenant_id,id)
);
ALTER TABLE ipat_ops.device_candidate_reviews OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.device_candidate_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.device_candidate_reviews FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.device_candidate_reviews FROM PUBLIC,ipat_app_runtime,
 ipat_identity_query,ipat_device_registry_execute;
GRANT SELECT,INSERT ON ipat_ops.device_candidate_reviews
 TO ipat_device_review_owner;
CREATE POLICY review_audit_read ON ipat_ops.device_candidate_reviews
 FOR SELECT TO ipat_device_review_owner USING(true);
CREATE POLICY review_audit_insert ON ipat_ops.device_candidate_reviews
 FOR INSERT TO ipat_device_review_owner WITH CHECK(true);
-- There is deliberately NO UPDATE, DELETE, TRUNCATE on audit events.
-- Sealed authorization emits ONE row only for currently eligible reviewers;
-- the API MUST NOT treat an empty queue as proof of reviewer membership.
CREATE FUNCTION ipat_platform.lookup_lab_device_reviewer(
 p_issuer text,p_subject text,p_tenant uuid
) RETURNS TABLE (permitted boolean)
 LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform AS $body$
 SELECT true
 FROM ipat_platform.identity_memberships m
 JOIN ipat_platform.tenants t ON t.id=m.tenant_id AND t.state='active'
 WHERE m.issuer=p_issuer AND m.subject=p_subject AND m.tenant_id=p_tenant
   AND m.role='security_admin' AND m.revoked_at IS NULL
   AND m.created_at<=statement_timestamp()
   AND m.expires_at>statement_timestamp()
   AND length(btrim(m.approved_by))>0
$body$;
ALTER FUNCTION ipat_platform.lookup_lab_device_reviewer(text,text,uuid)
 OWNER TO ipat_device_review_owner;
REVOKE ALL ON FUNCTION ipat_platform.lookup_lab_device_reviewer(text,text,uuid)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.lookup_lab_device_reviewer(text,text,uuid)
 TO ipat_device_review_execute;

-- A reviewer sees ONLY OTHER people's pending drafts in OWN active tenant.
-- Management IP and any CPE secret deliberately omitted from this queue.
CREATE FUNCTION ipat_platform.list_lab_device_review_queue(
 p_issuer text,p_subject text,p_tenant uuid
) RETURNS TABLE(
 id uuid,pop_id text,display_name text,device_kind text,
 vendor text,exact_model text,requested_at timestamptz
) LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
 SELECT d.id,d.pop_id,d.display_name,d.device_kind,d.vendor,
        d.exact_model,d.requested_at
 FROM ipat_ops.device_candidates d
 JOIN ipat_platform.tenants t ON t.id=d.tenant_id AND t.state='active'
 JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
 WHERE d.tenant_id=p_tenant AND d.adoption_state='pending_review'
   AND m.issuer=p_issuer AND m.subject=p_subject AND m.role='security_admin'
   AND m.revoked_at IS NULL AND m.created_at<=statement_timestamp()
   AND m.expires_at>statement_timestamp() AND length(btrim(m.approved_by))>0
   AND NOT(d.requested_issuer=p_issuer AND d.requested_subject=p_subject)
 ORDER BY d.requested_at,d.id LIMIT 100
$body$;
ALTER FUNCTION ipat_platform.list_lab_device_review_queue(text,text,uuid)
 OWNER TO ipat_device_review_owner;
REVOKE ALL ON FUNCTION ipat_platform.list_lab_device_review_queue(text,text,uuid)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_device_review_queue(text,text,uuid)
 TO ipat_device_review_execute;

-- Atomic row lock + one immutable review record + metadata-only transition.
-- Untrusted SQL claims are NOT auth; signed JWT+MFA are app preconditions.
CREATE FUNCTION ipat_platform.review_lab_device_candidate(
 p_issuer text,p_subject text,p_tenant uuid,p_candidate uuid,
 p_request uuid,p_decision text,p_reason text
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
DECLARE
 maker_issuer text; maker_subject text; current_state text;
 existing ipat_ops.device_candidate_reviews%ROWTYPE;
 created uuid;
BEGIN
 IF p_issuer IS NULL OR length(p_issuer)=0 OR p_subject IS NULL
   OR length(p_subject)=0 OR p_tenant IS NULL OR p_candidate IS NULL
   OR p_request IS NULL OR p_decision NOT IN('approved','rejected')
   OR p_decision IS NULL OR p_reason IS NULL
   OR length(p_reason) NOT BETWEEN 12 AND 180
   OR p_reason !~ '^[A-Za-z0-9 _.,:/()-]+$'
   OR NOT EXISTS(
     SELECT 1 FROM ipat_platform.tenants t
     JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
     WHERE t.id=p_tenant AND t.state='active'
       AND m.issuer=p_issuer AND m.subject=p_subject
       AND m.role='security_admin' AND m.revoked_at IS NULL
       AND m.created_at<=statement_timestamp()
       AND m.expires_at>statement_timestamp()
       AND length(btrim(m.approved_by))>0
   )
 THEN RETURN NULL; END IF;
 SELECT d.requested_issuer,d.requested_subject,d.adoption_state
   INTO maker_issuer,maker_subject,current_state
 FROM ipat_ops.device_candidates d
 WHERE d.tenant_id=p_tenant AND d.id=p_candidate FOR UPDATE;
 IF NOT FOUND OR (maker_issuer=p_issuer AND maker_subject=p_subject)
 THEN RETURN NULL; END IF;
 -- A single caller idempotency request may not approve two different drafts.
 IF EXISTS (SELECT 1 FROM ipat_ops.device_candidate_reviews r
   WHERE r.tenant_id=p_tenant AND r.reviewer_issuer=p_issuer
     AND r.reviewer_subject=p_subject AND r.request_id=p_request
     AND r.candidate_id<>p_candidate)
 THEN RETURN NULL; END IF;
 IF current_state<>'pending_review' THEN
   SELECT r.* INTO existing FROM ipat_ops.device_candidate_reviews r
   WHERE r.tenant_id=p_tenant AND r.candidate_id=p_candidate;
   IF FOUND AND existing.reviewer_issuer=p_issuer
     AND existing.reviewer_subject=p_subject AND existing.request_id=p_request
     AND existing.decision=p_decision AND existing.reason=p_reason
   THEN RETURN existing.review_id; END IF;
   RETURN NULL;
 END IF;
 UPDATE ipat_ops.device_candidates
    SET adoption_state=p_decision
  WHERE tenant_id=p_tenant AND id=p_candidate
    AND adoption_state='pending_review' AND connectivity='unknown'
    AND health='not_measured' AND last_verified_at IS NULL;
 IF NOT FOUND THEN RETURN NULL; END IF;
 INSERT INTO ipat_ops.device_candidate_reviews(
  tenant_id,candidate_id,request_id,decision,reason,reviewer_issuer,reviewer_subject
 ) VALUES (
  p_tenant,p_candidate,p_request,p_decision,p_reason,p_issuer,p_subject
 ) RETURNING review_id INTO created;
 RETURN created;
END $body$;
ALTER FUNCTION ipat_platform.review_lab_device_candidate(
 text,text,uuid,uuid,uuid,text,text) OWNER TO ipat_device_review_owner;
REVOKE ALL ON FUNCTION ipat_platform.review_lab_device_candidate(
 text,text,uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.review_lab_device_candidate(
 text,text,uuid,uuid,uuid,text,text) TO ipat_device_review_execute;
COMMIT;
