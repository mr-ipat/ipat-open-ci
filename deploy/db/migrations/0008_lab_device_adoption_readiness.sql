-- R9.1 immutable adoption-readiness evidence gates, LAB / disposable DB first.
-- Metadata approval NEVER equals physical permission. This schema cannot probe devices.
BEGIN;

CREATE TABLE ipat_ops.device_adoption_attestations (
  tenant_id uuid NOT NULL,
  candidate_id uuid NOT NULL,
  attestation_id uuid NOT NULL DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL,
  gate text NOT NULL CHECK (gate IN (
    'secure_management_path',
    'device_identity',
    'readonly_account',
    'recovery_plan'
  )),
  verdict text NOT NULL CHECK (verdict IN ('verified','blocked')),
  evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
  note text NOT NULL CHECK (
    length(note) BETWEEN 12 AND 180
    AND note ~ '^[A-Za-z0-9 _.,:/()-]+$'
  ),
  attester_issuer text NOT NULL,
  attester_subject text NOT NULL,
  captured_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id,candidate_id,attestation_id),
  UNIQUE (tenant_id,attester_issuer,attester_subject,request_id),
  FOREIGN KEY (tenant_id,candidate_id)
    REFERENCES ipat_ops.device_candidates(tenant_id,id),
  CHECK (captured_at <= recorded_at + interval '5 minutes'),
  CHECK (valid_until > captured_at),
  CHECK (valid_until <= captured_at + interval '7 days')
);
ALTER TABLE ipat_ops.device_adoption_attestations OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.device_adoption_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.device_adoption_attestations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.device_adoption_attestations
 FROM PUBLIC,ipat_app_runtime,ipat_identity_query,
      ipat_device_registry_execute,ipat_device_review_execute;

CREATE ROLE ipat_device_readiness_owner NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_device_readiness_execute NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;

GRANT USAGE ON SCHEMA ipat_platform
 TO ipat_device_readiness_owner,ipat_device_readiness_execute;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_device_readiness_owner;
GRANT SELECT ON ipat_platform.tenants,ipat_platform.identity_memberships,
 ipat_platform.identity_pop_grants TO ipat_device_readiness_owner;
GRANT SELECT ON ipat_ops.device_candidates,ipat_ops.device_candidate_reviews
 TO ipat_device_readiness_owner;
GRANT SELECT,INSERT ON ipat_ops.device_adoption_attestations
 TO ipat_device_readiness_owner;

CREATE POLICY readiness_membership_select ON ipat_platform.identity_memberships
 FOR SELECT TO ipat_device_readiness_owner USING (true);
CREATE POLICY readiness_pop_select ON ipat_platform.identity_pop_grants
 FOR SELECT TO ipat_device_readiness_owner USING (true);
CREATE POLICY readiness_candidate_select ON ipat_ops.device_candidates
 FOR SELECT TO ipat_device_readiness_owner USING (true);
CREATE POLICY readiness_review_select ON ipat_ops.device_candidate_reviews
 FOR SELECT TO ipat_device_readiness_owner USING (true);
CREATE POLICY readiness_attestation_select ON ipat_ops.device_adoption_attestations
 FOR SELECT TO ipat_device_readiness_owner USING (true);
CREATE POLICY readiness_attestation_insert ON ipat_ops.device_adoption_attestations
 FOR INSERT TO ipat_device_readiness_owner WITH CHECK (true);

-- Records evidence metadata only. The app MUST have verified a pinned signed
-- MFA token; SQL separately rechecks own active security_admin membership.
-- The reviewer must be the same independently approved metadata reviewer,
-- preventing a new unrelated actor from silently promoting a candidate.
CREATE FUNCTION ipat_platform.attest_lab_device_adoption_gate(
 p_issuer text,p_subject text,p_tenant uuid,p_candidate uuid,p_request uuid,
 p_gate text,p_verdict text,p_evidence_sha256 text,p_note text,
 p_captured_at timestamptz,p_valid_until timestamptz
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
DECLARE created uuid;
BEGIN
 IF p_issuer IS NULL OR length(p_issuer)=0
   OR p_subject IS NULL OR length(p_subject)=0
   OR p_tenant IS NULL OR p_candidate IS NULL OR p_request IS NULL
   OR p_gate NOT IN ('secure_management_path','device_identity',
                     'readonly_account','recovery_plan')
   OR p_verdict NOT IN ('verified','blocked')
   OR p_evidence_sha256 !~ '^[0-9a-f]{64}$'
   OR p_note IS NULL OR length(p_note) NOT BETWEEN 12 AND 180
   OR p_note !~ '^[A-Za-z0-9 _.,:/()-]+$'
   OR p_captured_at IS NULL OR p_valid_until IS NULL
   OR p_captured_at > statement_timestamp() + interval '5 minutes'
   OR p_valid_until <= p_captured_at
   OR p_valid_until > p_captured_at + interval '7 days'
 THEN RETURN NULL; END IF;

 IF NOT EXISTS (
   SELECT 1
   FROM ipat_platform.tenants t
   JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
   JOIN ipat_ops.device_candidates d ON d.tenant_id=t.id AND d.id=p_candidate
   JOIN ipat_ops.device_candidate_reviews r
     ON r.tenant_id=d.tenant_id AND r.candidate_id=d.id
   WHERE t.id=p_tenant AND t.state='active'
     AND d.adoption_state='approved'
     AND d.connectivity='unknown' AND d.health='not_measured'
     AND d.last_verified_at IS NULL
     AND r.decision='approved'
     AND r.reviewer_issuer=p_issuer AND r.reviewer_subject=p_subject
     AND m.issuer=p_issuer AND m.subject=p_subject
     AND m.role='security_admin' AND m.revoked_at IS NULL
     AND m.created_at<=statement_timestamp()
     AND m.expires_at>statement_timestamp()
     AND length(btrim(m.approved_by))>0
 ) THEN RETURN NULL; END IF;

 INSERT INTO ipat_ops.device_adoption_attestations(
   tenant_id,candidate_id,request_id,gate,verdict,evidence_sha256,note,
   attester_issuer,attester_subject,captured_at,valid_until
 ) VALUES(
   p_tenant,p_candidate,p_request,p_gate,p_verdict,p_evidence_sha256,p_note,
   p_issuer,p_subject,p_captured_at,p_valid_until
 ) ON CONFLICT(tenant_id,attester_issuer,attester_subject,request_id) DO NOTHING
 RETURNING attestation_id INTO created;

 IF created IS NOT NULL THEN RETURN created; END IF;
 SELECT a.attestation_id INTO created
 FROM ipat_ops.device_adoption_attestations a
 WHERE a.tenant_id=p_tenant
   AND a.attester_issuer=p_issuer AND a.attester_subject=p_subject
   AND a.request_id=p_request AND a.candidate_id=p_candidate
   AND a.gate=p_gate AND a.verdict=p_verdict
   AND a.evidence_sha256=p_evidence_sha256 AND a.note=p_note
   AND a.captured_at=p_captured_at AND a.valid_until=p_valid_until;
 RETURN created;
END $body$;
ALTER FUNCTION ipat_platform.attest_lab_device_adoption_gate(
 text,text,uuid,uuid,uuid,text,text,text,text,timestamptz,timestamptz)
 OWNER TO ipat_device_readiness_owner;
REVOKE ALL ON FUNCTION ipat_platform.attest_lab_device_adoption_gate(
 text,text,uuid,uuid,uuid,text,text,text,text,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.attest_lab_device_adoption_gate(
 text,text,uuid,uuid,uuid,text,text,text,text,timestamptz,timestamptz)
 TO ipat_device_readiness_execute;

-- Safe readiness projection. A stale/blocked latest gate makes the candidate
-- ineligible. Management IP, evidence hash/note and reviewer identity are omitted.
CREATE FUNCTION ipat_platform.list_lab_device_adoption_readiness(
 p_issuer text,p_subject text,p_tenant uuid,p_role text,p_pop text
) RETURNS TABLE(
 id uuid,pop_id text,display_name text,device_kind text,vendor text,
 exact_model text,adoption_state text,
 metadata_approved boolean,secure_management_path boolean,
 device_identity boolean,readonly_account boolean,recovery_plan boolean,
 read_probe_eligible boolean
) LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
 WITH permitted AS (
   SELECT m.tenant_id,m.issuer,m.subject,m.role
   FROM ipat_platform.identity_memberships m
   JOIN ipat_platform.tenants t ON t.id=m.tenant_id AND t.state='active'
   WHERE m.tenant_id=p_tenant AND m.issuer=p_issuer AND m.subject=p_subject
     AND m.role=p_role AND m.revoked_at IS NULL
     AND m.created_at<=statement_timestamp()
     AND m.expires_at>statement_timestamp()
     AND length(btrim(m.approved_by))>0
     AND (
       (p_role='tenant_admin' AND p_pop IS NULL)
       OR (p_role='noc_engineer' AND p_pop IS NOT NULL AND EXISTS(
         SELECT 1 FROM ipat_platform.identity_pop_grants g
         WHERE g.tenant_id=m.tenant_id AND g.issuer=m.issuer
           AND g.subject=m.subject AND g.role=m.role AND g.pop_id=p_pop
       ))
       OR (p_role='security_admin' AND p_pop IS NULL)
     )
 ), candidates AS (
   SELECT d.*
   FROM ipat_ops.device_candidates d,permitted p
   WHERE d.tenant_id=p.tenant_id
     AND (p_role<>'noc_engineer' OR d.pop_id=p_pop)
 ), latest AS (
   SELECT DISTINCT ON(a.tenant_id,a.candidate_id,a.gate)
     a.tenant_id,a.candidate_id,a.gate,a.verdict,a.valid_until,a.recorded_at
   FROM ipat_ops.device_adoption_attestations a
   JOIN candidates d ON d.tenant_id=a.tenant_id AND d.id=a.candidate_id
   ORDER BY a.tenant_id,a.candidate_id,a.gate,a.recorded_at DESC,a.attestation_id DESC
 ), flags AS (
   SELECT d.tenant_id,d.id,
     (d.adoption_state='approved' AND EXISTS(
       SELECT 1 FROM ipat_ops.device_candidate_reviews r
       WHERE r.tenant_id=d.tenant_id AND r.candidate_id=d.id
         AND r.decision='approved')) AS metadata_ok,
     COALESCE(bool_or(l.gate='secure_management_path' AND l.verdict='verified'
                      AND l.valid_until>statement_timestamp()),false) AS path_ok,
     COALESCE(bool_or(l.gate='device_identity' AND l.verdict='verified'
                      AND l.valid_until>statement_timestamp()),false) AS identity_ok,
     COALESCE(bool_or(l.gate='readonly_account' AND l.verdict='verified'
                      AND l.valid_until>statement_timestamp()),false) AS account_ok,
     COALESCE(bool_or(l.gate='recovery_plan' AND l.verdict='verified'
                      AND l.valid_until>statement_timestamp()),false) AS recovery_ok
   FROM candidates d LEFT JOIN latest l
    ON l.tenant_id=d.tenant_id AND l.candidate_id=d.id
   GROUP BY d.tenant_id,d.id,d.adoption_state
 )
 SELECT d.id,d.pop_id,d.display_name,d.device_kind,d.vendor,d.exact_model,
        d.adoption_state,f.metadata_ok,f.path_ok,f.identity_ok,f.account_ok,
        f.recovery_ok,
        (f.metadata_ok AND f.path_ok AND f.identity_ok AND f.account_ok
         AND f.recovery_ok
         AND d.connectivity='unknown' AND d.health='not_measured'
         AND d.last_verified_at IS NULL) AS read_probe_eligible
 FROM candidates d JOIN flags f ON f.tenant_id=d.tenant_id AND f.id=d.id
 ORDER BY d.requested_at DESC,d.id
 LIMIT 100
$body$;
ALTER FUNCTION ipat_platform.list_lab_device_adoption_readiness(
 text,text,uuid,text,text) OWNER TO ipat_device_readiness_owner;
REVOKE ALL ON FUNCTION ipat_platform.list_lab_device_adoption_readiness(
 text,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_device_adoption_readiness(
 text,text,uuid,text,text) TO ipat_identity_query;

COMMIT;
