-- R9.14 independently reviewed, expiry-bounded NONEXECUTABLE physical site evidence.
-- Lab disposable PostgreSQL only. No credentials, topology, keys or worker job.
BEGIN;
CREATE TABLE ipat_ops.physical_site_evidence (
  tenant_id uuid NOT NULL,
  candidate_id uuid NOT NULL,
  evidence_id uuid NOT NULL DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL,
  gate text NOT NULL CHECK (gate IN (
    'trusted_oob_host_key','isolated_management_last_hop',
    'restricted_publickey_account','firmware_readonly_command',
    'live_service_baseline','dedicated_worker_private_route'
  )),
  verdict text NOT NULL CHECK(verdict IN ('verified','blocked')),
  evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),
  captured_at timestamptz NOT NULL,
  valid_until timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  attester_issuer text NOT NULL,
  attester_subject text NOT NULL,
  PRIMARY KEY(tenant_id,candidate_id,evidence_id),
  UNIQUE(tenant_id,attester_issuer,attester_subject,request_id),
  FOREIGN KEY(tenant_id,candidate_id)
    REFERENCES ipat_ops.device_candidates(tenant_id,id),
  CHECK(captured_at <= recorded_at + interval '5 minutes'),
  CHECK(valid_until > captured_at AND valid_until <= captured_at + interval '1 day')
);
ALTER TABLE ipat_ops.physical_site_evidence OWNER TO ipat_schema_owner;
ALTER TABLE ipat_ops.physical_site_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.physical_site_evidence FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.physical_site_evidence FROM PUBLIC;
CREATE ROLE ipat_site_evidence_owner NOLOGIN NOSUPERUSER NOCREATEDB
 NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_site_evidence_execute NOLOGIN NOSUPERUSER NOCREATEDB
 NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA ipat_platform TO ipat_site_evidence_owner,ipat_site_evidence_execute;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_site_evidence_owner;
GRANT SELECT ON ipat_platform.tenants,ipat_platform.identity_memberships,
 ipat_ops.device_candidates,ipat_ops.device_candidate_reviews TO ipat_site_evidence_owner;
GRANT SELECT,INSERT ON ipat_ops.physical_site_evidence TO ipat_site_evidence_owner;
CREATE POLICY site_member_read ON ipat_platform.identity_memberships
 FOR SELECT TO ipat_site_evidence_owner USING (true);
CREATE POLICY site_candidates_read ON ipat_ops.device_candidates
 FOR SELECT TO ipat_site_evidence_owner USING (true);
CREATE POLICY site_review_read ON ipat_ops.device_candidate_reviews
 FOR SELECT TO ipat_site_evidence_owner USING (true);
CREATE POLICY site_evidence_read ON ipat_ops.physical_site_evidence
 FOR SELECT TO ipat_site_evidence_owner USING (true);
CREATE POLICY site_evidence_append ON ipat_ops.physical_site_evidence
 FOR INSERT TO ipat_site_evidence_owner WITH CHECK (true);
-- Caller MUST first prove genuine signed OIDC MFA and exact scoped role.
-- Text issuer/subject arguments are NOT authentication by themselves.
CREATE FUNCTION ipat_platform.attest_lab_physical_site_gate(
 p_issuer text,p_subject text,p_tenant uuid,p_candidate uuid,p_request uuid,
 p_gate text,p_verdict text,p_digest text,p_captured timestamptz,p_valid timestamptz
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
DECLARE created uuid;
BEGIN
 IF p_issuer IS NULL OR length(p_issuer)=0 OR p_subject IS NULL OR length(p_subject)=0
    OR p_tenant IS NULL OR p_candidate IS NULL OR p_request IS NULL
    OR p_gate IS NULL OR p_gate NOT IN (
       'trusted_oob_host_key','isolated_management_last_hop',
       'restricted_publickey_account','firmware_readonly_command',
       'live_service_baseline','dedicated_worker_private_route')
    OR p_verdict IS NULL OR p_verdict NOT IN ('verified','blocked')
    OR p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$'
    OR p_captured IS NULL OR p_valid IS NULL
    OR p_captured > statement_timestamp()+interval '5 minutes'
    OR p_captured < statement_timestamp()-interval '1 day'
    OR p_valid <= statement_timestamp()
    OR p_valid <= p_captured OR p_valid > p_captured+interval '1 day'
 THEN RETURN NULL; END IF;
 IF NOT EXISTS (
  SELECT 1 FROM ipat_platform.tenants t
  JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
  JOIN ipat_ops.device_candidates d ON d.tenant_id=t.id AND d.id=p_candidate
  JOIN ipat_ops.device_candidate_reviews r
       ON r.tenant_id=d.tenant_id AND r.candidate_id=d.id
  WHERE t.id=p_tenant AND t.state='active'
    AND m.issuer=p_issuer AND m.subject=p_subject AND m.role='security_admin'
    AND m.revoked_at IS NULL AND m.created_at<=statement_timestamp()
    AND m.expires_at>statement_timestamp() AND length(btrim(m.approved_by))>0
    AND d.adoption_state='approved' AND d.connectivity='unknown'
    AND d.health='not_measured' AND d.last_verified_at IS NULL
    AND d.requested_subject<>p_subject
    AND r.decision='approved' AND r.reviewer_issuer=p_issuer
    AND r.reviewer_subject=p_subject
 ) THEN RETURN NULL; END IF;
 INSERT INTO ipat_ops.physical_site_evidence(
  tenant_id,candidate_id,request_id,gate,verdict,evidence_sha256,
  captured_at,valid_until,attester_issuer,attester_subject
 ) VALUES(
  p_tenant,p_candidate,p_request,p_gate,p_verdict,p_digest,
  p_captured,p_valid,p_issuer,p_subject
 ) ON CONFLICT(tenant_id,attester_issuer,attester_subject,request_id) DO NOTHING
 RETURNING evidence_id INTO created;
 IF created IS NOT NULL THEN RETURN created; END IF;
 SELECT e.evidence_id INTO created FROM ipat_ops.physical_site_evidence e
 WHERE e.tenant_id=p_tenant AND e.candidate_id=p_candidate
 AND e.attester_issuer=p_issuer AND e.attester_subject=p_subject
 AND e.request_id=p_request AND e.gate=p_gate AND e.verdict=p_verdict
 AND e.evidence_sha256=p_digest AND e.captured_at=p_captured AND e.valid_until=p_valid;
 RETURN created;
END $body$;
ALTER FUNCTION ipat_platform.attest_lab_physical_site_gate(
 text,text,uuid,uuid,uuid,text,text,text,timestamptz,timestamptz)
 OWNER TO ipat_site_evidence_owner;
REVOKE ALL ON FUNCTION ipat_platform.attest_lab_physical_site_gate(
 text,text,uuid,uuid,uuid,text,text,text,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.attest_lab_physical_site_gate(
 text,text,uuid,uuid,uuid,text,text,text,timestamptz,timestamptz)
 TO ipat_site_evidence_execute;
-- Advisory metadata ONLY. Even all-green synthetic rows NEVER enable
-- operational worker because site identity, MFA and safety need real proof.
CREATE FUNCTION ipat_platform.list_lab_physical_site_readiness(
 p_issuer text,p_subject text,p_tenant uuid
) RETURNS TABLE(candidate_id uuid,pop_id text,
  gate text,gate_verified boolean,physical_worker_enabled boolean)
 LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path=pg_catalog,ipat_platform,ipat_ops AS $body$
 SELECT d.id,d.pop_id,g.name,
  COALESCE(latest.verdict='verified'
   AND latest.valid_until>statement_timestamp(),false),false
 FROM ipat_ops.device_candidates d
 JOIN ipat_platform.tenants t ON t.id=d.tenant_id AND t.state='active'
 JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
 CROSS JOIN (VALUES
   ('trusted_oob_host_key'),('isolated_management_last_hop'),
   ('restricted_publickey_account'),('firmware_readonly_command'),
   ('live_service_baseline'),('dedicated_worker_private_route')
 ) AS g(name)
 LEFT JOIN LATERAL (
   SELECT e.verdict,e.valid_until
   FROM ipat_ops.physical_site_evidence e
   WHERE e.tenant_id=d.tenant_id AND e.candidate_id=d.id AND e.gate=g.name
   ORDER BY e.recorded_at DESC,e.evidence_id DESC LIMIT 1
 ) latest ON true
 WHERE d.tenant_id=p_tenant AND p_issuer IS NOT NULL AND length(p_issuer)>0
  AND p_subject IS NOT NULL AND length(p_subject)>0
  AND m.issuer=p_issuer AND m.subject=p_subject AND m.role='tenant_admin'
  AND m.revoked_at IS NULL AND m.created_at<=statement_timestamp()
  AND m.expires_at>statement_timestamp() AND length(btrim(m.approved_by))>0
 ORDER BY d.id,g.name LIMIT 600
$body$;
ALTER FUNCTION ipat_platform.list_lab_physical_site_readiness(text,text,uuid)
 OWNER TO ipat_site_evidence_owner;
REVOKE ALL ON FUNCTION ipat_platform.list_lab_physical_site_readiness(
 text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_physical_site_readiness(
 text,text,uuid) TO ipat_identity_query;
COMMIT;
