-- R8.3 disposable-review schema: future immutable device adoption REQUESTS only.
-- DO NOT run against customer data until MFA/approver provenance and DR verified.
-- No raw credentials, unauthorized hardware reads, auto-approval or connectivity claims.
BEGIN;
CREATE TABLE ipat_ops.device_candidates (
  tenant_id uuid NOT NULL REFERENCES ipat_platform.tenants(id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL,
  pop_id text NOT NULL CHECK (length(pop_id) BETWEEN 1 AND 128
       AND pop_id ~ '^[A-Za-z0-9_.-]+$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80
       AND display_name ~ '^[A-Za-z0-9][A-Za-z0-9 _.-]*$'),
  device_kind text NOT NULL CHECK (device_kind IN ('olt','ont','router')),
  vendor text NOT NULL CHECK (vendor IN ('ZTE','C-DATA','VSOL','MikroTik','Other')),
  exact_model text CHECK (exact_model IS NULL OR length(exact_model) BETWEEN 1 AND 100),
  management_ipv4 inet CHECK (
     management_ipv4 IS NULL OR
     (family(management_ipv4)=4 AND masklen(management_ipv4)=32 AND
       (management_ipv4 <<= '10.0.0.0/8'::cidr OR
        management_ipv4 <<= '172.16.0.0/12'::cidr OR
        management_ipv4 <<= '192.168.0.0/16'::cidr))),
  adoption_state text NOT NULL DEFAULT 'pending_review'
       CHECK (adoption_state IN ('pending_review','approved','rejected','quarantined')),
  connectivity text NOT NULL DEFAULT 'unknown'
       CHECK (connectivity IN ('unknown','reachable','unreachable')),
  health text NOT NULL DEFAULT 'not_measured'
       CHECK (health IN ('not_measured','normal','degraded','critical')),
  last_verified_at timestamptz,
  requested_issuer text NOT NULL,
  requested_subject text NOT NULL,
  requested_at timestamptz NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,requested_issuer,requested_subject,request_id),
  CONSTRAINT health_never_forged_at_registration CHECK (
    (connectivity='unknown' AND health='not_measured' AND last_verified_at IS NULL)
    OR (last_verified_at IS NOT NULL AND adoption_state IN ('approved','quarantined')))
);
ALTER TABLE ipat_ops.device_candidates OWNER TO ipat_schema_owner;
CREATE INDEX candidates_tenant_pop ON ipat_ops.device_candidates(tenant_id,pop_id,requested_at DESC);
ALTER TABLE ipat_ops.device_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.device_candidates FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_ops.device_candidates FROM PUBLIC,ipat_app_runtime,ipat_identity_query;
CREATE ROLE ipat_device_registry_owner NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_device_registry_execute NOLOGIN NOSUPERUSER
 NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA ipat_platform TO ipat_device_registry_owner,ipat_device_registry_execute;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_device_registry_owner;
GRANT SELECT ON ipat_platform.tenants,ipat_platform.identity_memberships,
 ipat_platform.identity_pop_grants TO ipat_device_registry_owner;
GRANT SELECT,INSERT ON ipat_ops.device_candidates TO ipat_device_registry_owner;
CREATE POLICY registry_member_select ON ipat_platform.identity_memberships
 FOR SELECT TO ipat_device_registry_owner USING (true);
CREATE POLICY registry_pop_select ON ipat_platform.identity_pop_grants
 FOR SELECT TO ipat_device_registry_owner USING (true);
CREATE POLICY registry_candidate_select ON ipat_ops.device_candidates
 FOR SELECT TO ipat_device_registry_owner USING (true);
CREATE POLICY registry_candidate_insert ON ipat_ops.device_candidates
 FOR INSERT TO ipat_device_registry_owner WITH CHECK (true);

-- Caller MUST be a separately PINNED/SIGNED-JWT checked private service.
-- Identity claims passed as text are NOT authentication by themselves.
CREATE FUNCTION ipat_platform.propose_lab_device_candidate(
 p_issuer text,p_subject text,p_tenant uuid,p_request uuid,
 p_pop text,p_name text,p_kind text,p_vendor text,p_model text,p_ip text
) RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
 SET search_path = pg_catalog,ipat_platform,ipat_ops AS $body$
DECLARE result uuid;
BEGIN
 IF p_issuer IS NULL OR p_subject IS NULL OR
    p_tenant IS NULL OR p_request IS NULL OR
    p_pop IS NULL OR p_name IS NULL OR p_kind IS NULL OR p_vendor IS NULL
    OR length(p_issuer)=0 OR length(p_subject)=0
    OR NOT EXISTS (
       SELECT 1 FROM ipat_platform.identity_memberships m
       JOIN ipat_platform.tenants t ON t.id=m.tenant_id
       WHERE m.tenant_id=p_tenant AND t.state='active'
         AND m.issuer=p_issuer AND m.subject=p_subject
         AND m.role='tenant_admin' AND m.revoked_at IS NULL
         AND m.created_at <= statement_timestamp()
         AND m.expires_at > statement_timestamp()
         AND length(btrim(m.approved_by))>0
    )
 THEN RETURN NULL; END IF;
 -- No DNS/public IP, and absolutely no device connection or secret intake.
 IF p_ip IS NOT NULL AND NOT (
   (p_ip::inet <<= '10.0.0.0/8'::cidr OR
    p_ip::inet <<= '172.16.0.0/12'::cidr OR
    p_ip::inet <<= '192.168.0.0/16'::cidr)
   AND family(p_ip::inet)=4 AND masklen(p_ip::inet)=32)
 THEN RETURN NULL; END IF;
 INSERT INTO ipat_ops.device_candidates(
   tenant_id,request_id,pop_id,display_name,device_kind,vendor,
   exact_model,management_ipv4,requested_issuer,requested_subject
 ) VALUES(
   p_tenant,p_request,p_pop,p_name,p_kind,p_vendor,
   p_model,p_ip::inet,p_issuer,p_subject
 ) ON CONFLICT(tenant_id,requested_issuer,requested_subject,request_id) DO NOTHING
 RETURNING id INTO result;
 IF result IS NOT NULL THEN RETURN result; END IF;
 -- Idempotent retry returns the same ID ONLY if complete input matches.
 SELECT d.id INTO result FROM ipat_ops.device_candidates d
 WHERE d.tenant_id=p_tenant AND d.requested_issuer=p_issuer
   AND d.requested_subject=p_subject AND d.request_id=p_request
   AND d.pop_id=p_pop AND d.display_name=p_name AND d.device_kind=p_kind
   AND d.vendor=p_vendor AND d.exact_model IS NOT DISTINCT FROM p_model
   AND d.management_ipv4 IS NOT DISTINCT FROM p_ip::inet;
 RETURN result;
END $body$;
ALTER FUNCTION ipat_platform.propose_lab_device_candidate(
 text,text,uuid,uuid,text,text,text,text,text,text)
 OWNER TO ipat_device_registry_owner;
REVOKE ALL ON FUNCTION ipat_platform.propose_lab_device_candidate(
 text,text,uuid,uuid,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.propose_lab_device_candidate(
 text,text,uuid,uuid,text,text,text,text,text,text) TO ipat_device_registry_execute;

-- Safe scoped candidates list: tenant_admin (all own POPs) or NOC exact POP.
-- Separate reader EXECUTE never inherits registrar's INSERT privileges.
CREATE FUNCTION ipat_platform.list_lab_device_candidates(
 p_issuer text,p_subject text,p_tenant uuid,p_role text,p_pop text
) RETURNS TABLE(
 id uuid,pop_id text,display_name text,device_kind text,
 vendor text,exact_model text,management_ipv4 text,
 adoption_state text,connectivity text,health text,
 last_verified_at timestamptz,requested_at timestamptz
) LANGUAGE sql STABLE SECURITY DEFINER
 SET search_path = pg_catalog,ipat_platform,ipat_ops AS $body$
 SELECT d.id,d.pop_id,d.display_name,d.device_kind,d.vendor,
 d.exact_model,d.management_ipv4::text,d.adoption_state,
 d.connectivity,d.health,d.last_verified_at,d.requested_at
 FROM ipat_ops.device_candidates d
 JOIN ipat_platform.tenants t ON t.id=d.tenant_id AND t.state='active'
 JOIN ipat_platform.identity_memberships m ON m.tenant_id=t.id
  AND m.issuer=p_issuer AND m.subject=p_subject AND m.role=p_role
 WHERE d.tenant_id=p_tenant
  AND p_issuer IS NOT NULL AND length(p_issuer)>0
  AND p_subject IS NOT NULL AND length(p_subject)>0
  AND p_tenant IS NOT NULL
  AND m.revoked_at IS NULL AND m.created_at<=statement_timestamp()
  AND m.expires_at>statement_timestamp()
  AND length(btrim(m.approved_by))>0
  AND (
   (p_role='tenant_admin' AND p_pop IS NULL)
   OR (p_role='noc_engineer' AND p_pop IS NOT NULL
      AND d.pop_id=p_pop AND EXISTS (
        SELECT 1 FROM ipat_platform.identity_pop_grants g
        WHERE g.tenant_id=m.tenant_id AND g.issuer=m.issuer
          AND g.subject=m.subject AND g.role=m.role AND g.pop_id=p_pop
      ))
  )
 ORDER BY d.requested_at DESC,d.id
 LIMIT 100
$body$;
ALTER FUNCTION ipat_platform.list_lab_device_candidates(text,text,uuid,text,text)
 OWNER TO ipat_device_registry_owner;
REVOKE ALL ON FUNCTION ipat_platform.list_lab_device_candidates(
 text,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ipat_platform.list_lab_device_candidates(
 text,text,uuid,text,text) TO ipat_identity_query;
COMMIT;
