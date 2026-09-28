-- R8.0: synthetically proven read-only device inventory for PRIVATE LAB ONLY.
-- Separate sealed function: cannot expose customer devices outside exact active
-- verified-token issuer/subject AND operator-approved tenant/role/POP membership.
-- DBA must verify trusted caller provenance; no production login/migration here.
BEGIN;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_identity_lookup_owner;
GRANT SELECT ON ipat_ops.devices TO ipat_identity_lookup_owner;
-- devices has FORCE RLS: ONLY this dedicated function owner can SELECT after
-- its narrow membership/POP predicate. PUBLIC/app_runtime get no new privileges.
CREATE POLICY identity_lab_device_inventory_select
  ON ipat_ops.devices FOR SELECT TO ipat_identity_lookup_owner USING (true);

CREATE FUNCTION ipat_platform.list_authorized_lab_devices(
    p_issuer text, p_subject text, p_tenant uuid, p_role text, p_pop text
)
RETURNS TABLE (
    id uuid, pop_id text, device_kind text, vendor text,
    exact_model text, firmware text
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, ipat_platform, ipat_ops
AS $ipat_sql$
    SELECT d.id, d.pop_id, d.device_kind, d.vendor, d.exact_model, d.firmware
    FROM ipat_ops.devices AS d
    JOIN ipat_platform.tenants AS t
      ON t.id = d.tenant_id AND t.state = 'active'
    JOIN ipat_platform.identity_memberships AS m
      ON m.tenant_id = t.id AND m.issuer = p_issuer
     AND m.subject = p_subject AND m.role = p_role
    WHERE d.tenant_id = p_tenant
      AND p_issuer IS NOT NULL AND length(p_issuer) > 0
      AND p_subject IS NOT NULL AND length(p_subject) > 0
      AND p_tenant IS NOT NULL
      -- This initial private lab inventory accepts NOC only, exact POP.
      -- Tenant-wide admin requires a separate reviewed backend policy.
      AND p_role = 'noc_engineer'
      AND p_pop IS NOT NULL AND length(p_pop) > 0
      AND d.pop_id = p_pop
      AND m.revoked_at IS NULL
      AND m.created_at <= statement_timestamp()
      AND m.expires_at > statement_timestamp()
      AND length(btrim(m.approved_by)) > 0
      AND EXISTS (
          SELECT 1 FROM ipat_platform.identity_pop_grants AS g
          WHERE g.tenant_id = m.tenant_id AND g.issuer = m.issuer
            AND g.subject = m.subject AND g.role = m.role AND g.pop_id = p_pop
      )
    ORDER BY d.id
    LIMIT 100
$ipat_sql$;
ALTER FUNCTION ipat_platform.list_authorized_lab_devices(text,text,uuid,text,text)
  OWNER TO ipat_identity_lookup_owner;
REVOKE ALL ON FUNCTION
  ipat_platform.list_authorized_lab_devices(text,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  ipat_platform.list_authorized_lab_devices(text,text,uuid,text,text)
  TO ipat_identity_query;
COMMIT;
