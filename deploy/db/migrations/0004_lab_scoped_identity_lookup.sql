-- R7.7 DISPOSABLE PostgreSQL 16 LAB ONLY after 0001, 0002 and 0003.
-- No production login role, live VPS migration, IdP or actual customer records.
-- NO privilege is granted to ipat_app_runtime. Never call based on HTTP/JWT claims.
BEGIN;
CREATE ROLE ipat_identity_lookup_owner NOLOGIN NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE ROLE ipat_identity_query NOLOGIN NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
GRANT USAGE ON SCHEMA ipat_platform TO ipat_identity_lookup_owner, ipat_identity_query;
GRANT SELECT ON ipat_platform.tenants,
    ipat_platform.identity_memberships,
    ipat_platform.identity_pop_grants TO ipat_identity_lookup_owner;
-- Only the sealed function owner can read these RLS tables under a named,
-- narrow SELECT policy. ipat_app_runtime still has no schema/table access.
CREATE POLICY identity_lookup_membership_select ON
    ipat_platform.identity_memberships FOR SELECT
    TO ipat_identity_lookup_owner USING (true);
CREATE POLICY identity_lookup_pop_select ON
    ipat_platform.identity_pop_grants FOR SELECT
    TO ipat_identity_lookup_owner USING (true);
-- The future trusted adapter MUST supply issuer+subject from verified token
-- and choose a fixed reviewed role, exact tenant UUID and optional exact POP.
-- A SQL function cannot itself prove IdP MFA/approved reviewer identity.
CREATE FUNCTION ipat_platform.lookup_active_membership(
    p_issuer text, p_subject text, p_tenant uuid, p_role text, p_pop text
) RETURNS TABLE (approved_by text, expires_at timestamptz, tenant_slug text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, ipat_platform
AS $ipat_sql$
    SELECT m.approved_by, m.expires_at, t.tenant_slug
    FROM ipat_platform.identity_memberships AS m
    JOIN ipat_platform.tenants AS t
      ON t.id = m.tenant_id AND t.state = 'active'
    WHERE m.issuer = p_issuer AND m.subject = p_subject
      AND m.tenant_id = p_tenant AND m.role = p_role
      AND m.revoked_at IS NULL
      AND m.created_at <= statement_timestamp()
      AND m.expires_at > statement_timestamp()
      AND length(m.approved_by) > 0
      AND p_issuer IS NOT NULL AND p_subject IS NOT NULL
      AND p_tenant IS NOT NULL AND p_role IS NOT NULL
      AND p_role IN ('tenant_admin','noc_engineer','helpdesk','auditor')
      AND (
        (p_role = 'tenant_admin' AND p_pop IS NULL)
        OR
        (p_role <> 'tenant_admin' AND p_pop IS NOT NULL
          AND EXISTS (
            SELECT 1 FROM ipat_platform.identity_pop_grants AS g
            WHERE g.tenant_id = m.tenant_id AND g.issuer = m.issuer
              AND g.subject = m.subject AND g.role = m.role
              AND g.pop_id = p_pop
          ))
      )
$ipat_sql$;
ALTER FUNCTION ipat_platform.lookup_active_membership(text,text,uuid,text,text)
    OWNER TO ipat_identity_lookup_owner;
REVOKE ALL ON FUNCTION ipat_platform.lookup_active_membership(text,text,uuid,text,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    ipat_platform.lookup_active_membership(text,text,uuid,text,text)
    TO ipat_identity_query;
-- NO LOGIN identity role is created in this milestone.
-- Provisioning an isolated service account and actual MFA is separately gated.
COMMIT;
