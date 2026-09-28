-- R7.0 SYNTHETIC PostgreSQL ONLY; candidate schema, not commercial ADR-005 sign-off.
-- Requires 0001 first and a dedicated disposable ephemeral DB.
-- NO runtime database role may query memberships. Application integration is NOT done.
BEGIN;
CREATE TABLE ipat_platform.identity_memberships (
 tenant_id uuid NOT NULL REFERENCES ipat_platform.tenants(id),
 issuer text NOT NULL CHECK (length(issuer) BETWEEN 10 AND 512
    AND issuer LIKE 'https://%' AND issuer !~ '[[:space:]]'),
 subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 128
    AND subject ~ '^[a-zA-Z0-9_:/.-]+$'),
 role text NOT NULL CHECK (role IN
    ('tenant_admin','noc_engineer','helpdesk','auditor')),
 approved_by text NOT NULL CHECK (length(approved_by) BETWEEN 1 AND 128),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 PRIMARY KEY (tenant_id,issuer,subject,role),
 CONSTRAINT membership_future_expiration CHECK (expires_at > created_at),
 CONSTRAINT revoked_after_approval CHECK
    (revoked_at IS NULL OR revoked_at >= created_at)
);
ALTER TABLE ipat_platform.identity_memberships OWNER TO ipat_schema_owner;
CREATE INDEX identity_memberships_exact_subject ON
 ipat_platform.identity_memberships(issuer,subject,tenant_id)
 WHERE revoked_at IS NULL;
-- Explicit POP grant is only valid for that exact same tenant+identity+role.
CREATE TABLE ipat_platform.identity_pop_grants (
 tenant_id uuid NOT NULL,
 issuer text NOT NULL,
 subject text NOT NULL,
 role text NOT NULL,
 pop_id text NOT NULL CHECK
    (length(pop_id) BETWEEN 1 AND 128
     AND pop_id ~ '^[a-zA-Z0-9_.-]+$'),
 PRIMARY KEY(tenant_id,issuer,subject,role,pop_id),
 CONSTRAINT exact_membership_scope FOREIGN KEY
    (tenant_id,issuer,subject,role)
    REFERENCES ipat_platform.identity_memberships(tenant_id,issuer,subject,role)
    ON DELETE CASCADE
);
ALTER TABLE ipat_platform.identity_pop_grants OWNER TO ipat_schema_owner;
-- Platform principals are NOT tenant members and cannot read tenant secrets.
CREATE TABLE ipat_platform.platform_principals (
 issuer text NOT NULL CHECK (length(issuer) BETWEEN 10 AND 512
     AND issuer LIKE 'https://%' AND issuer !~ '[[:space:]]'),
 subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 128
     AND subject ~ '^[a-zA-Z0-9_:/.-]+$'),
 role text NOT NULL CHECK (role = 'platform_owner'),
 approved_by text NOT NULL CHECK (length(approved_by) BETWEEN 1 AND 128),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 PRIMARY KEY (issuer,subject),
 CONSTRAINT platform_expiry CHECK (expires_at > created_at),
 CONSTRAINT platform_revocation_after_approval CHECK
    (revoked_at IS NULL OR revoked_at >= created_at)
);
ALTER TABLE ipat_platform.platform_principals OWNER TO ipat_schema_owner;
-- RLS FORCE is a second boundary. No runtime SELECT/INSERT/UPDATE/DELETE
-- and no arbitrary SECURITY DEFINER function is granted in this milestone.
ALTER TABLE ipat_platform.identity_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_platform.identity_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE ipat_platform.identity_pop_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_platform.identity_pop_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE ipat_platform.platform_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_platform.platform_principals FORCE ROW LEVEL SECURITY;
REVOKE ALL ON ipat_platform.identity_memberships FROM PUBLIC,ipat_app_runtime;
REVOKE ALL ON ipat_platform.identity_pop_grants FROM PUBLIC,ipat_app_runtime;
REVOKE ALL ON ipat_platform.platform_principals FROM PUBLIC,ipat_app_runtime;
-- Only an independently authenticated migration/operator approval actor can
-- add trusted records later; no such provisioning or runtime actor exists yet.
COMMIT;
