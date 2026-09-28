-- IPAT S1 isolated synthetic PostgreSQL LAB ONLY, trusted migration owner.
-- Backend OIDC->trusted SET LOCAL binding NOT IMPLEMENTED, no real tenant data.
BEGIN;
CREATE ROLE ipat_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE ipat_app_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
CREATE SCHEMA ipat_platform AUTHORIZATION ipat_schema_owner;
CREATE SCHEMA ipat_ops AUTHORIZATION ipat_schema_owner;
REVOKE ALL ON SCHEMA ipat_platform FROM PUBLIC;
REVOKE ALL ON SCHEMA ipat_ops FROM PUBLIC;
GRANT USAGE ON SCHEMA ipat_ops TO ipat_app_runtime;
CREATE TABLE ipat_platform.tenants (
 id uuid PRIMARY KEY,
 tenant_slug text NOT NULL UNIQUE CHECK
  (length(tenant_slug) BETWEEN 1 AND 63 AND
   tenant_slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
 state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended')),
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE ipat_platform.tenants OWNER TO ipat_schema_owner;
CREATE TABLE ipat_ops.devices (
 tenant_id uuid NOT NULL REFERENCES ipat_platform.tenants(id),
 id uuid NOT NULL,
 pop_id text NOT NULL CHECK (length(pop_id) BETWEEN 1 AND 128),
 device_kind text NOT NULL CHECK (device_kind IN ('ont','olt','router')),
 vendor text NOT NULL CHECK (length(vendor) BETWEEN 1 AND 100),
 exact_model text, firmware text,
 PRIMARY KEY (tenant_id,id)
);
ALTER TABLE ipat_ops.devices OWNER TO ipat_schema_owner;
CREATE TABLE ipat_ops.subscribers (
 tenant_id uuid NOT NULL REFERENCES ipat_platform.tenants(id),
 id uuid NOT NULL,
 pop_id text NOT NULL CHECK (length(pop_id) BETWEEN 1 AND 128),
 customer_ref text NOT NULL CHECK (length(customer_ref) BETWEEN 1 AND 128),
 device_id uuid,
 PRIMARY KEY (tenant_id,id),
 UNIQUE (tenant_id,customer_ref),
 CONSTRAINT same_tenant_device_fk FOREIGN KEY (tenant_id,device_id)
 REFERENCES ipat_ops.devices(tenant_id,id)
);
ALTER TABLE ipat_ops.subscribers OWNER TO ipat_schema_owner;
GRANT SELECT,INSERT,UPDATE,DELETE ON ipat_ops.devices,ipat_ops.subscribers TO ipat_app_runtime;
ALTER TABLE ipat_ops.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.devices FORCE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.subscribers ENABLE ROW LEVEL SECURITY;
ALTER TABLE ipat_ops.subscribers FORCE ROW LEVEL SECURITY;
-- Missing/blank scope => NULL / deny, malformed scope => error/deny.
-- Only trusted backend transaction (not Host/header) may SET LOCAL ipat.tenant_id.
CREATE POLICY device_tenant_scope ON ipat_ops.devices FOR ALL TO ipat_app_runtime
 USING (tenant_id = NULLIF(current_setting('ipat.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('ipat.tenant_id',true),'')::uuid);
CREATE POLICY subscriber_tenant_scope ON ipat_ops.subscribers FOR ALL TO ipat_app_runtime
 USING (tenant_id = NULLIF(current_setting('ipat.tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id = NULLIF(current_setting('ipat.tenant_id',true),'')::uuid);
CREATE INDEX devices_tenant_pop ON ipat_ops.devices(tenant_id,pop_id);
CREATE INDEX subscribers_tenant_pop ON ipat_ops.subscribers(tenant_id,pop_id);
COMMIT;
