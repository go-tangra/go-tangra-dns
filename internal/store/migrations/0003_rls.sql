-- +goose Up
-- Per-tenant row-level security on every tenant dns_* table. dns_app is
-- NOBYPASSRLS; every statement runs with app.tenant_id set to the caller's
-- tenant. Trusted system paths (audit writer, challenge sweeper, backup tenant
-- enumeration) set app.system='on' (with app.tenant_id pinned to the nil uuid so
-- the uuid cast stays valid) so the policy admits their cross-tenant access.
--
-- dns_server_config has no tenant column: it is platform scope and reachable
-- only through the configuration service, which requires platform-admin (or
-- the system scope for the start-up re-apply).
--
-- Global zone ownership (research D1): the unique index on dns_zones.name is the
-- final arbiter of equality; dns_zone_conflict() answers the overlap question
-- (another tenant's zone equal to, an ancestor of or a descendant of a name)
-- with a boolean ONLY, so a caller learns "duplicate" and nothing about the
-- owner. dns_zone_names() gives the recursor reconciler the managed names only.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'dns_zones','dns_zone_templates','dns_supermasters','dns_ipam_sync',
    'dns_acme_challenges','dns_audit_events'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting('app.tenant_id', true)::uuid OR current_setting('app.system', true) = 'on') WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid OR current_setting('app.system', true) = 'on')$p$, t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO dns_app', t);
  END LOOP;
END $$;
-- +goose StatementEnd
GRANT SELECT, INSERT, UPDATE, DELETE ON dns_server_config TO dns_app;

-- Overlap check: true when a zone of ANOTHER tenant is equal to, an ancestor
-- of, or a descendant of p_name (canonical, trailing dot). Same-tenant nesting
-- is allowed. Runs as the owner with the system scope set for its own duration
-- only (FORCE ROW LEVEL SECURITY applies to a non-superuser owner too); returns
-- a boolean, never a row.
-- +goose StatementBegin
CREATE FUNCTION dns_zone_conflict(p_name text, p_tenant uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
SET app.system = 'on'
SET app.tenant_id = '00000000-0000-0000-0000-000000000000'
AS $f$
  SELECT EXISTS (
    SELECT 1 FROM dns_zones z
    WHERE z.tenant_id <> p_tenant
      AND (z.name = lower(p_name)
           OR right(lower(p_name), length(z.name) + 1) = '.' || z.name
           OR right(z.name, length(p_name) + 1) = '.' || lower(p_name))
  )
$f$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION dns_zone_conflict(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dns_zone_conflict(text, uuid) TO dns_app;

-- Every managed zone name (recursor reconciler); names only, no tenant data.
-- +goose StatementBegin
CREATE FUNCTION dns_zone_names()
RETURNS SETOF text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
SET app.system = 'on'
SET app.tenant_id = '00000000-0000-0000-0000-000000000000'
AS $f$
  SELECT z.name FROM dns_zones z ORDER BY z.name
$f$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION dns_zone_names() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dns_zone_names() TO dns_app;

-- +goose Down
DROP FUNCTION IF EXISTS dns_zone_names();
DROP FUNCTION IF EXISTS dns_zone_conflict(text, uuid);
REVOKE ALL ON dns_server_config FROM dns_app;
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'dns_zones','dns_zone_templates','dns_supermasters','dns_ipam_sync',
    'dns_acme_challenges','dns_audit_events'
  ]
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;
-- +goose StatementEnd
