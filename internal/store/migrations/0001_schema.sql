-- +goose Up
-- Core DNS tables (data-model.md). Record sets are NOT stored here: PowerDNS is
-- their source of truth. Every tenant table carries tenant_id and is
-- RLS-protected (policies + grants in 0003_rls.sql); the append-only audit
-- hypertable lives in 0002_audit.sql. Every UNIQUE constraint below is a
-- conflict/ownership guard and MUST be preserved:
--   * dns_zones.name is GLOBAL (across tenants): PowerDNS is shared, so one zone
--     name belongs to exactly one tenant. A unique index is enforced regardless
--     of RLS, so a second tenant's insert fails even though it cannot see the
--     first row (research D1). Overlap (ancestor/descendant) is refused through
--     dns_zone_conflict() in 0003_rls.sql.
--   * dns_zones.pdns_id is GLOBAL: the PowerDNS zone id used for every API call.
--   * dns_supermasters (ip, nameserver) is GLOBAL: PowerDNS's own key.
--   * (tenant_id, lower(name)) on templates; (tenant_id, fqdn, value) on
--     challenges (Present twice = one row).
-- Child rows reference parents through (tenant_id, id) composite foreign keys so
-- the database refuses a link across tenants (FK checks bypass RLS).

-- Zones owned by tenants on the shared PowerDNS Authoritative server.
CREATE TABLE dns_zones (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  name        text NOT NULL CHECK (name = lower(name) AND name LIKE '%_.' AND char_length(name) <= 254),
  pdns_id     text NOT NULL CHECK (pdns_id <> '' AND char_length(pdns_id) <= 300),
  kind        text NOT NULL DEFAULT 'native'
              CHECK (kind IN ('native','master','slave','producer','consumer')),
  masters     text[] NOT NULL DEFAULT '{}',
  dnssec      boolean NOT NULL DEFAULT false,
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
  template_id uuid, -- informational: no FK, deleting a template keeps its zones
  origin      text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual','ipam')),
  nameservers text[] NOT NULL DEFAULT '{}',
  created_by  text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (name),
  UNIQUE (pdns_id),
  UNIQUE (tenant_id, id)
);
CREATE INDEX dns_zones_tenant_name ON dns_zones (tenant_id, name);
CREATE INDEX dns_zones_tenant_kind ON dns_zones (tenant_id, kind);
CREATE INDEX dns_zones_tenant_origin ON dns_zones (tenant_id, origin);
-- Suffix search (longest-zone matching, overlap checks) over reversed names.
CREATE INDEX dns_zones_reverse_name ON dns_zones (reverse(name) text_pattern_ops);

-- Zone templates: record rows expanded ([ZONE]) when a zone is created.
CREATE TABLE dns_zone_templates (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  name        text NOT NULL CHECK (btrim(name) <> '' AND char_length(name) <= 100),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
  records     jsonb NOT NULL DEFAULT '[]'::jsonb
              CHECK (jsonb_typeof(records) = 'array' AND jsonb_array_length(records) <= 200),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX dns_zone_templates_name ON dns_zone_templates (tenant_id, lower(name));

-- Supermasters: server-wide trust in the shared PowerDNS (research D15).
-- Reads are tenant-scoped (RLS); writes require platform-admin in the module.
CREATE TABLE dns_supermasters (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  ip          inet NOT NULL,
  nameserver  text NOT NULL CHECK (nameserver = lower(nameserver) AND nameserver LIKE '%_.'),
  created_by  text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (ip, nameserver),
  UNIQUE (tenant_id, id)
);
CREATE INDEX dns_supermasters_tenant ON dns_supermasters (tenant_id);

-- Server configuration: platform scope, a single row (absent = defaults).
-- Reached only through the platform-admin configuration path.
CREATE TABLE dns_server_config (
  id            integer PRIMARY KEY CHECK (id = 1),
  recursor      jsonb NOT NULL DEFAULT '{}'::jsonb,
  authoritative jsonb NOT NULL DEFAULT '{}'::jsonb,
  recursor_hash text NOT NULL DEFAULT '',
  auth_hash     text NOT NULL DEFAULT '',
  updated_by    text NOT NULL DEFAULT '',
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- IPAM sync state: what the sync last wrote for one IPAM address, so renames,
-- cleared host names and deletes are exact and idempotent (research D8).
-- Zone references are not FKs: zone deletion nulls them (zone-delete path) and
-- is never blocked.
CREATE TABLE dns_ipam_sync (
  tenant_id       uuid NOT NULL,
  ip_address_id   text NOT NULL CHECK (ip_address_id <> '' AND char_length(ip_address_id) <= 64),
  address         inet NOT NULL,
  hostname        text NOT NULL DEFAULT '',
  forward_zone_id uuid,
  forward_name    text NOT NULL DEFAULT '',
  forward_type    text NOT NULL DEFAULT '' CHECK (forward_type IN ('','A','AAAA')),
  reverse_zone_id uuid,
  reverse_name    text NOT NULL DEFAULT '',
  last_event      text NOT NULL DEFAULT 'created'
                  CHECK (last_event IN ('created','updated','scanned','deleted','reconciled')),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, ip_address_id)
);
CREATE INDEX dns_ipam_sync_forward_zone ON dns_ipam_sync (tenant_id, forward_zone_id) WHERE forward_zone_id IS NOT NULL;
CREATE INDEX dns_ipam_sync_reverse_zone ON dns_ipam_sync (tenant_id, reverse_zone_id) WHERE reverse_zone_id IS NOT NULL;

-- ACME DNS-01 challenge bookkeeping (the TXT token is public, not secret).
CREATE TABLE dns_acme_challenges (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  zone_id      uuid NOT NULL,
  fqdn         text NOT NULL CHECK (fqdn = lower(fqdn) AND fqdn LIKE '\_acme-challenge.%'),
  value        text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 128),
  requested_by text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, fqdn, value),
  FOREIGN KEY (tenant_id, zone_id) REFERENCES dns_zones (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX dns_acme_challenges_created ON dns_acme_challenges (created_at);
CREATE INDEX dns_acme_challenges_zone ON dns_acme_challenges (tenant_id, zone_id);

-- +goose Down
DROP TABLE IF EXISTS dns_acme_challenges;
DROP TABLE IF EXISTS dns_ipam_sync;
DROP TABLE IF EXISTS dns_server_config;
DROP TABLE IF EXISTS dns_supermasters;
DROP TABLE IF EXISTS dns_zone_templates;
DROP TABLE IF EXISTS dns_zones;
