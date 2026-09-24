# Phase 1 Data Model: DNS Service

All tenant tables carry `tenant_id uuid NOT NULL` with per-tenant RLS (research
D1). IDs are application-generated strings (UUIDv7). Timestamps `timestamptz`.
Enums are stored as short lower-case text. **Record sets are not stored
locally** — PowerDNS is their source of truth; the module holds zone ownership,
templates, supermasters, configuration, sync state and challenge bookkeeping.
PowerDNS API keys are never stored in the database (secret references live in
config). Every unique constraint below is a conflict/ownership guard and MUST be
preserved.

## Entities

### dns_zones  (RLS; global uniqueness)
- `id` (PK), `tenant_id`, `name` (canonical: lower-case, trailing dot, A-labels),
  `pdns_id` (PowerDNS zone id as returned on create; used for every API call),
  `kind` (native|master|slave|producer|consumer), `masters` (text[]; IP[:port]
  literals, slave/consumer only), `dnssec` (bool), `description`,
  `template_id` (nullable, informational — no FK so deleting a template keeps
  zones), `origin` (manual|ipam), `nameservers` (text[] used at creation;
  informational), `created_by` (user id | "ipam-sync"), `created_at`,
  `updated_at`.
- **Unique**: `name` (**global**, across tenants), `pdns_id` (global).
- Indexes: `(tenant_id, name)`, `(tenant_id, kind)`, `(tenant_id, origin)`,
  `reverse(name)` text_pattern_ops (suffix search for longest-zone matching).
- **Security-definer functions** (return no tenant data):
  - `dns_zone_conflict(p_name text, p_tenant uuid) → boolean`: true if a zone of
    another tenant is equal to, an ancestor of, or a descendant of `p_name`.
  - `dns_zone_names() → setof text`: all managed zone names (recursor
    reconciler, system scope).

### dns_zone_templates  (RLS)
- `id` (PK), `tenant_id`, `name`, `description`, `records` (JSONB array of
  `{name, type, ttl, content, priority}`, ≤ 200 entries), `created_at`,
  `updated_at`.
- **Unique**: `(tenant_id, lower(name))`.

### dns_supermasters  (RLS for reads; writes platform-admin, research D15)
- `id` (PK), `tenant_id` (registering tenant; PowerDNS `account` is set to it),
  `ip` (inet, unicast non-loopback non-link-local), `nameserver` (FQDN,
  canonical), `created_by`, `created_at`.
- **Unique**: `(ip, nameserver)` (**global** — PowerDNS's own key).
- No update (delete and re-create, FR-007).

### dns_server_config  (platform scope, single row)
- `id` (PK, CHECK `id = 1`), `recursor` (JSONB: `{listen_addresses[], port,
  allowed_networks[], upstream_resolvers[], dnssec_validation,
  allow_open_resolver}`), `authoritative` (JSONB: `{listen_addresses[], port,
  transfer_peers[]}`), `recursor_hash`, `auth_hash` (sha256 of the last rendered
  file content successfully written), `updated_by`, `updated_at`.
- Not tenant-scoped: `dns_app` may read/write it only through the configuration
  service, which requires platform-admin (or system scope for start-up
  re-apply). Absent row → defaults (spec US5-1).

### dns_ipam_sync  (RLS)
- `tenant_id`, `ip_address_id` (IPAM id), `address` (inet), `hostname`
  (canonical, last applied), `forward_zone_id`, `forward_name`, `forward_type`
  (A|AAAA), `reverse_zone_id`, `reverse_name` (PTR owner), `last_event`
  (created|updated|scanned|deleted|reconciled), `updated_at`.
- **PK**: `(tenant_id, ip_address_id)`.
- Row removed after a successful delete of both records; forward/reverse columns
  are nulled individually when that side is removed or skipped.

### dns_acme_challenges  (RLS)
- `id` (PK), `tenant_id`, `zone_id` (FK ON DELETE CASCADE), `fqdn`, `value`
  (the public TXT token — not secret), `requested_by` (SPIFFE ID), `created_at`.
- **Unique**: `(tenant_id, fqdn, value)`. Index `(created_at)` for the sweeper.
- Deleted on CleanUp or by the sweeper after `acme.max_age`.

### dns_audit_events  (hypertable, append-only)
- Framework audit vocabulary: actor (user id | SPIFFE ID | "ipam-sync" |
  "system"), tenant (null for platform configuration), action, subject kind/id,
  outcome, redacted detail, time. No API keys, config file bodies or record
  values beyond name/type.

## PowerDNS-side objects (not stored locally)

- **Zone**: `{id, name, kind, serial, notified_serial, masters, dnssec,
  nameservers, account, rrsets}`.
- **RRset**: `{name, type, ttl, changetype REPLACE|DELETE, records: [{content,
  disabled}], comments: [{content, account}]}` — the API view of a record set
  (spec entity "Record set").
- **Supermaster**: `{ip, nameserver, account}`.
- **Recursor forward zone**: `{name, kind: Forwarded, servers: ["<ip>:<port>"],
  recursion_desired: false}`.

## Relationships
- Tenant 1–N Zones, Templates, Supermasters, Sync rows, Challenges.
- Zone 0–1 Template (informational); Zone 1–N Challenges (cascade).
- Sync row → forward Zone and reverse Zone (by id; nulled if a zone is deleted —
  enforced by the zone-delete path, not FK, so zone deletion is never blocked).
- Server configuration is platform-wide (no tenant).

## State transitions
- **Zone**: created (PowerDNS then local; compensated) → updated (metadata) →
  deleted (PowerDNS, recursor forward, local). Kind changes are allowed except
  to/from slave without masters (refused).
- **Sync row**: absent → forward+reverse applied → host renamed (old forward
  deleted, new applied, PTR repointed) → host cleared (forward + PTR deleted,
  row kept with nulls until address delete) → deleted (row removed).
- **Challenge**: presented → cleaned up | swept (after max age).
- **Configuration**: defaults → saved (validated) → applied per server (file
  written if hash changed → container restarted if enabled, else
  `restart_required`) → re-applied at start-up.

## Validation rules (from requirements)
- Zone name: canonical form, labels 1–63, total ≤ 253, not the root, not a
  public suffix (reverse zones excepted), no overlap with another tenant's zone
  (FR-002, D1, D4).
- Masters / supermaster IP: IP literal (optional port), not loopback, link-local,
  unspecified or multicast (SSRF guard).
- Record set: name inside the zone (`@`/relative accepted), type in the 15
  editable types, TTL 60–604800, 1–100 values, comment ≤ 512 chars, content
  per type (D5); CNAME exclusive and never at the apex; SOA read-only.
- Template: name 1–100 chars unique per tenant; ≤ 200 records each validated
  against a placeholder zone.
- Configuration: IP literals, ports 1–65535, CIDRs, `IP[:port]` upstreams,
  ≤ 32 entries per list, open resolver only with the explicit flag (D11).
- Challenge: `fqdn = "_acme-challenge." + domain-without-"*."`, inside a tenant
  zone, value 43-char base64url (D12).
- Dashboard: window ∈ {1h, 6h, 24h} (D13).
