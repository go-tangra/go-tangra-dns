# Phase 1 Contracts: DNS Service

Surfaces: (A) browser HTTP API via the gateway under `/api/dns`; (B)
module-to-module gRPC (`dns.v1`, SPIFFE mTLS) including the lcm-only DNS-01
challenge operations; (C) events consumed (IPAM) and published; (D) internal
client interfaces (PowerDNS auth API, recursor API, Docker restarter, metrics
query, IPAM, secrets), each with a fake; (E) the lcm-side provider.

## A. Browser HTTP API — prefix `/api/dns/v1` (gateway-proxied)

Every route declares `x-freya-permission` (or `x-freya-public`); mutating routes
carry the platform CSRF header. Errors use the platform envelope with reasons
`bad_request`, `invalid_name`, `invalid_record`, `invalid_kind`,
`invalid_config`, `zone_not_found`, `record_not_found`, `template_not_found`,
`duplicate` (zone name taken/overlapping — owner never revealed), `conflict`,
`forbidden`, `pdns_unavailable`, `metrics_unavailable`.

Zones (`zones:read` for reads, `zones:manage` for writes)
- `GET /zones` — query `query` (name substring), `kind`, `origin`, `page`,
  `page_size` (≤ 100) → `{items: Zone[], total}` (name order).
- `POST /zones` `{name, kind, masters?, nameservers?, dnssec?, description?,
  template_id?}` → Zone (201; `duplicate` if taken/overlapping/present in
  PowerDNS; compensated on local failure).
- `GET /zones/{id}` → Zone + `{serial, notified_serial}` from PowerDNS.
- `PUT /zones/{id}` `{kind?, masters?, dnssec?, description?}` → Zone.
- `DELETE /zones/{id}` → 204 (PowerDNS, recursor forward, local row).
- `GET /zones/{id}/export` → `{zone, text}` BIND text (size-capped).
- `POST /zones/{id}/notify` → 202 (master/producer only; else `invalid_kind`).

Records (`zones:read` / `zones:manage`)
- `GET /zones/{id}/records` — query `type`, `query` (name substring), `page`,
  `page_size` (≤ 500) → `{items: RecordSet[], total}`; SOA included with
  `read_only: true`.
- `POST /zones/{id}/records` RecordSetInput → RecordSet (REPLACE of name+type).
- `PUT /zones/{id}/records` `{original: {name, type}, record: RecordSetInput}` →
  RecordSet (rename = REPLACE new + DELETE old in one PATCH).
- `DELETE /zones/{id}/records?name=&type=` → 204.
- RecordSetInput: `{name ("@" | relative | absolute), type, ttl, values:
  [{content, disabled}], comment?}`; RecordSet adds the qualified `name`.

Templates (`zones:read` for list/get, `templates:manage` for writes)
- `GET /templates`, `GET /templates/{id}`, `POST /templates` `{name,
  description?, records: [{name, type, ttl, content, priority?}]}`,
  `PUT /templates/{id}` (replaces the record list), `DELETE /templates/{id}`.

Supermasters (`supermasters:manage`; create/delete also platform-admin)
- `GET /supermasters`, `GET /supermasters/{id}`, `POST /supermasters` `{ip,
  nameserver}` (account forced to the tenant), `DELETE /supermasters/{id}`.
  No update route.

Server configuration (`config:manage` **and** platform-admin)
- `GET /config` → `{recursor, authoritative, defaults: bool, restarter:
  {enabled, containers: {auth, recursor}}}`.
- `PUT /config` `{recursor: {listen_addresses, port, allowed_networks,
  upstream_resolvers, dnssec_validation, allow_open_resolver?}, authoritative:
  {listen_addresses, port, transfer_peers}}` → `{recursor, authoritative,
  changed: ["recursor"|"authoritative"], restarted: [container names],
  restart_required: [..], errors: [{server, reason}]}`.

Dashboard (`dashboard:read`)
- `GET /dashboard?window=1h|6h|24h` → `{available: bool, window, step_seconds,
  panels: [{id, kind: stat|series, unit, series: [{labels, points: [[ts,
  value]]}] | value}]}`. Panel ids are a fixed catalogue (research D13); no
  query text accepted. `available:false` when no metrics URL is configured.

Backup, stream, system
- `POST /backup/export` `{tenant_id?}`, `POST /backup/import` `{backup, mode?:
  skip|overwrite, tenant_id?, full?}` → `{tenant_id, mode, imported, skipped,
  missing_in_pdns}` (`backup:manage`; another tenant/full restore →
  platform-admin; bad document → 422). Never contains API keys.
- `GET /stream` (`zones:read`) — SSE of this tenant's `dns.*` events
  (`x-freya-timeout-seconds: 300`, module ends at 290 s, resume with `last_id`).
- `GET /health` (public).

No response contains PowerDNS/recursor API keys, Docker details beyond the two
container names, or rendered config file contents.

## B. Module-to-module gRPC — `dns.v1` (SPIFFE mTLS)

```proto
service Challenges {            // policy: from spiffe://example.org/svc/lcm ONLY
  rpc Present(ChallengeRequest) returns (ChallengeResponse);
  rpc CleanUp(ChallengeRequest) returns (ChallengeResponse);
}
message ChallengeRequest { string tenant_id = 1; string domain = 2; string fqdn = 3; string value = 4; }
message ChallengeResponse { string zone = 1; }        // the zone written/cleaned

service Zones {                 // policy: any module (read-only)
  rpc List(ListZonesRequest) returns (ListZonesResponse);   // {tenant_id, query, page, page_size}
  rpc Get(GetZoneRequest) returns (Zone);                     // {tenant_id, id | name}
  rpc FindForName(FindForNameRequest) returns (Zone);         // longest managed zone for a FQDN
}
```

- Challenges: the handler re-checks the peer SPIFFE ID equals the configured
  lcm identity (`acme.allowed_caller`, default `spiffe://example.org/svc/lcm`)
  → otherwise `PermissionDenied`, audited `challenge.refused`. `fqdn` must be
  `_acme-challenge.<domain without "*.">`; no tenant zone → `NotFound`, nothing
  written; CNAME at the name → `FailedPrecondition`; bad value →
  `InvalidArgument`; PowerDNS down → `Unavailable`. Present/CleanUp are
  idempotent (present twice = one value; cleanup of an absent value = OK).
- Tenant: the request `tenant_id` is honoured only for these allow-listed
  platform callers (lcm acts for the issuer's tenant); RLS scopes all reads.
- Policy (`services/dns/deploy/policy.yaml`): gateway forwards `*`; lcm →
  `/dns.v1.Challenges/Present|CleanUp`; `svc/*` → `/dns.v1.Zones/*`,
  `/grpc.health.v1.Health/Check`.

## C. Events

### Consumed — `platform:events:<tenant>` (Valkey stream)
Types `ipam.ip_address.created | updated | deleted | scanned`, fields `{type,
data, to, at}`; `data` JSON (services/ipam/internal/events/events.go):
`{action, id, address, subnet_id, hostname, device_id}`.
- Decoder: ≤ 4 KiB, required `id` (≤ 64 chars) and `address` (IP literal);
  unknown fields ignored; anything else dropped + counted.
- The payload is a **trigger**: the consumer calls ipam over mTLS
  (`IpAddressService/Get {tenant_id, id}`, `SubnetService/Get`) and acts on the
  returned state (research D8). Tenants consumed: `ipam_sync.tenants`.
- ipam's `deploy/policy.yaml` must allow `spiffe://example.org/svc/dns` →
  `/ipam.v1.IpAddressService/Get`, `/ipam.v1.IpAddressService/Find`,
  `/ipam.v1.SubnetService/Get`.

### Published — `platform:events:<tenant>`
`dns.zone.created`, `dns.zone.updated`, `dns.zone.deleted` `{zone_id, zone,
kind, origin, actor_kind}`; `dns.record.changed` `{zone_id, zone, name, type,
action: upserted|deleted, source: api|ipam|acme}`. Never record values, keys or
configuration.

## D. Internal interfaces (each with a fake for offline tests)

- `pdns.Client` (PowerDNS Authoritative HTTP API, `X-API-Key` from secrets):
  `ListZoneNames(ctx) ([]string, error)`, `GetZone(ctx, id) (Zone, error)`,
  `CreateZone(ctx, Zone) (Zone, error)`, `UpdateZoneMetadata(ctx, id, Zone)
  error`, `DeleteZone(ctx, id) error`, `PatchRRsets(ctx, id, []RRset) error`,
  `NotifyZone(ctx, id) error`, `ExportZone(ctx, id) (string, error)`,
  `ListSupermasters(ctx)`, `CreateSupermaster(ctx, Supermaster) error`,
  `DeleteSupermaster(ctx, ip, nameserver) error`. Errors: `ErrNotFound`,
  `ErrConflict`, `ErrUnavailable`, `*APIError{Status, Message}` (sanitised,
  truncated, never the key).
- `recursor.Client`: `Enabled() bool`, `SyncForward(ctx, zone) error`,
  `RemoveForward(ctx, zone) error`, `ListForwards(ctx) ([]string, error)`,
  `Ready(ctx) error`; `recursor.Reconciler.Run(ctx)`, `ReconcileNow(ctx)`.
- `dnsconf.Restarter` (Docker Engine unix socket): `Enabled() bool`,
  `Restart(ctx, target Target) (container string, err error)` where
  `Target ∈ {TargetAuth, TargetRecursor}` maps to the two configured names; the
  concrete client issues only `POST /containers/{name}/restart` and `GET
  /_ping`. `dnsconf.FileWriter`: `WriteIfChanged(path, content) (changed bool,
  err error)` (atomic).
- `dashboard.MetricsClient` (Prometheus HTTP API): `Query(ctx, promql, at)`,
  `QueryRange(ctx, promql, start, end, step)` — called only with catalogue
  expressions.
- `ipamsync.IPAM` (over `ipamclient`): `GetAddress(ctx, tenant, id)
  (Address, error)` (NotFound → deleted), `GetSubnet(ctx, tenant, id) (Subnet,
  error)`.
- `ipamsync.Reader` (stream): `XRead`, `XLast` (as services/deployer).
- `secrets.Source`: `PDNSAPIKey(ctx) (string, error)`,
  `RecursorAPIKey(ctx) (string, error)` (`warden:` | dev `file:` references).
- `validate`: `ZoneName(string) (string, error)`, `RecordName(zone, name)
  (string, error)`, `Content(type, zone, value) (canonical string, error)`,
  `RecordSet(zone, RecordSetInput, existing []RRset) (RRset, error)`,
  `Masters([]string)`, `ReverseZone(ip, prefix) (zone, owner string)`.

## E. lcm side (services/lcm)

- `internal/acme/dns.go`: registry entry `{Name: "freya-dns", DisplayName:
  "Freya DNS", Fields: []}`; `NewProviderWith(name, creds, ProviderDeps{FreyaDNS
  FreyaDNSClient, TenantID string})` (existing `NewProvider` delegates with
  empty deps → `ErrUnsupportedProvider` for freya-dns).
- `internal/acme/freyadns.go`: `FreyaDNSProvider{client, tenantID}` implementing
  `DNSProvider.Present/CleanUp` by calling `dnsclient.Present/CleanUp`; errors
  mapped to `ErrProvider` without echoing server messages.
- `FreyaDNSClient` interface: `Present(ctx, tenant, domain, fqdn, value) error`,
  `CleanUp(ctx, tenant, domain, fqdn, value) error` (satisfied by
  `services/dns/pkg/dnsclient`).
- lcm config: optional `dns: {service: dns}` + discovery `dns: ["dns:9965"]`.
