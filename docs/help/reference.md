---
title: Reference
summary: Zone and record set fields, zone kinds, editable record types, permissions and roles, API routes, errors and limits.
kind: reference
order: 60
tags: [dns, reference, permissions, api, limits, records]
requires: zones:read
---
## Zone fields

| Field | Meaning |
|---|---|
| `name` | canonical: lower case, trailing dot, internationalised names as A-labels; at most 254 characters; fixed after creation |
| `kind` | `native`, `master`, `slave`, `producer`, `consumer` |
| `masters` | primaries `IP` or `IP:port`, at most 16; required for `slave` and `consumer`, refused otherwise |
| `nameservers` | initial `NS` set, at most 16 host names; not for `slave` and `consumer` |
| `dnssec` | DNSSEC flag passed to PowerDNS |
| `description` | at most 1000 characters |
| `template_id` | template applied at creation |
| `origin` | `manual`, or `ipam` for zones the IPAM sync created |
| `serial`, `notified_serial` | from PowerDNS (zone detail only) |

## Record set fields

| Field | Meaning |
|---|---|
| `name` | `@`, a name relative to the zone, or a full name ending with a dot; must lie inside the zone |
| `type` | one of the [editable types](#record-types) |
| `ttl` | seconds, within `records.min_ttl`–`records.max_ttl` (default 60–604800) |
| `values` | 1–100 values (`records.max_values`), each `content` (up to 4096 characters) and `disabled` |
| `comment` | at most 512 characters |
| `read_only` | true for `SOA` |

## Record types

Editable: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SRV`, `TXT`, `CAA`, `DS`,
`DNSKEY`, `TLSA`, `SSHFP`, `SPF`, `NAPTR`. `SOA` is shown read-only.

| Type | Checked |
|---|---|
| `AAAA` | no IPv4-mapped addresses |
| `CNAME` | one value, not at the apex, alone at its name |
| `MX` | a null MX (`.`) needs preference 0 |
| `CAA` | flags 0 or 128; tag `issue`, `issuewild` or `iodef`; `iodef` a `mailto:` or `http(s):` URL |
| `DS` | digest type 1, 2 or 4 with a hex digest of the matching length |
| `DNSKEY` | flags 0, 256 or 257; protocol 3; base64 key |
| `TLSA` | usage 0–3, selector 0–1, matching type 0–2, hex data of the matching length |
| `SSHFP` | algorithm 1, 2, 3, 4 or 6; fingerprint type 1 or 2 with a hex fingerprint of the matching length |
| `NAPTR` | flags letters or digits |

## Template record fields

`name` (may contain `[ZONE]`; `@` or empty is the apex), `type`, `ttl`,
`content` (may contain `[ZONE]`) and `priority` (0–65535, `MX` and `SRV`
only). A template has a `name` (1–100 characters), a `description` and up to
200 records.

## Permissions and roles

| Permission | Allows |
|---|---|
| `zones:read` | list and read zones, record sets and templates; the live event stream |
| `zones:manage` | create, change and delete zones and record sets; export zones; send NOTIFY |
| `templates:manage` | create, change and delete templates |
| `supermasters:manage` | list supermasters; adding and deleting one also needs the `platform-admin` role |
| `dashboard:read` | read the DNS dashboard |
| `backup:manage` | export and import the tenant's DNS data |
| `config:manage` | the DNS server configuration; also needs the `platform-admin` role |

| Module role | Permissions |
|---|---|
| DNS administrator | all but `config:manage` |
| DNS viewer | `zones:read`, `dashboard:read` |

Built-in roles: `owner` and `admin` hold the administrator set; `operator`,
`member` and `auditor` the viewer set. No tenant role holds `config:manage`.

## API

The browser API is under `/api/dns/v1`, through the gateway. Changing
requests need the `X-CSRF-Token` header. Request bodies with unknown fields
are refused.

| Route | Permission |
|---|---|
| `GET /zones`, `GET /zones/{id}`, `GET /zones/{id}/records` | `zones:read` |
| `POST /zones`, `PUT /zones/{id}`, `DELETE /zones/{id}` | `zones:manage` |
| `POST /zones/{id}/records` (create or replace a set), `PUT /zones/{id}/records` (change or move a set), `DELETE /zones/{id}/records?name=&type=` | `zones:manage` |
| `GET /zones/{id}/export`, `POST /zones/{id}/notify` | `zones:manage` |
| `GET /templates`, `GET /templates/{id}` | `zones:read` |
| `POST /templates`, `PUT /templates/{id}`, `DELETE /templates/{id}` | `templates:manage` |
| `GET /supermasters`, `GET /supermasters/{id}`, `POST /supermasters`, `DELETE /supermasters/{id}` | `supermasters:manage` (changes also `platform-admin`) |
| `GET /config`, `PUT /config` | `config:manage` and `platform-admin` |
| `GET /dashboard?window=1h\|6h\|24h` | `dashboard:read` |
| `GET /stream` | `zones:read` |
| `POST /backup/export`, `POST /backup/import` | `backup:manage` |

`PUT /zones/{id}/records` takes the set to change and its new content:

```json
{
  "original": {"name": "www.example.com.", "type": "A"},
  "record": {"name": "www", "type": "A", "ttl": 300, "values": [{"content": "192.0.2.11"}]}
}
```

Lists take `page`, `page_size` (at most 200), `sort` and `order`. Record lists
default to 100 per page.

### Backup

An export carries the tenant's zone metadata (with each zone's BIND text, for
reference only), templates and supermasters; never API keys. An import
(`mode` `skip` or `overwrite`) re-links zones that still exist on the DNS
server and reports missing ones in `missing_in_pdns`; it does not recreate
zones or records. Supermasters are restored only for a platform
administrator.

### Errors

| Status | `reason` | Typical cause |
|---|---|---|
| 400 | `malformed_body` | invalid JSON or an unknown field |
| 400 | `bad_request` | invalid input, refused by PowerDNS, zone too large to export |
| 403 | `forbidden` | the permission or role is missing |
| 404 | `zone_not_found`, `record_not_found`, `template_not_found`, `not_found` | no such item in your tenant |
| 409 | `duplicate` | zone name taken (by anyone), overlapping, or already on the server |
| 409 | `conflict` | template or supermaster already exists; a set already exists under the new name and type of a moved set |
| 413 | `body_too_large` | the request body is over its limit |
| 422 | `invalid_name` | invalid or public-suffix zone name, record name outside the zone |
| 422 | `invalid_record` | a record value, TTL or CNAME rule was refused (`detail` names the field) |
| 422 | `invalid_kind` | missing primaries, NOTIFY on a non-primary zone, write to a secondary zone |
| 422 | `invalid_config` | a server configuration value was refused |
| 503 | `pdns_unavailable` | the DNS server API did not answer |
| 503 | `metrics_unavailable` | the dashboard's metrics source did not answer |

## Limits

| Limit | Value |
|---|---|
| zone name | 254 characters |
| primaries, nameservers per zone | 16 each |
| values per record set | `records.max_values` (default 100) |
| value | 4096 characters |
| TTL | `records.min_ttl`–`records.max_ttl` (default 60 s–1 week) |
| template records | 200 |
| BIND export | `limits_dns.max_export_bytes` (default 32 MiB) |
| backup import body | 64 MiB |
