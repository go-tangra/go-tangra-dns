# Phase 0 Research: DNS Service

Decisions resolving the Technical Context. Scope: a replica of go-tangra-dns
(management plane over PowerDNS Authoritative + Recursor: zones, record sets,
templates, supermasters, BIND export, NOTIFY, resolver forwarding, server
configuration applied by container restart, metrics dashboard, IPAM-driven
forward/reverse records) adapted to Freya, plus the enhancements listed in the
spec Overview (enforced permissions, cross-tenant zone uniqueness, per-type
validation, record search, IPv6 sync, subnet-sized reverse zones, public-suffix
parent zone, curated dashboard, events, audit, Freya DNS ACME provider).

Reference behaviour read from go-tangra-dns: `internal/pdns` (auth API client),
`internal/recursor` (forward-zone client + 5-minute reconciler),
`internal/dnsconf` (YAML/conf renderers + Docker restart), `internal/event`
(IPAM subscriber/handler: IPv4 only, last-two-labels parent zone, fixed /24
reverse zone), `internal/service` (zone/record/template/supermaster/config/
dashboard services), `protos/dns/service/v1`, `frontend/src/views`.

## D1. Storage, tenant isolation and global zone ownership
**Decision**: TimescaleDB with per-tenant RLS on every tenant table
(`dns_zones`, `dns_zone_templates`, `dns_supermasters`, `dns_ipam_sync`,
`dns_acme_challenges`); `dns_audit_events` is a hypertable; `dns_server_config`
is a platform-scoped single row with no tenant column, reached only by the
platform-admin configuration path. Record sets are **not** stored locally
(PowerDNS is the source of truth; the source did the same). Zone names are
canonical (lower-case, trailing dot) with a **global** unique index on
`dns_zones.name` — a unique index is enforced regardless of RLS, so a second
tenant's insert fails even though it cannot see the first row. Because PowerDNS
is shared, equality is not enough: a tenant creating `sub.example.com.` under
another tenant's `example.com.` (or `com.`-like parents above it) would shadow
or pre-empt it. A narrow `SECURITY DEFINER` function
`dns_zone_conflict(name, tenant)` returns only a boolean: true when any zone of
**another** tenant is equal to, an ancestor of, or a descendant of `name`.
Same-tenant nesting (e.g. `example.com.` + `lab.example.com.`) is allowed. A
second function `dns_zone_names()` returns only zone names for the system-scoped
recursor reconciler. Every PowerDNS operation first loads the zone under RLS
(ownership check, SR-001) and uses the stored `pdns_id`, never a caller-supplied
name.
**Rationale**: the source relied on ent tenant filtering with a per-tenant
unique index `(tenant_id, name)`, so two tenants could claim the same zone on a
shared PowerDNS. RLS + a global unique index + the overlap function close the
hijack/shadow threat by construction while revealing nothing about the owner
(the caller only learns "duplicate").
**Alternatives**: per-tenant PowerDNS servers or views (out of scope, heavy);
app-level checks only (race-prone; the unique index is the final arbiter).

## D2. Zone lifecycle and PowerDNS consistency
**Decision**: Create = validate name/kind/masters/nameservers → overlap check →
refuse if PowerDNS already has the zone (`GET` 200 → `duplicate`, never adopted —
spec edge case) → `POST` to PowerDNS (with template rrsets, D7) → insert local
row; if the insert fails the PowerDNS zone is deleted again (compensation) and
the error returned. Update (kind, masters, description, DNSSEC) = `PUT` metadata
first, then the local row; on local failure the previous metadata is re-`PUT`.
Delete = ownership check → PowerDNS `DELETE` (404 tolerated) → recursor forward
removal (best effort) → local row delete; published event + audit. Serial is
read from PowerDNS on get/list-detail (list shows local fields only; serial is
fetched per zone on the detail view to keep list fast). When PowerDNS is
unreachable every mutation fails with `pdns_unavailable` before any local write
(spec US1-6). Zone kinds map to PowerDNS `Native|Master|Slave|Producer|Consumer`;
DNSSEC toggles `dnssec` on create/update (key management out of scope).
**Rationale**: PowerDNS-first ordering plus compensation guarantees no
half-created zone in either store; refusing unknown PowerDNS zones prevents
silent takeover of zones created outside the platform (or by a supermaster).

## D3. PowerDNS Authoritative API client
**Decision**: Port `internal/pdns` onto a typed stdlib client behind
`pdns.Client` (interface + fake): ListZones (names only, reconciliation),
GetZone (rrsets), CreateZone, UpdateZoneMetadata (PUT), DeleteZone,
PatchRRsets (REPLACE/DELETE), NotifyZone, ExportZone (text, size-capped),
supermasters List/Create/Delete. Differences from the source: base URL and
server id from typed config; `X-API-Key` read from the secret source per call
(rotation without restart) and never included in errors (errors carry status +
a truncated, sanitised PowerDNS message); response bodies capped (e.g. 32 MiB
for GET zone/export, 64 KiB otherwise) and JSON-decoded into typed structs;
zone ids are URL-path-escaped; per-call timeout 10 s; `ErrNotFound`,
`ErrConflict` (409/422 "already exists") and `ErrUnavailable` sentinels. The API
is reached only on the internal network (`http://pdns-auth:8081` in the stack);
PowerDNS's `webserver-allow-from` is restricted to the stack network and the
port is not published on the host. HTTPS is supported by config (TLS in front of
PowerDNS); plaintext is permitted with a startup warning (dev opt-out).
**Rationale**: parity with the source's client with bounded, typed boundary
handling (Constitution III); no vendor SDK (VI).
**Alternatives**: a third-party PowerDNS Go client (unmaintained / unnecessary).

## D4. Zone name rules
**Decision**: `validate.ZoneName` canonicalises (trim, lower-case, IDNA
rejected unless already in A-label form, single trailing dot), checks label
syntax (1–63 octets, total ≤ 253, LDH plus `_` allowed only for non-first
labels, no empty labels) and refuses: the root, a **public suffix** per
`golang.org/x/net/publicsuffix` (`com.`, `co.uk.` …, but not reverse zones under
`in-addr.arpa.`/`ip6.arpa.`, which are validated by the reverse rules), and
names overlapping another tenant's zone (D1). Record names: relative (`@`,
`www`, `_sip._tcp`) or absolute; qualified against the zone and required to be
equal to or inside it; wildcard `*` only as the left-most label.
**Rationale**: SC-002 (100 % of invalid/duplicate names refused before
PowerDNS) and SR-001 (no shadowing via public suffixes).

## D5. Record content validation (per type)
**Decision**: New dependency `github.com/miekg/dns` parses each value in
presentation format by building one RR line from **our** qualified name, TTL,
class `IN`, the type and the value (`dns.NewRR`), after first refusing control
characters, CR/LF and `$`-directives in the value; the parse must yield exactly
one RR of the requested type. Semantic rules on top: A = IPv4, AAAA = IPv6 (no
v4-mapped); CNAME alone at its name, never at the apex; MX/SRV priority (and SRV
weight/port) present and in range with an FQDN target; NS/PTR/CNAME targets are
FQDNs; TXT/SPF split into ≤ 255-octet quoted strings (the module quotes
unquoted input); CAA flags 0/128 with tag `issue|issuewild|iodef` (others
refused); TLSA usage/selector/matching-type ranges with hex data of the right
length; SSHFP algorithm/fingerprint-type with hex of the right length; DS/DNSKEY
field ranges; NAPTR order/preference/flags/service/regexp/replacement; SOA is
read-only (edits refused — serials are PowerDNS-managed). TTL 60–604800 (config
bounds). The **canonical re-serialisation** produced by the parser (`rr.String()`
rdata) is what is sent to PowerDNS, so nothing the caller typed reaches a zone
file verbatim. The same validator backs the HTTP API, templates, IPAM sync and
challenges.
**Rationale**: SC-002 requires type-inconsistent content to be refused before
PowerDNS; miekg/dns is the de-facto Go DNS library (CoreDNS, many resolvers),
parses exactly the presentation format PowerDNS accepts, and is fuzzable
end-to-end. Hand-written parsers for 15 types would be larger and less correct.
**Alternatives**: rely on PowerDNS's own 422 errors (the source's behaviour —
rejected: SC-002 says "before reaching the DNS server"); hand-written parsers
(rejected above); `codeberg.org/miekg/dns` v2 (acceptable successor — pick the
maintained line at implementation and record the choice in go.mod review).

## D6. Record listing, search, export and NOTIFY
**Decision**: Records list = one `GET zone` (rrsets) → in-module filter by type
and case-insensitive name substring → stable sort (name, type) → page
(`page_size` ≤ 500) with the correct total; SOA is included read-only. Create/
replace = `PATCH` REPLACE of (name, type) with all values, per-value `disabled`
and one comment; update = same, keyed by the original (name, type) — a rename
is REPLACE new + DELETE old in one PATCH; delete = PATCH DELETE. CNAME
exclusivity is checked against the current rrsets in the same request. Export =
PowerDNS `/export` text streamed back (size cap). NOTIFY only for `master`
(and `producer`) kinds; any other kind → `invalid_kind` without calling
PowerDNS. A single PATCH per request keeps each change atomic in PowerDNS.
**Rationale**: SC-008 (5,000 rrsets < 3 s: one upstream call, in-memory filter);
parity with the source's record service plus search.

## D7. Zone templates
**Decision**: Per-tenant templates `{name (unique per tenant, case-insensitive),
description, records: [{name, type, ttl, content, priority}]}` (≤ 200 records).
Template records are validated at save time with a placeholder zone
(`example.invalid.`) so broken templates are refused early. Expansion on zone
creation: `[ZONE]` replaced in name and content with the zone name (no trailing
dot in content substitution, as the source), `@`/empty → apex, relative names
qualified, **priority applied** to MX/SRV (`"<prio> <content>"`; the source
dropped it), records with the same (name, type) **merged** into one rrset (the
source emitted duplicate rrsets that PowerDNS rejects), then validated again
against the real zone before the PowerDNS `POST`.
**Rationale**: FR-006 plus fixing two source defects.

## D8. IPAM event intake (platform event bus, verified)
**Decision**: Consume `ipam.ip_address.{created,updated,deleted,scanned}` from
`platform:events:<tenant>` Valkey streams with the same `Reader` pattern as
services/deployer (`XLast` on start, `XRead` block 2 s, ignore own events), for
the tenants in config `ipam_sync.tenants` (default: the mesh-enroll tenant —
the same single-tenant limitation the deployer consumer has; a platform tenant
directory is future work). Actual IPAM payload
(`services/ipam/internal/events/events.go`): `{action, id, address, subnet_id,
hostname, device_id}` — **no previous host name** and no producer identity; the
stack's Valkey ACLs let every module write every key. Therefore an event is
treated as an **untrusted trigger only** (SR-004): the consumer validates the
type and payload shape (bounded, fuzzed decoder), then **fetches the address
from IPAM over SPIFFE mTLS** (`IpAddressService/Get` by id in the event's
tenant, via a small `ipamclient.GetAddress` addition — the client today only
exposes `FindAddress` by address string) and acts on IPAM's answer: present with a host name → upsert;
not found → treat as deleted; the payload's host name/address are never used
for writes. The previous names come from local **sync state** (`dns_ipam_sync`,
keyed by tenant + IPAM address id, holding the forward name/type/zone and PTR
name/zone last written), which makes updates, renames, cleared host names and
deletes exact and idempotent (duplicate or out-of-order events converge to
IPAM's current state). Subnet prefix for reverse sizing comes from
`SubnetService/Get` (fallback /24 IPv4, /64 IPv6 when IPAM is unreachable or the
subnet is gone). ipam's `deploy/policy.yaml` gains a rule allowing
`spiffe://example.org/svc/dns` to call `SubnetService/Get` and
`IpAddressService/Get|Find`.
**Rationale**: the source trusted Redis pub/sub payloads (including tenant id)
outright. Fetch-to-verify (as the deployer's fetch-to-match) means a forged
event can at most trigger a re-read of genuine IPAM state in the tenant it
names, never write attacker-chosen records. Sync state removes the need for a
`previous_hostname` field IPAM does not publish.
**Alternatives**: extend IPAM's payload with `previous_hostname` and a producer
signature (IPAM change; still forgeable without per-module stream ACLs);
pub/sub channels as in the source (not the Freya bus).

## D9. Forward/reverse planning for IPAM addresses
**Decision**: Forward zone = the tenant's **longest** managed zone that equals
or is a suffix of the host name; if none, the **registrable domain**
(`publicsuffix.EffectiveTLDPlusOne`) is created as a native zone marked
`origin=ipam` (the source took the last two labels, wrong for `co.uk`); a bare
host or a host whose registrable domain overlaps another tenant's zone is
skipped + logged. Record type A (IPv4) / AAAA (IPv6); TTL from config (default
3600). Reverse: IPv4 zone sized from the subnet prefix rounded **down** to an
octet boundary and clamped to /8../24 (`/22` → /16 zone `x.y.in-addr.arpa.`);
IPv6 rounded down to a nibble boundary, clamped to /4../64 (`/64` →
16-nibble `ip6.arpa.` zone). An existing **longer** reverse zone of the tenant
that contains the address wins over creating a new one. PTR target = host FQDN.
If the reverse zone would conflict with another tenant (D1), the PTR is skipped
and logged — never written (SR-004). Zones are never deleted by sync. Forward
and reverse writes are independent: a reverse failure never undoes the forward
record (source behaviour), and both are recorded in sync state only on success.
**Rationale**: FR-009 + spec US2 incl. IPv6 and subnet sizing; the source was
IPv4-only with fixed /24.

## D10. Resolver forwarding and reconciliation
**Decision**: Port `internal/recursor` behind `recursor.Client` (interface +
fake): `SyncForward(zone)` (idempotent delete-then-create of a `Forwarded` zone
pointing at the authoritative server's **IP:port** — the recursor API rejects
host names, so the auth host is resolved at sync time as in the source),
`RemoveForward(zone)` (404/422 = success), `ListForwards()`. Called on zone
create/delete (best effort; failures logged + retried by the reconciler), at
start-up, every `recursor.reconcile_interval` (default 5 min), and after any
restart from a configuration change (poll the recursor API for readiness,
bounded, instead of the source's fixed 6 s sleep). The reconciler also
**removes** forward entries for zones no longer managed (the source only
added), except the root/`.` and configured static forwards. Recursor 5.x needs
its API-managed zones persisted: `webservice.api_dir` on a volume (verify key
name for the pinned version). The recursor being down never blocks zone
management (spec edge case).
**Rationale**: FR-008; parity plus drift removal.

## D11. Server configuration, rendering and container restart
**Decision**: A typed model `{recursor: {listen_addresses[], port,
allowed_networks[], upstream_resolvers[], dnssec_validation: off|process|
validate}, authoritative: {listen_addresses[], port, transfer_peers[]}}` with
the spec defaults (resolver `0.0.0.0`,`::` :53, private networks + loopback,
validation off; auth `0.0.0.0` :53, no peers). Validation: listen addresses are
IP literals; port 1–65535; networks/peers are CIDRs or IPs (canonicalised);
upstreams `IP[:port]`; list lengths bounded; `0.0.0.0/0`/`::/0` in
`allowed_networks` refused unless the platform admin sets
`allow_open_resolver=true` (audited, warned) — the "opening the resolver to the
internet" threat. Rendering: `RenderRecursorYAML` (recursor 5.x YAML) and
`RenderAuthConf` (key=value) built only from validated typed values through a
writer that quotes every scalar, so no free text reaches the files (SR-003);
files written atomically (temp + rename, 0644) to fixed paths in the shared
include-dir volumes, **only when the content hash differs**. Only the container
whose file changed is restarted; a no-op save restarts nothing (SC-006). On
start-up the stored configuration is re-applied (file rewritten if drifted;
restart only if changed) and forwards re-synced (FR-010, US5-4).
**Docker socket (requester decision: keep)**: the restarter is a tiny client on
the unix socket that implements **only** `POST /containers/{name}/restart` (and
`/_ping`), where `{name}` is one of the **two names fixed in config**
(`docker.auth_container`, `docker.recursor_container`) chosen by an enum
(`auth|recursor`) — no request field ever carries a container name; names are
validated at start-up against `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$` and
path-escaped. The feature is **disabled unless `docker.enabled: true`**; when
disabled, a save renders files and reports `restart_required` instead of
restarting. The socket must be mounted **read-write** (Docker's `:ro` on a
socket bind does not restrict the API; the connect(2) needs write permission),
and the non-root runtime user joins the socket's group (`group_add` with the
host docker GID). **Risk accepted by the requester**: anyone who compromises the
dns container can drive the full Docker API (root-equivalent on the host).
Compensating controls: the code path cannot address other containers (enum +
config, unit + fuzz tested), platform-admin authority + audit on every restart,
no generic Docker client dependency, disabled by default, dev-stack only by
default; production guidance (deploy README) recommends placing an
API-filtering socket proxy (allowing only `POST /containers/<two names>/restart`)
between the service and the daemon, or disabling the restarter and applying
changes out of band.
**Rationale**: FR-010/SR-003 with the requester's choice, minimising what the
code can do with the socket.
**Alternatives**: socket proxy by default (offered; requester kept direct
socket); PowerDNS runtime control (`rec_control`/`pdns_control` cannot change
listen addresses without restart); SIGHUP via shared PID namespace (fragile).

## D12. ACME DNS-01 for hosted domains (Freya DNS provider in lcm)
**Decision**: dns exposes `dns.v1.Challenges` with `Present{tenant_id, domain,
fqdn, value}` and `CleanUp{…}` over SPIFFE mTLS. Authorisation is double: the
dns `policy.yaml` allows only `spiffe://example.org/svc/lcm` on these methods,
**and** the handler re-checks the peer SPIFFE ID (SR-005). Rules: `fqdn` must be
`_acme-challenge.` + the domain with any leading `*.` removed; it must fall
inside the tenant's longest matching zone (else `not_found` — nothing written);
a CNAME at the name refuses; value is a 43-char base64url string. Present =
read the TXT rrset at the name, add the quoted value if absent (other values
kept), PATCH REPLACE with TTL 60; CleanUp = remove only that value, DELETE the
rrset when empty. Per-name mutex serialises concurrent Present/CleanUp (apex +
wildcard share a name). Each present is recorded in `dns_acme_challenges` and a
sweeper removes values older than `acme.max_age` (default 1 h) whose CleanUp
never arrived (SC-005). lcm side: registry entry `freya-dns` ("Freya DNS", no
credential fields) in `services/lcm/internal/acme/dns.go`; a new
`FreyaDNSProvider` (`internal/acme/freyadns.go`) implementing `DNSProvider` over
`services/dns/pkg/dnsclient`, carrying the issuer's tenant; `NewProvider` gains a
dependency-injected variant (`NewProviderWith(name, creds, ProviderDeps{FreyaDNS,
TenantID})`) used by `issue.acmeClientFor`; lcm dials `dns` lazily (discovery
entry) and returns `ErrUnsupportedProvider` when dns is not configured. No DNS
credentials are stored for this provider.
**Rationale**: FR-012/SC-005 with no vendor credentials; mesh identity replaces
API keys.
**Alternatives**: lcm writing to PowerDNS directly with the API key (spreads the
secret, bypasses tenant ownership — rejected); lcm's existing generic
`powerdns` provider entry (needs credentials per issuer, no tenant check).

## D13. Dashboard (curated panels)
**Decision**: A fixed catalogue in code: resolver QPS, cache hit %, concurrent
queries, uptime, latency buckets (answers0_1 … 100_1000), answer codes over time
(NOERROR/NXDOMAIN/SERVFAIL), questions vs outqueries, auth query rate, auth
packet/query cache hit %, auth SERVFAIL/NXDOMAIN packets (the PromQL of the
reference's dashboard view). API: `GET /dashboard?window=1h|6h|24h` runs the
whole set server-side (bounded concurrency, 10 s timeout, response caps) with
step 60 s / 300 s / 900 s and returns named series; no query text is accepted
(SR-006). No metrics URL configured → `{available: false}` (UI notice, US6-2).
The Prometheus client is stdlib HTTP (`/api/v1/query`, `/api/v1/query_range`)
behind an interface + fake. The stack gets an optional `metrics` profile running
Prometheus scraping both PowerDNS webservers' `/metrics`.
**Rationale**: the source proxied arbitrary PromQL from the browser
(reconnaissance/DoS vector).

## D14. PowerDNS API keys (secret references)
**Decision**: Config holds references only: `pdns.api_key_ref`,
`recursor.api_key_ref`, resolved by a `secrets.Source` adapted from
services/ticket/internal/secrets (`warden:<id>` in production, `file:<path>`
dev-only with a startup warning), cached with a refresh interval so rotation
needs no restart; values are never logged, returned, audited or published
(SR-002, SC-007 — verified by a redaction scan test). **Known platform gap (from
feature 014 T069)**: warden's `Secrets/GetPassword` authorises only a *user*
platform token and modules have no long-lived service-principal token, so a
warden reference cannot be resolved unattended today. As in ticket, the dev
stack therefore uses `file:` references generated by a one-shot
`dns-secrets-init` container (random keys written once into a `dns-secrets`
volume, plus the matching `api-key=` / `webservice.api_key` include snippets
for the PowerDNS containers); production keeps the warden reference path and
inherits the pending platform decision.
**Rationale**: keeps the secret out of config/env (Constitution: Secrets) with
the same, already-reviewed compromise as ticket.

## D15. Supermasters
**Decision**: Supermasters are **server-wide** trust in the shared PowerDNS: a
registered primary may auto-provision *any* zone name, bypassing the global
uniqueness/overlap rules (D1) and able to pre-empt another tenant's future
zone. Therefore: list/view with `supermasters:manage` (own tenant's rows);
**create/delete additionally require platform-administrator authority**; the
PowerDNS `account` is forced to the tenant id; `(ip, nameserver)` is globally
unique (PowerDNS's own key); the IP must be a unicast, non-loopback,
non-link-local literal and the nameserver an FQDN. Create = PowerDNS first,
local row second, compensating delete on failure; delete likewise (FR-007). The
reconciler reports PowerDNS zones with no local owner (e.g. auto-provisioned)
as a metric/log — they are never adopted (spec edge case).
**Rationale**: SR-001 threat "shadowing another tenant's domain" applies to
supermasters; this is a tightening of FR-007's "administrators" wording and is
flagged to the requester.

## D16. Permissions, roles, audit, events, backup
**Decision**: Permissions `zones:read`, `zones:manage` (zones + records +
export/NOTIFY), `templates:manage`, `supermasters:manage`, `dashboard:read`,
`backup:manage` (FR-017), and `config:manage` (configuration; **not** granted to
any tenant built-in role — handlers additionally require platform-admin, as
ticket's `IsPlatformAdmin`: the `platform-admin` role or system scope only).
Seeded roles: `dns admin` (all tenant permissions), `dns viewer` (`zones:read`,
`dashboard:read`); built-in grants owner/admin → dns admin, operator/member/
auditor → dns viewer. Audit vocabulary: zone.create/update/delete/export/notify,
record.upsert/delete, template.*, supermaster.*, config.update/apply/restart,
sync.upsert/delete/skip, challenge.present/cleanup/refused/swept, backup.* —
actor, tenant, subject, outcome; no keys, no config file contents. Events to
`platform:events:<tenant>`: `dns.zone.created|updated|deleted`,
`dns.record.changed` `{zone_id, zone, name, type, action}` (FR-013). Backup:
export/import of zone metadata, templates and supermaster rows (schema-
versioned, skip/overwrite); zone contents are included as BIND text for
reference only (not re-imported); import re-links zones that exist in PowerDNS
and are not owned elsewhere, reports missing ones; full/cross-tenant restore
platform-admin only.

## D17. UI
**Decision**: A Module-Federation remote on `@freya/ui` (FlyonUI, drawers not
dialogs, `breakpointSpecificity` build plugin, no inline styles), mirroring
services/ticket/ui and services/ipam/ui: Zones list (search, kind filter,
paging) with a zone drawer (create/edit, template picker, masters, DNSSEC,
export view with copy, NOTIFY, delete confirm); Records view per zone (type
filter + name search, inline row editor with per-type hints, multi-value with
disabled toggles, comment, SOA read-only); Templates (list + drawer with record
rows); Supermasters (list + create drawer, delete; create hidden without
platform-admin ability); Configuration (platform-admin only; resolver and
authoritative sections, restarted containers shown after save); Dashboard
(window picker, 30 s auto-refresh, "metrics unavailable" notice).

## Supply-chain note (Constitution VI)
New third-party dependency: `github.com/miekg/dns` (DNS presentation-format
parsing for record validation — BSD-3, the standard Go DNS library used by
CoreDNS; its v1 line is in maintenance with the successor at
`codeberg.org/miekg/dns`; the implementation picks the maintained line and pins
it). Promoted from indirect: `golang.org/x/net` (publicsuffix; already pinned at
v0.58.0 in the framework's `go.sum`). No PowerDNS, Docker or Prometheus SDKs —
stdlib `net/http` only. Intra-repo: ipamclient, secrets (from ticket), and lcm
gains a dependency on `services/dns/pkg/dnsclient` (module `replace ../dns`).
Container images `powerdns/pdns-auth-49` and `powerdns/pdns-recursor-51`
(official PowerDNS images; verify the tags and pin by digest). `go.sum`
committed; `govulncheck` in CI.

## STRIDE summary
- **Spoofing**: forged IPAM events → treated as triggers, verified against IPAM
  over mTLS (D8); a non-lcm module calling challenge ops → policy + handler
  SPIFFE check (D12); browser callers → gateway platform token.
- **Tampering**: record content injecting zone-file syntax → parser +
  canonical re-serialisation (D5); config values injecting settings → typed
  validation + quoting renderer (D11); cross-tenant record writes → RLS +
  ownership check + stored `pdns_id` (D1); reverse PTR into another tenant's
  zone → overlap function, skip (D9).
- **Repudiation**: append-only audit of every change, restart, sync and
  challenge with actor and outcome (D16).
- **Information disclosure**: API keys → references, redaction, never in
  errors (D3, D14); zone existence of other tenants → only "duplicate" is
  revealed; arbitrary PromQL reconnaissance → curated panels (D13).
- **Denial of service**: zone pre-emption by supermasters → platform-admin only
  (D15); oversized PowerDNS/Prometheus responses → caps; resolver opened to
  the internet → refused without explicit flag (D11); runaway sync loops →
  idempotent upserts, bounded stream reads; stale challenge TXT → sweeper (D12).
- **Elevation of privilege**: Docker socket → enum-selected fixed names,
  restart-only client, platform-admin, disabled by default, accepted residual
  risk (D11); configuration → `config:manage` + platform-admin; supermasters →
  platform-admin; slave-zone masters/supermaster IPs as SSRF → IP-literal,
  non-loopback/link-local/unspecified guard (D4/D15).
