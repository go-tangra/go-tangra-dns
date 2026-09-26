# DNS service — deployment notes

The **dns** service is the tenant-scoped **PowerDNS management plane** of the
Freya platform (go-tangra-dns replica): zones and record sets on one shared
PowerDNS Authoritative server with global zone-name ownership, a PowerDNS
Recursor that forwards every managed zone to the authoritative server, zone
templates, supermasters, BIND export and NOTIFY, **IPAM sync** (addresses become
A/AAAA + PTR records), the **Freya DNS** ACME DNS-01 provider used by lcm,
platform-admin **server configuration** (rendered include files + container
restart), a curated metrics **dashboard**, live updates and tenant backup.

Module id `dns`; browser API under `/api/dns/v1` (gateway-proxied, platform
token); module gRPC surface `dns.v1` (`Zones` read-only for any module,
`Challenges` for lcm only) on the SPIFFE mTLS mesh (not proxied, see
`pkg/dnsclient`).

## Server operations

| Item | Value |
|---|---|
| Binary | `dnssvc -config deploy/container.yaml` (applies migrations, then serves) |
| Listeners | gRPC `server.grpc_addr` (:9965), HTTP `server.http_addr` (:9966) — mesh, mTLS; admin `admin.addr` (:9850, `/healthz`, `/readyz`) |
| Store | TimescaleDB, database `dns`, app role `dns_app` (NOBYPASSRLS); `db.migrate_dsn` for the migration role |
| Event bus | Valkey user `dns` (Streams `platform:events:<tenant>`: publishes `dns.*`, consumes `ipam.ip_address.*`) |
| KEK | 32-byte key (`kek.source: file|env`, `deploy/kek.dev` for development only) |
| PowerDNS | `pdns.api_url` (Authoritative 4.9 API) + `recursor.api_url` (Recursor 5.x API), keys by reference |
| Mesh identity | enrolls with lcm through the gateway edge (`mesh_enroll`), stores its SVID in `/state` |
| Gateway | registers its manifest (routes, permissions, abilities, nav) on a lease; registers the module roles `administrator` / `viewer` (DNS administrator/viewer) and built-in grants with auth |

Every `dns_*` table carries `tenant_id` under **row-level security**. The only
cross-tenant reads are `dns_zone_conflict(name, tenant)` (SECURITY DEFINER,
boolean only — the owner is never revealed) and `dns_zone_names()` (names only,
for the recursor reconciler). PowerDNS itself has no tenants: every call on an
existing zone first loads the zone under the caller's tenant and then uses the
stored PowerDNS zone id — never a caller-supplied name.

Policy (`deploy/policy.yaml`): the gateway forwards HTTP operations only; lcm may
call `dns.v1.Challenges/{Present,CleanUp}` (the handler re-checks the exact peer
SPIFFE ID `acme.allowed_caller` as well); any module may call
`dns.v1.Zones/{List,Get,FindForName}` and the gRPC health check. dns itself needs
`ipam` to allow `svc/dns` on `IpAddressService/{Get,Find}` + `SubnetService/Get`
(rule `dns-ipam-sync` in `services/ipam/deploy/policy.yaml`) and auth's generic
`svc/*` rules (keys, sessions, authorization checks, permission registration).

## PowerDNS + Recursor setup

The dev stack (`deploy/stack/compose.yaml`) runs:

| Service | Image (pinned by digest) | Notes |
|---|---|---|
| `pdns-auth` (`freya-pdns-auth`) | `powerdns/pdns-auth-49` (4.9.x) | gsqlite3 backend on `pdns-auth-data`; base config `deploy/pdns/pdns.conf` (`primary=yes` for NOTIFY); include dir = `pdns-auth-conf` volume; DNS on host `127.0.0.1:5300` udp+tcp |
| `pdns-recursor` (`freya-pdns-recursor`) | `powerdns/pdns-recursor-53` (5.3.x) | YAML config `deploy/pdns/recursor.yml`; include dir = `pdns-recursor-conf`; API-managed forward zones persisted in `pdns-recursor-api` (`webservice.api_dir`); DNS on host `127.0.0.1:5301` udp+tcp |

The Recursor 5.1 line was replaced by 5.3 because 5.1.10 reports a mandatory
security update through PowerDNS's secpoll. Host port 53 belongs to
systemd-resolved and 5353/udp to mDNS on typical workstations, hence 5300/5301
bound to loopback only.

Both HTTP APIs (auth :8081, recursor :8082) listen on the **internal compose
network only** — never published — with `webserver-allow-from` / `allow_from`
limited to loopback and private ranges. Each include directory holds:

- `00-api.conf` / `00-api.yml` — written by the one-shot `dns-secrets-init`
  from the API keys (mode 0600, owned by the PowerDNS user);
- `50-freya.conf` / `50-freya.yml` — rendered by dns from the saved
  Configuration (`managed_files.auth_path` / `managed_files.recursor_path`),
  "Managed by Freya DNS — do not edit by hand". Files are written atomically
  (temp + rename, 0644) and only when their content hash changes; include files
  load in name order, so the managed file overrides the base config.

Forwarding: for every managed zone the reconciler (start-up + every
`recursor.reconcile_interval_seconds`) keeps a recursor forward zone pointing at
`pdns.auth_forward_host:auth_forward_port` (resolved to an IP), removes forwards
for zones no longer managed (except `recursor.static_forwards`), and reports
PowerDNS zones no tenant owns (never adopted).

```
dig @127.0.0.1 -p 5300 example.test SOA      # authoritative
dig @127.0.0.1 -p 5301 www.example.test A    # through the resolver
```

## API keys (secret references) and the warden gap

Configuration carries references only: `pdns.api_key_ref`,
`recursor.api_key_ref`. Production: `warden:<secret-id>` resolved through warden
with `secrets.token_file`, cached and refreshed every `secrets.refresh_seconds`
(rotation needs no restart). **Known platform gap** (shared with ticket T069):
warden's `Secrets/GetPassword` authorises only a *user* platform token and
modules have no long-lived service-principal token, so a warden reference cannot
be resolved unattended today. The dev stack therefore uses `file:` references
(`file:/secrets/pdns-auth.key`, `file:/secrets/pdns-recursor.key`) generated once
by `dns-secrets-init` into the `dns-secrets` volume; `file:` refs are refused in
production (`env: production`) and warned about otherwise. Rotate in dev by
removing the `dns-secrets` volume and re-running `dns-secrets-init`,
`pdns-auth`, `pdns-recursor` and `dns`.

Keys are never logged, audited, published, exported or returned (PowerDNS error
bodies are sanitised; the redaction test `tests/security` and
`scripts/redaction-scan.sh` enforce it).

## Docker socket (configuration restarts) — risk acceptance

A configuration save that changes a rendered file restarts **only** the
container whose file changed. The restarter is a minimal client on the Docker
unix socket implementing only `GET /_ping` and `POST /containers/{name}/restart`,
where `{name}` is one of the two names fixed in config
(`docker.auth_container`, `docker.recursor_container`) selected by an enum — no
API field carries a container name. It is **disabled unless
`docker.enabled: true`**; when disabled a save renders the files and reports
`restart_required`.

The dev stack enables it and mounts `/var/run/docker.sock` **read-write** (a
`:ro` socket bind does not restrict the API) with `group_add: ["${DOCKER_GID}"]`
(`deploy/stack/up.sh` exports the socket's GID; the stack runs modules as root
for the shared token volume, so the group matters once the service runs as its
image's non-root user). **The socket is root-equivalent on the host**: whoever
compromises the dns container can drive the whole Docker API. This was accepted
by the requester for development. For production either

- place an API-filtering socket proxy (e.g. `tecnativa/docker-socket-proxy` or
  an nginx/haproxy allow-list) in front of the daemon that allows **only**
  `GET /_ping` and `POST /containers/{freya-pdns-auth,freya-pdns-recursor}/restart`,
  and point `docker.socket` at the proxy's socket, or
- keep `docker.enabled: false` and apply `restart_required` changes out of band.

## IPAM sync

With `ipam_sync.enabled`, dns consumes `ipam.ip_address.{created,updated,scanned,deleted}`
events of the tenants in `ipam_sync.tenants` (default: the enrolment tenant)
from `platform:events:<tenant>`. Events are **hints only**: each one is verified
by re-reading the address (and its subnet prefix) from ipam over mTLS before
anything is written, so a forged event can at most make dns write IPAM's real
state. Forward records go to the tenant's longest matching zone (auto-created,
never at a public suffix); PTRs go to the subnet-sized reverse zone
(`in-addr.arpa` for IPv4, nibble `ip6.arpa` for IPv6). A reverse zone owned by
another tenant is skipped and logged. TTL `ipam_sync.default_ttl`.

## ACME — the Freya DNS provider (lcm)

lcm's ACME issuers can pick the DNS provider **Freya DNS** (`freya-dns`, no
credential fields). lcm calls `dns.v1.Challenges/Present|CleanUp` over mTLS for
the issuer's tenant: `fqdn` must be `_acme-challenge.<domain without *.>`
inside one of the tenant's zones; only that TXT value is added/removed (other
values untouched), a CNAME at the name refuses, and a sweeper removes values
whose CleanUp never arrived after `acme.max_age_seconds`. lcm needs discovery
`dns: ["dns:9965"]` and `dns: { service: dns }` (see
`deploy/stack/configs/lcm.yaml`). The stack's Pebble runs with
`PEBBLE_VA_ALWAYS_VALID=1`; the real DNS-01 path (Pebble VA → recursor →
pdns-auth) is exercised by `services/lcm/tests/integration/acme_freyadns_test.go`.

## Dashboard / Prometheus

`metrics.prometheus_url` points at a Prometheus that scrapes both PowerDNS
webservers' `/metrics`. The stack ships an optional profile:

```
docker compose -p freya-stack --profile metrics up -d prometheus
```

Only the fixed panel catalogue runs server-side (no PromQL is accepted from the
browser). Without a reachable Prometheus the dashboard answers
`{available: false}` and the UI shows "metrics unavailable".

## Backup

`POST /backup/export` returns the tenant's zone metadata (with each zone's BIND
text for reference), templates and supermaster rows — schema-versioned, never
API keys, PowerDNS zone ids or the server configuration.
`POST /backup/import` (`mode: skip|overwrite`): zones are **re-linked, never
re-created or deleted** — only when present on PowerDNS, not owned or
overlapped by another tenant and not accounted to a foreign tenant in PowerDNS;
missing ones are listed in `missing_in_pdns`. Templates are upserted.
Supermasters (server-wide trust) are restored only for a platform admin.
Another tenant or `full: true` (wipe the target's templates first) requires a
platform admin; a cross-tenant restore mints fresh ids.

## Security review (T105)

Reviewed `services/dns` and the lcm Freya DNS provider against the research
STRIDE list. Findings and dispositions:

| Threat (research STRIDE) | Result |
|---|---|
| Tenant overlap / shadowing | OK — global unique index + RLS + `dns_zone_conflict()` (boolean only) checked before every PowerDNS create; all later calls use the stored PowerDNS id of a zone loaded under the caller's tenant. Backup import re-links only zones on PowerDNS that no other tenant owns/overlaps and whose PowerDNS account is not foreign. |
| Forged IPAM events | OK — events are hints; the address (and subnet) is re-read from ipam over mTLS and must match the event id before anything is written. Live-verified: a forged `ipam.ip_address.created` XADDed to the platform tenant's stream wrote nothing. |
| Docker socket | OK in code (enum → one of two configured names, regex-validated, path-escaped, only `/_ping` + `POST …/restart`, disabled by default). **Finding (LOW, documented):** the dev stack runs dns as root (`user: "0:0"`, like every stack module, because the shared token/state volumes are root-owned), so the "non-root user in the socket group" control of D11 does not apply in dev; the socket is root-equivalent either way (accepted risk). Production: socket proxy or `docker.enabled: false`. |
| Config injection | OK — typed model validated with `netip`; the renderer quotes every scalar through allow-list regexes; no free text reaches the files. |
| Challenge caller restriction | OK — policy allows only `svc/lcm` on `dns.v1.Challenges` and the handler re-checks the exact peer SPIFFE ID; fqdn/value grammar, CNAME refusal, tenant's own zones only. |
| PromQL restriction | OK — only the fixed catalogue runs; no query text is accepted. |
| Key redaction | OK — keys by reference only, PowerDNS error bodies sanitised (incl. truncated fragments); `tests/security/redaction_test.go` drives every path with sentinel keys and hostile PowerDNS replies; `scripts/redaction-scan.sh` scans captured output (0 matches). |
| HTTP authz | OK — every protected route requires the platform token and its OpenAPI `x-freya-permission`; configuration, supermaster create/delete and cross-tenant/full backup additionally require platform-admin; bodies bounded. |
| SSRF (masters/supermasters/upstreams) | **Finding (LOW, fixed):** recursor upstream resolvers accepted loopback/link-local addresses (platform-admin only field). Now guarded like masters (`internal/dnsconf/model.go`, tests added). |

Bugs found while wiring the real servers (fixed, covered by tests):
PowerDNS 4.9 serves supermasters at `/autoprimaries` (the client used
`/supermasters` → 404); record comments without `account` were refused (422);
the zone export arrived JSON-wrapped (`{"zone": …}`) because of the client's
Accept header and is now unwrapped.

## Metrics

Prometheus metrics on the admin listener: PowerDNS/recursor call latency and
errors, zones/records written, IPAM sync outcomes, recursor reconcile results,
unowned PowerDNS zones, challenge present/cleanup/sweep counts, config renders
and restarts.
