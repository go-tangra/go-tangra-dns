# Implementation Plan: DNS Service

**Branch**: `015-dns-service` | **Date**: 2026-09-23 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/015-dns-service/spec.md`

## Summary

A tenant-scoped DNS management plane replicating go-tangra-dns: tenants manage
zones (native/master/slave/producer/consumer, DNSSEC flag), record sets (15
editable types + read-only SOA), zone templates with `[ZONE]` expansion and
supermasters on a **shared PowerDNS Authoritative** server through its HTTP API;
zones export as BIND text and master zones can be NOTIFYed; the **PowerDNS
Recursor** is kept forwarding every managed zone to the authoritative server; a
platform administrator edits the server configuration, which is validated,
rendered to include-dir files and applied by restarting only the affected DNS
container over the Docker socket (restricted to the two configured names); a
curated dashboard proxies a fixed PromQL panel set; IPAM address events keep
A/AAAA + PTR records in sync. Freya adaptations: SPIFFE mTLS + gateway platform
token; TimescaleDB + RLS; PowerDNS API keys via secret references; IPAM events
from the platform event bus, **verified against IPAM over the mesh** before they
are applied. Enhancements over the source: enforced permissions, globally unique
and non-overlapping zone names across tenants, per-type record validation before
PowerDNS, record search, IPv6 sync with subnet-sized reverse zones and a
public-suffix-aware parent zone, curated dashboard, published events, audited
history, and a **Freya DNS ACME DNS-01 provider** in the certificate service
(lcm) that calls a lcm-only `dns.v1.Challenges` gRPC surface.

## Technical Context

**Language/Version**: Go 1.26 (as every Freya service); UI TypeScript/Vue 3.

**Primary Dependencies**: the Freya framework (`github.com/go-freya/freya`:
SPIFFE mTLS gRPC, OpenAPI-validated HTTP edge, identity, audit, sealed envelopes,
gateway registration, observe metrics); `pgx` + TimescaleDB; Valkey (platform
event bus, read via the stream client as services/deployer does);
`golang.org/x/net/publicsuffix` (already in the framework's `go.sum` as an
indirect `golang.org/x/net v0.58.0` — promoted to a direct requirement, no new
module); **new**: `github.com/miekg/dns` (presentation-format RR parsing for
record validation, research D5); stdlib `net/http` clients for the PowerDNS
Authoritative API, the Recursor API, the Docker Engine socket and the Prometheus
HTTP API (no vendor SDKs); intra-repo `services/ipam/pkg/ipamclient` (event
verification + subnet lookup) and the ticket-style `secrets` package (API-key
references). UI: the shared `@freya/ui` kit (FlyonUI/Tailwind/Zod) as a
Module-Federation remote. lcm gains `services/dns/pkg/dnsclient` for its Freya
DNS provider.

**Storage**: TimescaleDB with per-tenant RLS on `dns_zones`,
`dns_zone_templates`, `dns_supermasters`, `dns_ipam_sync`, `dns_acme_challenges`;
a platform-scoped single-row `dns_server_config` reachable only through the
platform-admin path; `dns_audit_events` hypertable. Record sets live only in
PowerDNS. Global zone-name uniqueness and cross-tenant overlap checks are
enforced by a unique index plus a narrow security-definer function
(data-model.md).

**External systems**: PowerDNS Authoritative 4.9 (`powerdns/pdns-auth-49`) and
Recursor 5.1 (`powerdns/pdns-recursor-51`) — tags to be verified and pinned by
digest at implementation; both HTTP APIs on the internal network only. Docker
Engine API over `/var/run/docker.sock` (restart two named containers). Optional
Prometheus-compatible query endpoint.

**Testing**: Go `testing` with the `testrt` runtime and a `memstore` fake; the
PowerDNS auth client, recursor client, Docker restarter, metrics client, IPAM
client and secret source are interfaces with fakes (plus `httptest` servers that
mimic the PowerDNS/Docker/Prometheus wire formats for the real clients), so
zones, records, templates, sync, challenges, configuration and dashboard are
unit-tested offline; fuzz tests for zone/record name canonicalisation, per-type
content validation, template expansion, reverse-name computation, config
rendering and IPAM event decoding; contract tests over OpenAPI + proto;
integration suite (testcontainers: TimescaleDB, Valkey, pdns-auth, pdns-recursor)
behind `//go:build integration`. Coverage gate ≥ 80 % overall, 100 % on
`authz`, `sealed` and `validate` (names/content). UI: vitest unit tests +
Playwright e2e/axe.

**Target Platform**: Linux container in `deploy/stack` behind the gateway, next
to new `pdns-auth` and `pdns-recursor` containers sharing managed-config volumes;
calls ipam over the mesh; is called by lcm over the mesh; mounts the Docker
socket (dev stack) for the two allowed restarts.

**Project Type**: Web service (Go backend + gRPC + OpenAPI HTTP) managing
external DNS servers, with an event consumer, background reconcilers and a
Module-Federation UI; plus a small provider addition in services/lcm.

**Performance Goals**: zone + record resolvable through the resolver < 1 min
(SC-001; forward entry pushed synchronously on zone create); IPAM change
reflected < 10 s (SC-003; stream read block 2 s + IPAM verify + 2 PATCHes);
5,000-record-set zones list/search/export < 3 s (SC-008; single PowerDNS GET,
in-module filter/page, export streamed).

**Constraints**: per-tenant RLS; zone ownership verified before every PowerDNS
call; global non-overlapping zone names; no free text reaches PowerDNS or the
rendered config files unvalidated; API keys never returned/logged/audited/
published; configuration + restarts platform-admin only and only the two
configured containers; challenge ops lcm identity only and `_acme-challenge`
TXT only; dashboard fixed panel set with bounded windows/steps; IPAM events are
triggers that are verified against IPAM before any write.

**Scale/Scope**: thousands of zones platform-wide, 5,000 record sets per zone;
six prioritized user stories (zones/records, IPAM sync, templates/supermasters/
export/NOTIFY, ACME DNS-01, server configuration, dashboard); ports gRPC 9965,
HTTP 9966, admin 9850 (no conflict with deploy/stack/configs/*.yaml).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Secure by Default**: refuses to start without KEK, PowerDNS endpoint and
  API-key references; the Docker restarter is **off unless explicitly enabled**
  with an allow-list of exactly the auth/recursor container names; an
  open-resolver `allowed_networks` (0.0.0.0/0, ::/0) is refused unless an
  explicit `allow_open_resolver` flag is set (warned); `file:` secret references
  and plaintext PowerDNS API URLs are dev-only opt-outs that log warnings; the
  dashboard is disabled without a configured metrics URL. PASS.
- **II. Zero Trust Service Communication**: browser via the gateway platform
  token with per-route permissions; mesh calls SPIFFE mTLS (ipam, auth, lcm →
  dns); `dns.v1.Challenges` allowed by policy **and** re-checked in the handler
  against the lcm SPIFFE ID; IPAM events are not trusted by origin — each is
  re-verified with ipam over mTLS before acting (research D8). The PowerDNS and
  Docker APIs are not mesh peers: they are reached on the internal network /
  local socket with API keys, documented as accepted exceptions (research D3,
  D11). PASS (with the justified exceptions in Complexity Tracking).
- **III. Boundary Validation & Defense in Depth**: OpenAPI + proto validation at
  the edge; module-level name/content validation (miekg/dns parse + semantic
  rules) before PowerDNS; PowerDNS responses bounded and decoded into typed
  structs; config values typed and validated, rendered by a quoting writer;
  gateway permission + module authz + RLS + ownership check on every zone
  operation; request/body/page limits; SSRF guard on slave-zone masters and
  supermaster IPs. PASS.
- **IV. Test-First with Security Verification (NON-NEGOTIABLE)**: contract/unit/
  integration tests precede implementation; external systems behind fakes;
  negative tests for cross-tenant zone access/overlap, forged IPAM events,
  non-lcm challenge callers, non-admin config/restart, container-name
  injection, arbitrary PromQL, API-key leakage; fuzz tests for every parser
  (names, record content, templates, reverse names, config rendering, event
  payloads). PASS.
- **V. Observability & Auditability**: append-only audit for every zone, record,
  template, supermaster, configuration, restart, sync and challenge change;
  Prometheus metrics (PowerDNS call latency/errors, sync outcomes, reconciler
  runs, restarts, challenges) on the admin listener; health/readiness separate;
  API keys redacted by construction (never in structs that are logged). PASS.
- **VI. Supply Chain Integrity & Minimal Dependencies**: one new dependency
  (`github.com/miekg/dns`) justified in research; `x/net/publicsuffix` already
  pinned; all external APIs via stdlib `net/http`; PowerDNS images pinned by
  digest; `go.sum` committed; `govulncheck` in CI. PASS.
- **VII. Simplicity & Explicit Configuration**: explicit wiring; PowerDNS auth,
  recursor, Docker, metrics and IPAM are small interfaces with fakes; container
  names, paths, URLs and reconcile interval are typed config validated at start
  (the source read them from environment variables at call sites); the curated
  panel set replaces the source's free-form query proxy. PASS.

No unjustified Constitution violations. Security Requirements SR-001..007 map to
research decisions D1–D17 and to test tasks. Post-design re-check: PASS — the
design adds no trust boundary beyond those listed in the spec; the Docker socket
and non-mTLS PowerDNS APIs are recorded in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```
specs/015-dns-service/
├── plan.md              # This file
├── research.md          # Phase 0 output (D1–D17, supply chain, STRIDE)
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (HTTP, gRPC, events, interfaces)
└── tasks.md             # Phase 2 output (/speckit-tasks)
```

### Source Code (repository root)

```
services/dns/
├── go.mod                       # module github.com/go-freya/freya/services/dns
├── cmd/dnssvc/                  # run + bootstrap/migrate
├── api/
│   ├── openapi/dns.yaml         # browser routes (x-freya-permission / x-freya-public)
│   └── proto/dns/v1/            # gRPC: Challenges (lcm only), Zones (read, modules)
├── internal/
│   ├── app/                     # wiring (freya.New, stores, pdns, recursor, docker, metrics, ipam, consumer, reconcilers, gateway reg)
│   ├── config/                  # db/valkey/kek/pdns/recursor/docker/managed_files/metrics/ipam_sync/acme/limits/gateway
│   ├── store/ + repo/ + repodb/ # migrations (RLS, global unique + overlap function, audit hypertable), models, SQL
│   ├── memstore/                # in-memory repo fake
│   ├── sealed/ authz/ audit/    # envelopes, permission + platform-admin + caller-identity checks, audit vocabulary
│   ├── secrets/                 # API-key references (warden | file:) + fake (adapted from services/ticket)
│   ├── validate/                # zone/record names, per-type content (miekg/dns + semantics), masters/IP guards
│   ├── pdns/                    # PowerDNS Authoritative HTTP client (+ fake)
│   ├── recursor/                # Recursor forward-zone client + reconciler (+ fake)
│   ├── zones/ records/          # domain services (ownership, compensation, events, audit)
│   ├── templates/ supermasters/ # domain services
│   ├── dnsconf/                 # config model, defaults, validation, renderers, file writer, docker restarter (+ fake)
│   ├── ipamsync/                # event consumer, IPAM verification, forward/reverse planning, sync state
│   ├── acmechallenge/           # Present/CleanUp on _acme-challenge TXT + stale sweeper
│   ├── dashboard/               # curated panel catalogue + Prometheus query client (+ fake)
│   ├── backup/                  # export/import
│   ├── events/ stream/          # platform event publisher + SSE relay
│   ├── metrics/                 # Prometheus collectors
│   └── httpapi/ grpcapi/        # gateway HTTP + mesh gRPC surfaces
├── pkg/
│   ├── dnsmanifest/             # gateway manifest (routes/permissions/abilities/nav) + SeedPermissions/roles
│   └── dnsclient/               # typed module client (Challenges, Zones) — used by lcm
├── testdata/                    # PowerDNS API response fixtures, IPAM event payloads
├── ui/                          # @freya/ui MF remote: zones (list + drawer), records, templates, supermasters, configuration, dashboard
├── deploy/                      # policy.yaml, kek.dev, pdns/ (base auth + recursor configs), README
├── Dockerfile Makefile buf.yaml buf.gen.yaml scripts/coverage-gate.sh
services/lcm/internal/acme/      # + freyadns.go (Freya DNS provider), registry entry, ProviderDeps
services/ipam/deploy/policy.yaml # + dns → ipam.v1 SubnetService/Get, IpAddressService/Get|Find
deploy/stack/                    # pdns-auth, pdns-recursor, dns-secrets-init, dns-token, dns service (docker socket),
                                 # init-db role/DB, Valkey user, configs/dns.yaml, gateway allow-list, lcm discovery,
                                 # optional `metrics` profile (Prometheus scraping PowerDNS)
```

**Structure Decision**: mirrors services/ticket and services/asset (module layout,
store + RLS, memstore, authz, audit, events/stream, manifest, contract tests,
coverage gate) and services/deployer's platform-event consumer and module
client, with the DNS-specific packages — `pdns`, `recursor`, `validate`,
`dnsconf`, `ipamsync`, `acmechallenge`, `dashboard` — each behind small
interfaces with fakes for offline tests. The lcm change is additive (one new
provider behind the existing `DNSProvider` interface).

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| Docker Engine socket mounted into the dns container (root-equivalent on the host) | Requester decision: keep the reference's apply-by-restart for server configuration (FR-010) | A socket proxy or an external operator step was offered; the requester chose the socket. Mitigations: disabled by default, platform-admin only, a restarter that can only `POST /containers/{name}/restart` for two names fixed in config (never from a request), audit of every restart; production guidance recommends an API-filtering socket proxy (research D11). |
| PowerDNS Authoritative/Recursor HTTP APIs are not mTLS mesh peers | PowerDNS supports only API-key auth on its webserver | No mTLS option upstream; compensated by internal-network-only exposure, `webserver-allow-from` restricted to the dns container network, API keys from secret references, and never exposing the APIs on the host (research D3). |
| One new dependency (`github.com/miekg/dns`) | Correct presentation-format parsing for 15 record types (FR-004, SC-002) | Hand-written per-type parsers would be larger, less correct and still need fuzzing; rationale in research D5. |
| Background workers (IPAM consumer, recursor reconciler, challenge sweeper, config re-apply) | FR-008, FR-009, FR-010, SC-005 | Request-driven only would leave drift after restarts and stale challenge TXT values; each worker is a small loop with injected clock and fakes. |
