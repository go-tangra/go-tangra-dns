# Tasks: DNS Service

**Feature**: 015-dns-service | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

Organized by phase; user-story phases are independently testable. Tests are
MANDATORY and precede implementation (Constitution IV). `[P]` = parallelizable
(different files, no dependency on an incomplete task). Module path:
`github.com/go-freya/freya/services/dns`. Mirror services/ticket and
services/asset (module layout, config, store + RLS, memstore, repodb, authz with
per-route permissions, audit, events/stream, manifest + SeedPermissions,
contract tests, coverage gate, stack wiring), services/deployer (platform event
consumer + module gRPC client) and services/ticket/internal/secrets (secret
references; dev `file:` references — see research D14 and ticket T069). The UI
is an `@freya/ui` Module-Federation remote mirroring services/ticket/ui and
services/ipam/ui (drawers not dialogs, `breakpointSpecificity`, no inline
styles). Reference implementation for behaviour:
/home/jadmin/projects/go-tangra/go-tangra-dns (internal/pdns, internal/recursor,
internal/dnsconf, internal/event, internal/service, protos, frontend/src).
Cross-module touches: services/lcm (Freya DNS provider), services/ipam
(ipamclient.GetAddress + policy rule).

## Phase 1: Setup (Shared Infrastructure)

- [X] T001 Create the module skeleton `services/dns/` per plan.md: cmd/dnssvc, api/{openapi,proto/dns/v1}, internal/{app,config,store,repo,memstore,sealed,authz,audit,secrets,validate,pdns,recursor,zones,records,templates,supermasters,dnsconf,ipamsync,acmechallenge,dashboard,backup,events,stream,metrics,httpapi,grpcapi}, pkg/{dnsmanifest,dnsclient}, testdata, ui, deploy/pdns, scripts.
- [X] T002 Add `services/dns/go.mod` (module .../services/dns, Go 1.26) with replaces for ../.. ../auth ../gateway ../lcm ../warden ../ipam; require github.com/miekg/dns (research D5) and golang.org/x/net (publicsuffix, direct); seed go.sum from services/ticket and `go mod tidy`.
- [X] T003 [P] Add `services/dns/buf.yaml`, `buf.gen.yaml` and `services/dns/api/proto/dns/v1/dns.proto` (Challenges: Present/CleanUp; Zones: List/Get/FindForName per contracts §B) + Makefile `generate` target (mirror services/ticket).
- [X] T004 [P] Add `services/dns/Dockerfile` (build UI via the workspace listing every UI workspace, embed with -tags ui, build dnssvc, non-root user 10001), `services/dns/Makefile` (test/cover/vuln/lint/generate/build/image) and `services/dns/scripts/coverage-gate.sh` (≥ 80 % overall, 100 % authz/sealed/validate) mirroring services/ticket.
- [X] T005 [P] Scaffold `services/dns/ui/` from services/ticket/ui: package.json (name freya-dns-ui, @freya/ui, zod), vite.config.ts (base /m/dns/, tailwindcss + breakpointSpecificity + federation), module-federation.config.ts (remote `dns`, host-only @freya/ui singletons), src/{main.ts,main.css,dev.css,api/client.ts (BASE /api/dns/v1),remote/{routes.ts,nav.ts}}, eslint/tsconfig, playwright.config.ts, tests/unit/setup.ts, embed.go/embed_stub.go.
- [X] T006 [P] Build fixtures under `services/dns/testdata/`: pdns/ (zone GET with rrsets incl. SOA, zone list, 404/409/422 error bodies, export text, supermaster list, recursor zone list; generator helper for a 5,000-rrset zone), ipam/ (event payloads for created/updated/deleted/scanned, malformed and oversized payloads), records/ (valid + invalid content corpus per type used as table and fuzz seeds), docker/ (restart 204/404 responses).
- [X] T007 [P] Register the new UI workspace in every existing image: add `COPY services/dns/ui/package.json services/dns/ui/` to `services/{asset,auth,deployer,gateway,inventory,ipam,lcm,notification,paperless,ticket,warden}/Dockerfile` (where they install the workspace) and refresh the root `package-lock.json` with `npm install`.

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T008 Typed, validated config `services/dns/internal/config/config.go` (+ `config_test.go`): sections db, valkey, kek, pdns (api_url, server_id, api_key_ref, timeout, max_response_bytes, auth_forward_host/port), recursor (api_url, api_key_ref, reconcile_interval, static_forwards), docker (enabled, socket, auth_container, recursor_container), managed_files (recursor_path, auth_path), metrics (prometheus_url optional, timeout), ipam_sync (enabled, tenants, ipam service, default_ttl), acme (allowed_caller, max_age), records (min/max ttl, max values, page limits), events, gateway, mesh_enroll, secrets, limits_dns; Default/Load/Validate (refuse start without KEK, pdns api_url + api_key_ref; container names validated against `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)/Warnings (file: refs, plaintext API URLs, docker enabled).
- [X] T009 Store migrations `services/dns/internal/store/migrations/`: 0001_schema.sql (dns_zones with GLOBAL unique name + pdns_id, dns_zone_templates, dns_supermasters with global unique (ip, nameserver), dns_server_config single row, dns_ipam_sync, dns_acme_challenges per data-model.md with all indexes), 0002_audit.sql (dns_audit_events hypertable), 0003_rls.sql (per-tenant RLS on every tenant table + dns_app grants + security-definer `dns_zone_conflict(name, tenant)` boolean and `dns_zone_names()`).
- [X] T010 Store models + repository interface `services/dns/internal/store/models.go` and `services/dns/internal/repo/repo.go`: zones (create/get/get-by-name/list with query/kind/origin + paging + total, update, delete, ZoneConflict, AllZoneNames, ZonesForTenant for longest-suffix matching), templates (CRUD), supermasters (create/list/get/delete), server config (get/save hashes), ipam sync (get/upsert/delete by address id), acme challenges (insert/delete/list older than), backup iteration, audit append.
- [X] T011 [P] In-memory repository `services/dns/internal/memstore/memstore.go` implementing repo.Store (global name/pdns_id/supermaster uniqueness across tenants, overlap conflict semantics identical to the SQL function, paging, FailNext) for offline tests.
- [X] T012 [P] `services/dns/internal/sealed/` envelope seal/open + redaction helpers (copy services/ticket/internal/sealed, module path updated) + `sealed_test.go` (100 %).
- [X] T013 [P] `services/dns/internal/authz/` Subjects{TenantID,UserID,Roles,ActorKind (user|module|ipam-sync|system),PeerSPIFFE} + permission constants (zones:read, zones:manage, templates:manage, supermasters:manage, dashboard:read, backup:manage, config:manage) + Require helpers + strict IsPlatformAdmin (platform-admin role or system scope only, as ticket) + `CallerIs(spiffeID)` for module callers + `SystemFor(tenant)` for the sync worker + `authz_test.go` (100 %, incl. tenant admin/owner NOT platform admin, forged peer IDs).
- [X] T014 [P] `services/dns/internal/audit/` writer adapter with the action vocabulary (zone.create/update/delete/export/notify, record.upsert/delete, template.*, supermaster.*, config.update/apply/restart, sync.upsert/delete/skip, challenge.present/cleanup/refused/swept, backup.*) + redaction of api_key/password/token fields and record values + `audit_test.go`.
- [X] T015 [P] `services/dns/internal/secrets/` — Source {PDNSAPIKey, RecursorAPIKey} over `warden:` / dev `file:` references with refresh (adapt services/ticket/internal/secrets) + Fake + test (values never in errors or logs).
- [X] T016 [P] Tests first for names `services/dns/internal/validate/names_test.go` + `services/dns/internal/validate/names_fuzz_test.go`: zone canonicalisation (case, trailing dot, empty/long labels, total length, root, IDNA U-labels refused), public suffix refusal (`com`, `co.uk`) with reverse-zone exception, record name qualification (`@`, relative, absolute, outside zone, wildcard position), masters/supermaster IP guard (loopback, link-local, unspecified, multicast, ports); fuzz: never panics, output always canonical and inside the zone.
- [X] T017 `services/dns/internal/validate/names.go` — ZoneName, RecordName, Masters, IPGuard using golang.org/x/net/publicsuffix (makes T016 pass; 100 % coverage).
- [X] T018 [P] Tests first for the PowerDNS client `services/dns/internal/pdns/client_test.go` against an httptest server replaying `testdata/pdns`: every method's method/path/body, `X-API-Key` header from the secret source per call, zone id path escaping, 404 → ErrNotFound, 409/422 → ErrConflict, connection refused → ErrUnavailable, body caps, error text never contains the key, export as text.
- [X] T019 `services/dns/internal/pdns/client.go` + `types.go` + `fake.go` — typed client per contracts §D (port go-tangra-dns internal/pdns with the changes in research D3) and an in-memory Fake PowerDNS (zones, rrsets REPLACE/DELETE semantics, serial bump, supermasters, export rendering, failure injection).
- [X] T020 [P] Tests first for the recursor client `services/dns/internal/recursor/client_test.go`: forward create payload (`Forwarded`, IP:port servers, recursion_desired false), delete-then-create idempotency, 404/422 on remove = success, auth host resolution to IP, ListForwards, Ready, disabled client is a no-op, key never in errors.
- [X] T021 `services/dns/internal/recursor/client.go` + `fake.go` (port go-tangra-dns internal/recursor/client.go onto typed config + secrets).
- [X] T022 [P] `services/dns/internal/events/` publisher (dns.zone.created/updated/deleted, dns.record.changed → platform:events:<tenant>, ids/names only) + `services/dns/internal/stream/` SSE relay (copy services/ticket) + test asserting payloads never carry record values or keys.
- [X] T023 [P] `services/dns/internal/metrics/metrics.go` Prometheus collectors (pdns_calls_total{op,result}, pdns_call_seconds, recursor_sync_total{result}, ipam_sync_total{action,result}, config_restarts_total{target,result}, challenges_total{op,result}, unowned_pdns_zones) on the admin listener.
- [X] T024 `services/dns/api/openapi/dns.yaml` — every route from contracts §A with x-freya-permission (health x-freya-public), CSRF on mutations, body limits, schemas; embed.go; contract test `services/dns/tests/contract/openapi_test.go` (parses; every mounted route declared; config routes carry config:manage; no schema contains an api_key field).
- [X] T025 [P] `services/dns/pkg/dnsmanifest/manifest.go` — routes/permissions, roles (dns admin: all tenant permissions; dns viewer: zones:read + dashboard:read; config:manage granted to no tenant built-in role) via SeedPermissions, built-in grants, UI abilities, nav (Zones, Templates, Supermasters, Dashboard, Configuration) + `manifest_test.go`.
- [X] T026 App build/wire/run `services/dns/internal/app/app.go` — freya.New + mesh enroll, store/KEK, secrets, pdns + recursor clients, events/stream, metrics, gateway registration via dnsmanifest, mesh HTTP + gRPC surfaces, worker list (reconciler, IPAM consumer, sweeper, config re-apply added by later stories), admin health/readiness; refuses to start insecure.
- [X] T027 `services/dns/cmd/dnssvc/main.go` + bootstrap subcommand (config, migrate, run) with ui.Remote() wiring (the GUI-404 lesson from paperless).
- [X] T028 `services/dns/internal/repo/repodb/` implementing repo.Store over TimescaleDB + integration test `services/dns/internal/repo/repodb/repodb_integration_test.go` (`//go:build integration`, testcontainers): schema, RLS isolation between two tenants, global zone-name uniqueness across tenants under RLS, `dns_zone_conflict` equal/ancestor/descendant/same-tenant cases returning only a boolean, supermaster global pair uniqueness.

## Phase 3: User Story 1 — Manage zones and records (Priority: P1) 🎯 MVP

**Goal**: tenant-isolated zone and record-set management on the shared PowerDNS with per-type validation and resolver forwarding.
**Independent test**: create a zone, add/edit/delete record sets, query the authoritative server and the resolver, delete the zone (quickstart Scenario 1).

### Tests (write first, must fail)
- [X] T029 [P] [US1] Contract test `services/dns/tests/contract/zones_test.go` — create/get/list/update/delete shapes; query/kind filters + paging total; invalid name → invalid_name; duplicate across tenants and overlapping parent/child of another tenant's zone → duplicate (owner not revealed); tenant B gets 404 on tenant A's zone id; viewer 403 on every mutation.
- [X] T030 [P] [US1] Contract test `services/dns/tests/contract/records_test.go` — list with type filter/name search/paging, SOA read_only, create/replace/rename/delete shapes, invalid content → invalid_record with reason, zones:manage required.
- [X] T031 [P] [US1] Unit test `services/dns/internal/zones/zones_test.go` (fake pdns/recursor, memstore) — PowerDNS-first create with compensating delete when the local insert fails; zone present in PowerDNS but not locally → duplicate, never adopted; update re-PUTs previous metadata on local failure; delete tolerates PowerDNS 404 and still removes the local row; PowerDNS unavailable → pdns_unavailable with no local write; recursor forward synced on create/removed on delete (failure logged, not fatal); events + audit per mutation.
- [X] T032 [P] [US1] Table tests `services/dns/internal/validate/content_test.go` over `testdata/records` — every type A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA, DS, DNSKEY, TLSA, SSHFP, SPF, NAPTR valid/invalid cases per research D5; control characters, CR/LF and `$INCLUDE`/`$ORIGIN` refused; TXT auto-quoting and 255-octet splitting; canonical re-serialisation is what is returned; SOA refused; TTL bounds.
- [X] T033 [P] [US1] Fuzz tests `services/dns/internal/validate/content_fuzz_test.go` — arbitrary type/value/name for Content and RecordSet: never panics, accepted output always re-parses to exactly one RR of the requested type, never contains a newline or directive, names always inside the zone.
- [X] T034 [P] [US1] Unit test `services/dns/internal/records/records_test.go` — ownership check before every PowerDNS call (stored pdns_id only); filter/search/stable sort/paging with correct total; CNAME exclusivity against existing rrsets and apex CNAME refused; rename = single PATCH with REPLACE + DELETE; per-value disabled + comment mapping; SOA edits refused; `BenchmarkList5000` over a 5,000-rrset fake zone (< 3 s budget, SC-008).
- [X] T035 [P] [US1] Unit test `services/dns/internal/recursor/reconciler_test.go` — start-up + interval reconcile pushes every managed zone, removes forwards for unmanaged zones except static forwards and `.`, ReconcileNow after readiness, disabled client no-op, injected clock.

### Implementation
- [X] T036 [US1] `services/dns/internal/validate/content.go` + `services/dns/internal/validate/recordset.go` — per-type parsing via miekg/dns `NewRR` on a module-built line + semantic rules + canonical output + RecordSet (names, TTL, values, exclusivity) (makes T032/T033 pass; 100 % coverage).
- [X] T037 [US1] `services/dns/internal/zones/zones.go` — Service: Create (validate, conflict function, PowerDNS existence check, create, compensate), Get (with serial), List, Update, Delete, with recursor sync, events, audit and metrics.
- [X] T038 [US1] `services/dns/internal/records/records.go` — Service: List (filter/search/page), Upsert, Update (rename), Delete via single PATCH per request, events (`dns.record.changed` source api) and audit.
- [X] T039 [US1] `services/dns/internal/recursor/reconciler.go` — periodic + start-up reconcile over `dns_zone_names()` (system scope), unmanaged-forward removal, ReconcileNow with readiness polling; registered as an app worker in `services/dns/internal/app/app.go`.
- [X] T040 [US1] HTTP handlers `services/dns/internal/httpapi/zones.go` and `services/dns/internal/httpapi/records.go` + registration in `services/dns/internal/httpapi/server.go` with per-route permission enforcement and error-reason mapping.
- [X] T041 [P] [US1] gRPC `services/dns/internal/grpcapi/zones.go` — Zones.List/Get/FindForName for module callers (tenant from request, SPIFFE caller checked against policy) + `services/dns/internal/grpcapi/zones_test.go`.
- [X] T042 [P] [US1] UI schemas + stores: `services/dns/ui/src/schemas/zone.ts` (zoneSchema, ZONE_KINDS, name rules), `services/dns/ui/src/schemas/record.ts` (RECORD_TYPES, per-type hints/light checks), `services/dns/ui/src/api/types.ts`, `services/dns/ui/src/stores/zones.ts`, `services/dns/ui/src/stores/records.ts`.
- [X] T043 [US1] UI views: `services/dns/ui/src/views/zones/index.vue` (search, kind filter, paged UiDataTable, row click opens drawer, "New zone" UiRecordDrawer close-on-save) and `services/dns/ui/src/views/zones/drawer.vue` (name/kind/masters/nameservers/DNSSEC/description, serial chip, delete with confirm) + unit tests `services/dns/ui/tests/unit/zones.spec.ts`.
- [X] T044 [US1] UI records view `services/dns/ui/src/views/zones/records.vue` (type filter + name search, paged table, inline row editor with per-type placeholder hints, multi-value rows with disabled toggles, comment, SOA read-only row, delete confirm, server error reasons shown inline) + route in `services/dns/ui/src/remote/routes.ts` + unit tests `services/dns/ui/tests/unit/records.spec.ts`.

## Phase 4: User Story 2 — Keep DNS in sync with IPAM (Priority: P1)

**Goal**: IPAM address events, verified against IPAM, maintain A/AAAA + PTR records with subnet-sized reverse zones and public-suffix-aware parent zones.
**Independent test**: allocate IPv4 and IPv6 addresses with host names in IPAM; see forward + PTR records; rename one and release the other; records follow (quickstart Scenario 2).

### Tests (write first, must fail)
- [X] T045 [P] [US2] Test `services/ipam/pkg/ipamclient/ipamclient_getaddress_test.go` — GetAddress(tenant, id) maps IpAddressService/Get, NotFound propagated as a gRPC NotFound status, errors propagated.
- [X] T046 [P] [US2] Unit + fuzz tests `services/dns/internal/ipamsync/plan_test.go` and `services/dns/internal/ipamsync/plan_fuzz_test.go` — forward zone = longest tenant zone suffix; registrable-domain parent via publicsuffix (`web.newcorp.co.uk` → `newcorp.co.uk.`); bare host skipped; A vs AAAA; IPv4 reverse sizing /8 /16 /24 rounding down + clamping; IPv6 nibble sizing /4../64; existing longer reverse zone preferred; PTR owner names for v4/v6; fuzz: any IP + prefix yields a zone that contains the PTR owner name.
- [X] T047 [P] [US2] Fuzz test `services/dns/internal/ipamsync/decode_fuzz_test.go` — stream entry decoding: arbitrary type/data never panics, oversized (> 4 KiB) or malformed payloads dropped, only the four ipam.ip_address.* types accepted.
- [X] T048 [P] [US2] Unit tests `services/dns/internal/ipamsync/sync_test.go` (fake IPAM, fake pdns, memstore) — created/scanned upsert forward + PTR and write sync state; forged event (unknown id or hostname differing from IPAM) writes only IPAM's real state or nothing; rename removes old forward from sync state and repoints PTR; cleared host name removes forward + PTR; deleted (IPAM NotFound) removes both, zones kept; duplicate and out-of-order events converge; only the event's tenant is touched; reverse zone overlapping another tenant → PTR skipped + audited `sync.skip`; reverse failure keeps the forward; IPAM subnet lookup failure falls back to /24 or /64; events without host name ignored.
- [X] T049 [P] [US2] Unit test `services/dns/internal/ipamsync/consumer_test.go` — XLast start position per tenant, XRead loop over configured tenants, own `dns.*` events ignored, handler errors logged and loop continues, context cancel stops.

### Implementation
- [X] T050 [US2] Add `GetAddress(ctx, tenantID, id)` to `services/ipam/pkg/ipamclient/ipamclient.go` (IpAddressService/Get) (makes T045 pass).
- [X] T051 [US2] `services/dns/internal/ipamsync/plan.go` — zone selection, registrable-domain parent, reverse zone sizing and PTR names for IPv4/IPv6 (research D9).
- [X] T052 [US2] `services/dns/internal/ipamsync/decode.go` + `services/dns/internal/ipamsync/consumer.go` — bounded decoder and stream consumer (deployer pattern, tenants from `ipam_sync.tenants`).
- [X] T053 [US2] `services/dns/internal/ipamsync/sync.go` — verify via IPAM (GetAddress, GetSubnet), ensure zones through zones.Service (origin ipam, system subject pinned to the tenant), upsert/delete via validated rrsets, sync state, events (source ipam), audit, metrics.
- [X] T054 [US2] Wire the IPAM consumer in `services/dns/internal/app/app.go` (ipam module client via Freya.Client, stream reader) and add the rule allowing `spiffe://example.org/svc/dns` → `/ipam.v1.IpAddressService/Get`, `/ipam.v1.IpAddressService/Find`, `/ipam.v1.SubnetService/Get` in `services/ipam/deploy/policy.yaml`.
- [X] T055 [US2] UI: origin badge ("IPAM") + origin filter in `services/dns/ui/src/views/zones/index.vue` and source hint on IPAM-managed record rows in `services/dns/ui/src/views/zones/records.vue` + unit test update in `services/dns/ui/tests/unit/zones.spec.ts`.

## Phase 5: User Story 3 — Templates, supermasters, export and NOTIFY (Priority: P2)

**Goal**: reusable zone templates with `[ZONE]` expansion, platform-admin-controlled supermasters, BIND export and NOTIFY.
**Independent test**: create a template and a zone from it; add/remove a supermaster; export a zone; NOTIFY a master zone and see a native zone refused (quickstart Scenario 3).

### Tests (write first, must fail)
- [X] T056 [P] [US3] Unit tests `services/dns/internal/templates/templates_test.go` — CRUD, per-tenant case-insensitive unique name, record validation at save against a placeholder zone, expansion: `[ZONE]` in names and content, `@`/empty → apex, relative qualification, priority applied to MX/SRV, same (name, type) merged into one rrset, re-validation against the real zone.
- [X] T057 [P] [US3] Fuzz test `services/dns/internal/templates/expand_fuzz_test.go` — arbitrary template records + zone names: expansion never panics and every produced rrset is either valid and inside the zone or refused.
- [X] T058 [P] [US3] Unit tests `services/dns/internal/supermasters/supermasters_test.go` — create/delete require supermasters:manage AND platform-admin (tenant admin refused); account forced to the tenant; global (ip, nameserver) uniqueness; IP guard; PowerDNS-first with compensation both ways; list/get only own tenant's rows; no update.
- [X] T059 [P] [US3] Contract test `services/dns/tests/contract/templates_test.go` — templates CRUD shapes, supermasters routes (no PUT), `/zones/{id}/export` text shape, `/zones/{id}/notify` 202 for master and invalid_kind for native, permissions per route.

### Implementation
- [X] T060 [US3] `services/dns/internal/templates/templates.go` + `services/dns/internal/templates/expand.go` — Service CRUD + audit + Expand; HTTP handlers `services/dns/internal/httpapi/templates.go`.
- [X] T061 [US3] Zone creation from a template in `services/dns/internal/zones/zones.go` (template_id → Expand → rrsets on the PowerDNS create) + test cases added to `services/dns/internal/zones/zones_test.go`.
- [X] T062 [US3] `services/dns/internal/supermasters/supermasters.go` — Service with PowerDNS mirroring + compensation + audit; HTTP handlers `services/dns/internal/httpapi/supermasters.go`.
- [X] T063 [US3] Export (size-capped text) and NOTIFY (master/producer only) in `services/dns/internal/zones/zones.go` + routes in `services/dns/internal/httpapi/zones.go`; unowned-PowerDNS-zone detection metric in `services/dns/internal/recursor/reconciler.go`.
- [X] T064 [P] [US3] UI templates: `services/dns/ui/src/views/templates/index.vue` (list) + `services/dns/ui/src/views/templates/drawer.vue` (name/description, record rows name/type/TTL/content/priority, `[ZONE]` hint) + `services/dns/ui/src/schemas/template.ts` + store + unit test.
- [X] T065 [P] [US3] UI supermasters: `services/dns/ui/src/views/supermasters/index.vue` (list, delete confirm) + `services/dns/ui/src/views/supermasters/drawer.vue` (create ip/nameserver; hidden without the platform-admin ability) + store + unit test.
- [X] T066 [US3] UI zone drawer additions in `services/dns/ui/src/views/zones/drawer.vue` — template picker on create, Export tab (monospace BIND text + copy), NOTIFY action shown for master/producer only + unit tests.

## Phase 6: User Story 4 — Certificates for hosted domains via ACME DNS-01 (Priority: P2)

**Goal**: lcm's Freya DNS provider publishes and removes `_acme-challenge` TXT values through the lcm-only `dns.v1.Challenges` surface.
**Independent test**: issue an ACME certificate for a name in a managed zone with the Freya DNS provider; TXT appears during validation and is removed afterwards; a non-lcm caller is refused (quickstart Scenario 4).

### Tests (write first, must fail)
- [X] T067 [P] [US4] Unit tests `services/dns/internal/acmechallenge/acmechallenge_test.go` — fqdn must equal `_acme-challenge.` + domain without `*.`; longest tenant zone chosen; no tenant zone → not found and nothing written; CNAME at the name refused; value format checked; Present adds the value keeping other TXT values; Present twice = one value; CleanUp removes only that value and deletes the rrset when empty; concurrent Present for apex + wildcard serialised per name; sweeper removes values older than max_age; audit per op.
- [X] T068 [P] [US4] gRPC tests `services/dns/internal/grpcapi/challenges_test.go` — lcm SPIFFE ID allowed; any other peer (deployer, gateway, none) → PermissionDenied + audit challenge.refused; error mapping (NotFound, FailedPrecondition, InvalidArgument, Unavailable); plus `services/dns/deploy/policy_test.go` asserting only lcm may call `/dns.v1.Challenges/*`.
- [X] T069 [P] [US4] Test `services/dns/pkg/dnsclient/dnsclient_test.go` — Present/CleanUp/Zones calls over an in-process gRPC server; errors propagated as typed errors.
- [X] T070 [P] [US4] lcm tests `services/lcm/internal/acme/freyadns_test.go` — registry lists `freya-dns` with no fields; NewProviderWith with a fake FreyaDNSClient calls Present/CleanUp with the issuer tenant; missing deps → ErrUnsupportedProvider; server error text never surfaced (ErrProvider); existing NewProvider behaviour unchanged (update `services/lcm/internal/acme/dns_test.go`).

### Implementation
- [X] T071 [US4] `services/dns/internal/acmechallenge/acmechallenge.go` (Present/CleanUp with per-name lock, dns_acme_challenges bookkeeping) + `services/dns/internal/acmechallenge/sweeper.go` registered as an app worker.
- [X] T072 [US4] `services/dns/internal/grpcapi/challenges.go` — Challenges service with peer SPIFFE check against `acme.allowed_caller`, registered in `services/dns/internal/grpcapi/server.go`.
- [X] T073 [US4] `services/dns/pkg/dnsclient/dnsclient.go` — typed module client (Present, CleanUp, ListZones, GetZone, FindForName).
- [X] T074 [US4] lcm provider: registry entry + `NewProviderWith`/`ProviderDeps` in `services/lcm/internal/acme/dns.go` and `FreyaDNSProvider` in `services/lcm/internal/acme/freyadns.go`; add `replace ../dns` + require in `services/lcm/go.mod`.
- [X] T075 [US4] lcm wiring: pass ProviderDeps (lazy dns client, issuer tenant) from `services/lcm/internal/issue/acme.go` (`acmeClientFor`), optional `dns: {service}` section in `services/lcm/internal/config/config.go`, dial in `services/lcm/internal/app/wire.go` + tests in `services/lcm/internal/issue/`.
- [X] T076 [US4] lcm UI: issuer drawer in `services/lcm/ui/src/views/issuers/index.vue` renders "Freya DNS" with no credential inputs and a hint that the domain must be hosted in the DNS module; schema update in `services/lcm/ui/src/schemas/issuer.ts` + unit test.

## Phase 7: User Story 5 — Server configuration (Priority: P3)

**Goal**: platform administrators edit resolver/authoritative settings, rendered to include-dir files and applied by restarting only the affected configured container.
**Independent test**: as platform admin change allowed networks and see only the resolver restarted; no-op save restarts nothing; tenant admin refused (quickstart Scenario 5).

### Tests (write first, must fail)
- [X] T077 [P] [US5] Unit tests `services/dns/internal/dnsconf/model_test.go` — defaults match spec US5-1; validation of IP literals, ports, CIDRs, `IP[:port]` upstreams, list bounds, dnssec_validation enum; `0.0.0.0/0`/`::/0` refused without allow_open_resolver.
- [X] T078 [P] [US5] Golden + fuzz tests `services/dns/internal/dnsconf/render_test.go` and `services/dns/internal/dnsconf/render_fuzz_test.go` — recursor YAML and auth conf golden files in `services/dns/testdata/dnsconf/`; deterministic output; fuzzed models (after validation) never yield a line outside the managed keys, never a raw newline/`#`/`:` injection inside a value; unvalidated models refused.
- [X] T079 [P] [US5] Tests `services/dns/internal/dnsconf/docker_test.go` — httptest server on a temp unix socket: only `POST /containers/{name}/restart` and `GET /_ping` are ever requested; names come only from the Target enum mapped to config; path escaping; 404/500 → error; disabled restarter never dials; fuzz Target values beyond the enum are rejected.
- [X] T080 [P] [US5] Unit tests `services/dns/internal/dnsconf/service_test.go` — requires config:manage AND platform-admin (tenant admin/owner, viewer refused); save validates, persists, writes only changed files atomically, restarts only the affected target, no-op restarts nothing (SC-006), disabled docker → restart_required; readiness poll + ReconcileNow after a recursor restart; start-up re-apply rewrites drifted files; audit config.update/apply/restart.
- [X] T081 [P] [US5] Contract test `services/dns/tests/contract/config_test.go` — GET/PUT shapes, 403 for non-platform-admins, invalid_config reasons, response lists restarted containers and never file contents or keys.

### Implementation
- [X] T082 [US5] `services/dns/internal/dnsconf/model.go` — typed model, defaults, Validate (research D11).
- [X] T083 [US5] `services/dns/internal/dnsconf/render.go` (quoting writer; recursor 5.x YAML + auth key=value; port go-tangra-dns internal/dnsconf/render.go) + `services/dns/internal/dnsconf/files.go` (hash compare, temp + rename).
- [X] T084 [US5] `services/dns/internal/dnsconf/docker.go` — restart-only unix-socket client over the two configured names + Fake.
- [X] T085 [US5] `services/dns/internal/dnsconf/service.go` — Get/Update/Apply/start-up re-apply worker + HTTP handlers `services/dns/internal/httpapi/config.go` + wiring in `services/dns/internal/app/app.go`.
- [X] T086 [US5] UI `services/dns/ui/src/views/configuration/index.vue` (platform-admin only; resolver and authoritative sections with list editors, open-resolver warning toggle, save → restarted/restart_required summary) + `services/dns/ui/src/schemas/config.ts` + store + unit test.

## Phase 8: User Story 6 — Observe DNS health (Priority: P3)

**Goal**: curated resolver + authoritative dashboard over 1 h / 6 h / 24 h with graceful degradation.
**Independent test**: with metrics configured the panels populate and refresh; without it a notice shows; no arbitrary query is possible (quickstart Scenario 6).

### Tests (write first, must fail)
- [X] T087 [P] [US6] Unit tests `services/dns/internal/dashboard/dashboard_test.go` — window → range/step mapping (1h/60 s, 6h/300 s, 24h/900 s), unknown window refused, only catalogue expressions reach the client (assert via fake), no metrics URL → available:false, one failing panel does not fail the rest, bounded concurrency and timeout.
- [X] T088 [P] [US6] Tests `services/dns/internal/dashboard/prom_test.go` — Prometheus HTTP client against httptest: query and query_range parameters, vector/matrix decoding, error/status handling, response size cap.
- [X] T089 [P] [US6] Contract test `services/dns/tests/contract/dashboard_test.go` — response shape, dashboard:read required, `query` parameters rejected by the schema.

### Implementation
- [X] T090 [US6] `services/dns/internal/dashboard/catalogue.go` (panel ids + PromQL from go-tangra-dns frontend/src/views/dashboard/index.vue) + `services/dns/internal/dashboard/prom.go` (stdlib client + Fake) + `services/dns/internal/dashboard/dashboard.go` (service).
- [X] T091 [US6] HTTP handler `services/dns/internal/httpapi/dashboard.go` + wiring (optional metrics URL) in `services/dns/internal/app/app.go`.
- [X] T092 [US6] UI `services/dns/ui/src/views/dashboard/index.vue` (window picker, stat tiles, series charts via the kit, 30 s auto-refresh, "metrics unavailable" notice) + store + unit test.

## Phase 9: Platform integration & polish

- [X] T093 [P] Tests `services/dns/internal/backup/backup_test.go` + fuzz of the import parser — export of zone metadata, templates, supermasters (+ BIND text for reference), schema version, skip/overwrite, non-admin import pinned to the caller tenant, full/cross-tenant restore refused for non-admins, zones missing in PowerDNS reported, zones owned elsewhere skipped, no keys exported.
- [X] T094 `services/dns/internal/backup/backup.go` + HTTP `/backup/export|import` in `services/dns/internal/httpapi/backup.go`; SSE `/stream` in `services/dns/internal/httpapi/stream.go`.
- [X] T095 Stack DNS servers in `deploy/stack/compose.yaml`: `dns-secrets-init` (one-shot: random auth + recursor API keys into the `dns-secrets` volume, plus `00-api.conf` / `00-api.yml` include snippets into the `pdns-auth-conf` / `pdns-recursor-conf` volumes), `pdns-auth` (powerdns/pdns-auth-49 pinned by digest, `container_name: freya-pdns-auth`, sqlite3 backend on `pdns-auth-data`, webserver/API on the internal network only with allow-from the stack subnet, include-dir from `pdns-auth-conf`, DNS published 5300/udp+tcp) and `pdns-recursor` (powerdns/pdns-recursor-51 pinned, `container_name: freya-pdns-recursor`, API internal only, `api_dir` volume, include_dir `pdns-recursor-conf`, DNS published 127.0.0.1:5301/udp+tcp (5353 is mDNS on hosts)); base configs `services/dns/deploy/pdns/pdns.conf` and `services/dns/deploy/pdns/recursor.yml`. — DONE: recursor pinned to `powerdns/pdns-recursor-53` (5.1.10 reports a mandatory security update); DNS published on loopback 5300 (auth) / 5301 (resolver; 5353 is mDNS).
- [X] T096 Stack dns service: `dns` DB + `dns_app` role in `deploy/stack/init-db.sql`; `dns` Valkey user in the valkey command; `dns-token` mint init; `dns` compose service (freya/dns:dev, mounts policy + kek, `dns-secrets:/secrets:ro`, `pdns-auth-conf` + `pdns-recursor-conf` read-write for the rendered files, `/var/run/docker.sock` read-write with `group_add: ["${DOCKER_GID}"]` set by `deploy/stack/up.sh`); `deploy/stack/configs/dns.yaml` (ports 9965/9966/9850, discovery gateway/auth/lcm/ipam, `file:` key refs, docker enabled with the two container names, ipam_sync tenants); lcm discovery `dns: ["dns:9965"]` + `dns: {service: dns}` in `deploy/stack/configs/lcm.yaml`; optional `metrics` profile with Prometheus scraping both PowerDNS webservers (`deploy/stack/prometheus/prometheus.yml`).
- [X] T097 Gateway allow-list: add `spiffe://example.org/svc/dns=/api/dns;dns` to gateway-bootstrap in `deploy/stack/compose.yaml`; confirm registration (registered:true) and the DNS menu renders. — DONE: registered:true, `/api/dns/v1/health` 200 via gateway, remote `/m/dns/remoteEntry.js` 200; menu rendering not browser-verified (no operator sign-in).
- [X] T098 [P] `services/dns/deploy/policy.yaml` (gateway forwards; lcm → Challenges only; modules → Zones read + health) + `services/dns/deploy/kek.dev`.
- [X] T099 [P] `services/dns/deploy/README.md` (PowerDNS + recursor setup, API-key references and the warden/platform-token gap, managed include files, Docker socket risk acceptance and socket-proxy recommendation for production, IPAM sync tenants, ACME Freya DNS provider, dashboard/Prometheus) and list dns in `deploy/stack/README.md`; CHANGELOG entry in `CHANGELOG.md`.
- [X] T100 [P] Redaction test `services/dns/tests/security/redaction_test.go` — drive every service path with sentinel API keys through fakes and assert the keys never appear in logs, audit rows, events, HTTP/gRPC responses or errors (SR-002, SC-007); wire `scripts/redaction-scan.sh` for the dns module.
- [ ] T101 [P] UI end-to-end `services/dns/ui/tests/e2e/dns-flow.spec.ts` + `services/dns/ui/tests/e2e/a11y.spec.ts` (axe) — zones list → drawer → create → records inline edit → export; templates; supermasters; configuration (platform admin); dashboard notice. — PARTIAL: `dns-flow.spec.ts` + extended `a11y.spec.ts` written, lint clean; they skip without `E2E_OPERATOR_PASSWORD` (the stack operator is already enrolled with unknown credentials), so not executed.
- [X] T102 Integration test `services/dns/tests/integration/pdns_test.go` (`//go:build integration`; TimescaleDB, Valkey, real pdns-auth + pdns-recursor containers): zone create → SOA + A via the authoritative server and the resolver (miekg/dns client), record edit/delete, template zone, export, NOTIFY refusal, IPAM sync against a fake IPAM gRPC server (v4 + v6 PTR), challenge Present/CleanUp visible in DNS, config render + file write (restarter faked), cross-tenant duplicate refusal.
- [X] T103 Integration test `services/lcm/tests/integration/acme_freyadns_test.go` (`//go:build integration`): Pebble (VA pointed at the recursor, not always-valid) + dns module + pdns containers issue a certificate for a hosted name with the Freya DNS provider; no `_acme-challenge` TXT remains afterwards (SC-005).
- [X] T104 Coverage + supply chain: `go -C services/dns test ./...` ≥ 80 % overall, 100 % on authz/sealed/validate; `services/dns/scripts/coverage-gate.sh` wired into `make cover`; `make vuln` (govulncheck) and `make lint` clean for services/dns, services/lcm and services/ipam. — DONE: dns 96.1 % (authz/sealed/validate 100 %), govulncheck clean for dns/lcm/ipam, `make lint` clean for dns + lcm; ipam staticcheck clean, ipam gosec still reports 29 PRE-EXISTING findings (G115 int conversions in grpcapi/mapper + ipamclient, kvm BMC TLS/cookie) not introduced by this feature.
- [X] T105 Security review (Constitution: Code Review) of `services/dns` + the lcm provider against research STRIDE: tenant overlap/shadowing, forged IPAM events, Docker socket restart-only path, config injection, challenge caller restriction, PromQL restriction, key redaction; record findings and fixes in `services/dns/deploy/README.md` security section.
- [X] T106 Stack smoke: bring up the stack; dns registers; quickstart Scenarios 1–6 via curl/dig (US1 zone+records through resolver on :5301, US2 IPAM allocate/rename/release, US3 template/export/NOTIFY, US4 Freya DNS issuance, US5 config save restarting only freya-pdns-recursor, US6 dashboard with the metrics profile) and the quickstart security checks. — DONE with limits: live stack exercised through the real dns services (zone+records, overlap refusal, template/export/NOTIFY, ACME Present/CleanUp by lcm identity + non-lcm refusal, config save restarting only freya-pdns-recursor / nothing when unchanged, tenant-admin config refusal, backup round-trip, dashboard available:false) with `dig` on :5300/:5301; forged IPAM event wrote nothing (live consumer → ipam mTLS). NOT verified live: browser/gateway-authenticated calls (no operator credentials), real IPAM allocate→sync (covered by T102), lcm issuance in the stack (Pebble is ALWAYS_VALID; covered by T103).

## Dependencies & sequencing

- Setup (Phase 1) and Foundational (Phase 2) block everything; T017 (names), T019
  (pdns client) and T021 (recursor client) are needed by every story.
- US1 (P1) is the MVP: zones + records + resolver forwarding work alone.
- US2 (P1) depends on US1 (zones.Service for ensure-zone, validate content T036,
  records PATCH path) and on the ipam change T050 + policy T054.
- US3 (P2) depends on US1 (zone create path for templates, export/NOTIFY on
  zones); US4 (P2) depends on US1 (zones, validate) and touches lcm (T074–T076
  after T073).
- US5 (P3) depends on Foundational + the recursor reconciler (T039) for
  post-restart re-sync; US6 (P3) depends on Foundational only.
- Phase 9: T093–T094 after US1/US3 (entities); T095–T097 before T106; T102 needs
  US1–US5; T103 needs US4; T104–T106 last.

## Parallel execution examples

- Phase 1: T003 ∥ T004 ∥ T005 ∥ T006 ∥ T007 after T001–T002.
- Phase 2: T011, T012, T013, T014, T015, T016, T018, T020, T022, T023, T025 in parallel after T010; then T017 ∥ T019 ∥ T021.
- US1: T029 ∥ T030 ∥ T031 ∥ T032 ∥ T033 ∥ T034 ∥ T035, then T036 → T037 → T038 → T040; T039, T041 and T042 in parallel with T038; T043 → T044.
- US2: T045 ∥ T046 ∥ T047 ∥ T048 ∥ T049, then T050 ∥ T051 ∥ T052, then T053 → T054, T055 in parallel.
- US3: T056 ∥ T057 ∥ T058 ∥ T059, then T060 ∥ T062, T061 and T063 after T060, UI T064 ∥ T065, then T066.
- US4 can run in parallel with US3 (different packages): T067 ∥ T068 ∥ T069 ∥ T070 → T071 ∥ T073 → T072, T074 → T075 → T076.
- US5 and US6 can run in parallel with each other: T077–T081 ∥ T087–T089, then their implementations.

## Implementation strategy

MVP first: Setup + Foundational + US1 (zones and records on PowerDNS with
resolver forwarding) → demoable against the stack's PowerDNS. Then US2 (IPAM
sync — the reference system's main integration). Then US3 (templates,
supermasters, export, NOTIFY) and US4 (Freya DNS ACME provider) in parallel,
then US5 (configuration + restarts) and US6 (dashboard), then Phase 9 (backup,
stack, e2e, integration, coverage, security review, smoke).

## Summary

- **Total tasks**: 106 across 9 phases.
- **Per story**: US1 = 16 (T029–T044), US2 = 11 (T045–T055), US3 = 11 (T056–T066), US4 = 10 (T067–T076), US5 = 10 (T077–T086), US6 = 6 (T087–T092).
- **Setup/Foundational/Polish**: 7 + 21 + 14.
- **MVP scope**: Setup + Foundational + US1.
- **Novel vs prior modules**: management of an external shared DNS server with cross-tenant name-overlap protection, per-type DNS content validation, verified (fetch-to-verify) platform-event consumption, subnet-sized IPv4/IPv6 reverse zones, config rendering + restart-only Docker socket client, curated metrics proxy, and a cross-module ACME DNS-01 provider restricted to the lcm identity.
