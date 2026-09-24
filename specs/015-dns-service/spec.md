# Feature Specification: DNS Service

**Feature Branch**: `015-dns-service`

**Created**: 2026-09-23

**Status**: Draft

**Input**: User description: "use speckit to create a new service called dns. The idea is to replicate the same functionality like following project /home/jadmin/projects/go-tangra/go-tangra-dns. Then create a plan and tasks"

## Overview

The **dns** service is a tenant-scoped **DNS management plane** for a PowerDNS
deployment (authoritative server + recursive resolver) that runs alongside the
platform. It does not answer DNS queries itself: PowerDNS does. The service lets
tenants manage **zones** (native, master, slave, producer, consumer; optional
DNSSEC), their **record sets** (16 record types), reusable **zone templates**,
and **supermasters** (trusted primaries that may auto-provision secondary zones);
it exports zones as BIND text and sends NOTIFY; it keeps the **recursive
resolver** forwarding every managed zone to the authoritative server; it lets a
platform administrator edit the **server configuration** (listen addresses,
ports, allowed clients, upstream resolvers, zone-transfer peers, DNSSEC
validation) which is rendered to config files and applied by restarting the DNS
containers; it shows a **dashboard** of resolver and authoritative metrics; and
it keeps **forward and reverse records in sync with IPAM** address allocations.

Freya adaptations (vs the source): SPIFFE mTLS + gateway platform token replace
the mTLS-CN trust and LCM bootstrap; TimescaleDB + per-tenant row-level security
replace ent app-level filtering; the PowerDNS API keys come from the platform
secret store; IPAM events arrive from the Freya IPAM module (feature 011) over
the platform event bus; server configuration and container restarts are
restricted to platform administrators.

Enhancements over the reference (which lacks them or leaves them unfinished):
enforced API permissions; zone names unique across all tenants (PowerDNS is
shared, so one tenant can never shadow or collide with another's zone); record
content validated per type before it reaches PowerDNS; record-set search; IPAM
sync for IPv6 (AAAA + ip6.arpa) with reverse zones sized to the subnet and a
public-suffix-aware parent zone; a curated (not free-form) dashboard query set;
published zone and record events; an audited history of every change; and a
**Freya DNS provider for the certificate service**, so ACME DNS-01 challenges
for domains hosted here are answered automatically.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Manage zones and records (Priority: P1)

A DNS administrator creates a zone (e.g. `example.com`), adds records (A, AAAA,
CNAME, MX, TXT, SRV, CAA …) with TTLs, edits and deletes them, and sees the
zone's current serial. Internal clients can resolve the new names through the
platform resolver immediately.

**Why this priority**: This is the MVP — authoritative zone and record management
is the core of the product; everything else extends it.

**Independent Test**: Create a zone, add, edit and delete record sets, query the
authoritative server and the resolver for them, and delete the zone.

**Acceptance Scenarios**:

1. **Given** a tenant administrator, **When** they create a zone with a valid name (trailing dot optional), kind and optional nameservers, **Then** the zone exists in PowerDNS and in the tenant's list, and the resolver forwards it to the authoritative server.
2. **Given** a zone name already used by any tenant, **When** another zone with that name is created, **Then** it is refused as a duplicate; an invalid name is refused with the reason.
3. **Given** a zone, **When** a record set (name, type, TTL, one or more values, optional comment, per-value disabled flag) is created or edited, **Then** it replaces the record set of that name and type, and the authoritative server answers with the new data.
4. **Given** record content that does not match its type (e.g. an A value that is not an IPv4 address, an MX without priority, a CNAME at the apex next to other data), **When** it is saved, **Then** it is refused with a clear message and nothing reaches PowerDNS.
5. **Given** a zone with records, **When** the records are listed with a type filter or a name search, **Then** only matching record sets are shown; **When** the zone is deleted, **Then** it disappears from PowerDNS, the list and the resolver's forward list.
6. **Given** PowerDNS is unreachable, **When** any change is attempted, **Then** it fails with a clear message and local and PowerDNS state stay consistent (no half-created zone).

---

### User Story 2 - Keep DNS in sync with IPAM (Priority: P1)

When an address with a host name is allocated (or discovered by a scan) in IPAM,
the matching forward record (A or AAAA) and reverse record (PTR) appear
automatically; renaming or releasing the address updates or removes them.

**Why this priority**: Automatic forward/reverse DNS for managed addresses is the
reference system's main integration and removes routine manual work.

**Independent Test**: Allocate an IPv4 and an IPv6 address with host names in
IPAM and see A/AAAA + PTR records created; rename one and release the other and
see the records follow.

**Acceptance Scenarios**:

1. **Given** a managed zone that is a suffix of a new address's host name, **When** IPAM reports the address as created or scanned, **Then** an A (IPv4) or AAAA (IPv6) record is upserted in the longest matching zone, and a PTR record in the matching reverse zone (created if missing, sized to the subnet: /8, /16 or /24 for IPv4 on octet boundaries, nibble boundaries for IPv6).
2. **Given** no managed zone matches, **When** the address is created, **Then** a zone is created for the registrable domain of the host name (public-suffix aware) and marked as auto-created from IPAM.
3. **Given** an address whose host name changes, **When** IPAM reports the update, **Then** the old forward record is removed and the new one created; a cleared host name removes the PTR.
4. **Given** an address is released, **When** IPAM reports the deletion, **Then** its forward and reverse records are removed; zones are never deleted by the sync.
5. **Given** an event for a tenant, **When** it is processed, **Then** only that tenant's zones are touched; events without a host name are ignored.

---

### User Story 3 - Templates, supermasters, export and NOTIFY (Priority: P2)

An administrator defines zone templates (e.g. standard NS, MX and SPF records
with a `[ZONE]` placeholder) and creates new zones from them; registers
supermasters so trusted primaries can auto-provision secondary zones; exports a
zone as BIND text; and sends NOTIFY for master zones.

**Why this priority**: These speed up and standardise zone operations but are not
needed to manage a zone by hand.

**Independent Test**: Create a template, create a zone from it and see the
expanded records; add and remove a supermaster; export a zone; send NOTIFY for a
master zone and see it refused for a native zone.

**Acceptance Scenarios**:

1. **Given** a template with records (name relative or "@", type, TTL, content, priority), **When** a zone is created from it, **Then** `[ZONE]` is replaced in names and content, relative names are qualified, priorities are applied to MX and SRV records, and the records exist in the new zone.
2. **Given** template names, **When** a template is created, **Then** its name is unique per tenant; editing replaces its record list.
3. **Given** a supermaster (IP, nameserver, account), **When** it is created or deleted, **Then** PowerDNS reflects it and the pair (IP, nameserver) is unique; editing is not offered (delete and re-create).
4. **Given** a zone, **When** it is exported, **Then** its full BIND zone text is returned for display and copying.
5. **Given** a master zone, **When** NOTIFY is sent, **Then** PowerDNS notifies the secondaries; for any other kind it is refused.

---

### User Story 4 - Certificates for hosted domains via ACME DNS-01 (Priority: P2)

A certificate operator requests a public (ACME) certificate for a domain whose
zone is managed by the DNS service; the certificate service publishes and later
removes the `_acme-challenge` TXT record through the DNS service, with no DNS
vendor credentials to configure.

**Why this priority**: It connects two platform services and removes a manual
step for hosted domains, but DNS management is useful without it.

**Independent Test**: Request an ACME certificate for a name in a managed zone
using the Freya DNS provider; see the TXT record appear during validation and be
removed afterwards, and the certificate issue.

**Acceptance Scenarios**:

1. **Given** the certificate service selects the Freya DNS provider for a tenant, **When** it presents a DNS-01 challenge, **Then** the TXT record is added in the tenant's longest matching managed zone and removed on clean-up, without touching other TXT values of that name.
2. **Given** a domain not in any zone of that tenant, **When** a challenge is presented, **Then** it is refused clearly and nothing is written.
3. **Given** a caller other than the certificate service, **When** it calls the challenge operations, **Then** it is refused.

---

### User Story 5 - Server configuration (Priority: P3)

A platform administrator adjusts the resolver (listen addresses, port, allowed
client networks, upstream resolvers, DNSSEC validation) and the authoritative
server (listen addresses, port, zone-transfer peers). Saving renders the
configuration and restarts only the DNS container(s) whose configuration
changed, reporting which were restarted.

**Why this priority**: Needed to operate the DNS servers from the platform, but
changes are rare and administrator-only.

**Independent Test**: As a platform administrator, change the resolver's allowed
networks, save, see the resolver restarted and the new setting in effect; as a
tenant administrator, see the configuration refused.

**Acceptance Scenarios**:

1. **Given** no saved configuration, **When** it is read, **Then** safe defaults are shown (resolver on all addresses port 53, private networks + loopback allowed, validation off; authoritative on all addresses port 53, no transfer peers).
2. **Given** a platform administrator, **When** the configuration is saved, **Then** it is validated (addresses, CIDRs, ports), rendered, written only if changed, and only the affected container(s) are restarted; the response lists them.
3. **Given** anyone who is not a platform administrator, **When** they read or change the configuration, **Then** they are refused.
4. **Given** the service restarts, **When** it starts, **Then** it re-applies the stored configuration and re-synchronises the resolver's forward zones.

---

### User Story 6 - Observe DNS health (Priority: P3)

An administrator opens a dashboard showing resolver throughput, cache hit rate,
latency, answer codes (NOERROR/NXDOMAIN/SERVFAIL) and authoritative query rates
over 1 h, 6 h or 24 h, refreshing automatically.

**Why this priority**: Operational visibility; the service works without it.

**Independent Test**: With metrics collection configured, open the dashboard and
see the panels populated; without it, see a clear "metrics unavailable" notice.

**Acceptance Scenarios**:

1. **Given** metrics collection is configured, **When** the dashboard loads a window, **Then** each panel shows its series for that window and refreshes every 30 seconds.
2. **Given** metrics collection is not configured, **When** the dashboard loads, **Then** it shows a notice instead of errors.
3. **Given** a caller, **When** the dashboard queries metrics, **Then** only the predefined panel queries can be run (no arbitrary query text).

### Edge Cases

- Creating a zone succeeds in PowerDNS but saving it locally fails: the PowerDNS zone is removed again (no orphan).
- A zone name exists in PowerDNS but not locally (created outside the platform): creation is refused as a duplicate; it is not silently adopted.
- Deleting a zone that PowerDNS no longer has still removes the local entry.
- A record set name outside the zone, or an SOA edit, is refused; SOA serials are managed by PowerDNS.
- A CNAME cannot coexist with other data at the same name; apex CNAME is refused.
- IPAM events arriving out of order or twice are applied idempotently (upserts/deletes by name+type).
- An IPAM host name that matches no zone and has no registrable domain (e.g. a bare host) is ignored.
- A reverse zone the tenant does not own (another tenant manages that range) is never written; the PTR is skipped and logged.
- The resolver or Docker being unavailable does not block zone management; synchronisation retries on its interval.
- A configuration save with no effective change restarts nothing.
- Very large zones (thousands of record sets) list, search and export without timing out.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST let tenant administrators create, read, list (search by name, filter by kind, paged with a correct total), update (kind, masters, description, DNSSEC) and delete zones, keeping PowerDNS and local state consistent (compensating on partial failure).
- **FR-002**: Zone names MUST be canonical (trailing dot, lower-case, valid labels) and unique across all tenants.
- **FR-003**: System MUST let users list (type filter, name search), create/replace, update and delete record sets of a zone for the types A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA, DS, DNSKEY, TLSA, SSHFP, SPF, NAPTR (SOA read-only), each with TTL, one or more values, per-value disabled flag and a comment.
- **FR-004**: System MUST validate record names (inside the zone, relative "@" allowed) and content per type (address formats, priority/weight/port fields, CNAME exclusivity, TXT quoting, CAA/TLSA/SSHFP field formats) before any change reaches PowerDNS.
- **FR-005**: System MUST show each zone's current serial, export a zone as BIND text, and send NOTIFY for master zones only.
- **FR-006**: System MUST let tenant administrators CRUD zone templates (name unique per tenant, record list with name/type/TTL/content/priority) and create zones from a template with `[ZONE]` substitution, relative-name qualification and priority applied to MX/SRV.
- **FR-007**: System MUST let administrators create, list, view and delete supermasters (IP, nameserver, account; unique IP+nameserver), mirrored to PowerDNS with compensation on failure.
- **FR-008**: System MUST keep the resolver forwarding every managed zone to the authoritative server: on zone create/delete, after start-up, on a configurable interval, and after a configuration change.
- **FR-009**: System MUST consume IPAM address created/scanned/updated/deleted events and maintain A/AAAA and PTR records as described in User Story 2, idempotently and within the event's tenant only.
- **FR-010**: System MUST let a platform administrator read and update the DNS server configuration (resolver: listen addresses, port, allowed networks, upstream resolvers, DNSSEC validation; authoritative: listen addresses, port, zone-transfer peers), validate it, render it to the servers' configuration files, write only changed files, restart only the affected DNS containers, report them, and re-apply the stored configuration on start-up.
- **FR-011**: System MUST provide dashboard data for a fixed set of resolver and authoritative panels over a selectable window when metrics collection is configured, and report "unavailable" otherwise.
- **FR-012**: System MUST expose DNS-01 challenge operations (present/clean up a TXT value for a name) to the certificate service only, and the certificate service MUST offer a "Freya DNS" provider that uses them.
- **FR-013**: System MUST publish events for zone created/updated/deleted and record set changed (identifiers and names only) to the platform event bus.
- **FR-014**: System MUST enforce API permissions: zones:read, zones:manage, templates:manage, supermasters:manage, dashboard:read, and platform-administrator-only configuration; seeded roles DNS admin (all tenant permissions) and DNS viewer (read).
- **FR-015**: System MUST record an append-only audit entry for every zone, record, template, supermaster, configuration, sync and challenge change (actor, tenant, subject, outcome).
- **FR-016**: System MUST register its routes, permissions, UI abilities and navigation with the application gateway, expose service-to-service APIs, and ship its UI module (zones list + zone drawer, records view with inline editor, templates, supermasters, configuration, dashboard).
- **FR-017**: System MUST support per-tenant export/import of its own data (zones metadata, templates, supermasters); zone contents are exported as BIND text by reference to FR-005, and full or cross-tenant restore is restricted to platform administrators.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: browser API via the gateway; the PowerDNS authoritative and resolver HTTP APIs; the Docker Engine socket (container restarts); the metrics backend; the platform event bus (IPAM events in, DNS events out); service-to-service mesh (certificate service calls, secret store, auth).
- **Data classification**: zone and record data (tenant-confidential until published); PowerDNS API keys (secrets); server configuration (platform-sensitive); audit records (tamper-evident).
- **Authentication/Authorization**: browser callers use the gateway platform token with per-route permissions; module callers use SPIFFE mTLS; challenge operations accept only the certificate service's identity; configuration and container restarts require platform-administrator authority; RLS isolates tenants.
- **Threat scenarios**: one tenant hijacking or shadowing another tenant's domain through the shared PowerDNS; forged IPAM events writing records; record content injecting configuration into zone files; a non-administrator restarting infrastructure or opening the resolver to the internet; the Docker socket being used to control unrelated containers; arbitrary metrics queries used for reconnaissance or load; leakage of PowerDNS API keys.
- **SR-001**: All local data MUST be isolated per tenant by row-level security, and every PowerDNS operation MUST first verify that the zone belongs to the caller's tenant; zone names MUST be globally unique so no tenant can create a zone overlapping another's.
- **SR-002**: PowerDNS API keys MUST come from the platform secret store and never appear in responses, logs, audit or events.
- **SR-003**: Configuration reads and writes and container restarts MUST require platform-administrator authority; rendered values MUST be validated (no free text reaches the files unvalidated); the service MUST only restart the two configured DNS container names and never any other container.
- **SR-004**: IPAM events MUST be accepted only from the IPAM module's authenticated channel and applied only within the tenant carried by the event; reverse records MUST never be written into another tenant's reverse zone.
- **SR-005**: Challenge operations MUST accept only the certificate service's identity and only write TXT records at `_acme-challenge` names inside the tenant's zones.
- **SR-006**: Dashboard queries MUST be limited to the predefined panel set with bounded windows and steps.
- **SR-007**: Every change MUST be audited append-only with actor, tenant, subject and outcome.

### Key Entities *(include if feature involves data)*

- **Zone**: a DNS zone owned by a tenant; canonical name (globally unique), kind, masters, DNSSEC flag, description, template used, origin (manual | ipam-auto), PowerDNS identifier.
- **Record set**: name + type within a zone with TTL, values (each with a disabled flag) and a comment; stored in PowerDNS, not locally.
- **Zone template**: a named, per-tenant list of template records (name, type, TTL, content, priority).
- **Supermaster**: a trusted primary (IP, nameserver, account) allowed to auto-provision secondary zones.
- **DNS configuration**: the platform-wide resolver and authoritative settings (single record).
- **Sync state**: per IPAM address, the forward/reverse names last written (for idempotent updates and deletes).

## Success Criteria *(mandatory)*

- **SC-001**: An administrator can create a zone and publish a record that resolves through the platform resolver in under 1 minute.
- **SC-002**: 100% of invalid zone names, duplicate zone names (across tenants) and type-inconsistent record contents are refused before reaching the DNS server.
- **SC-003**: An IPAM allocation with a host name has working forward and reverse resolution within 10 seconds, and a release removes both within 10 seconds, for IPv4 and IPv6.
- **SC-004**: No tenant can read, change or shadow another tenant's zones or records in any tested scenario.
- **SC-005**: An ACME certificate for a hosted domain issues with the Freya DNS provider without any DNS credentials being configured, and no challenge TXT record remains afterwards.
- **SC-006**: A configuration change restarts only the DNS containers whose configuration changed, and a no-op save restarts nothing (100% of test cases).
- **SC-007**: PowerDNS API keys never appear in any response, log, audit entry or event (verified by inspection).
- **SC-008**: Zones with 5,000 record sets list, search and export in under 3 seconds.

## Assumptions

- PowerDNS Authoritative (with its HTTP API) and the PowerDNS Recursor run as containers in the platform stack; this feature adds them to the development stack. Production operators provide equivalent deployments.
- The PowerDNS instance is shared by all tenants (as in the reference); tenant separation is enforced by the service (ownership checks + global zone-name uniqueness).
- Metrics collection (Prometheus-compatible) is optional; the dashboard degrades gracefully without it.
- The requester chose to keep the reference's container-restart approach (Docker Engine socket), restricted to platform administrators and to the two DNS containers.
- IPAM (feature 011) publishes address events with tenant, address, host name, previous host name and subnet; subnet prefix is looked up from IPAM when sizing reverse zones (defaults /24 IPv4, /64 IPv6 if unavailable).
- The platform provides tenant identity, the gateway, the event bus, the audit trail, identity issuance, the secret store and the certificate service; this feature consumes them.

## Out of Scope

- Serving DNS queries from the platform service itself (PowerDNS does).
- Zone import from BIND files or AXFR into the UI, bulk record operations.
- DNSSEC key management, DS publication at registrars and key rollover (DNSSEC is an on/off flag).
- Other DNS vendors (Cloudflare, Route 53, …) as backends.
- RFC 2136 dynamic updates / TSIG, GeoDNS, health-checked failover, propagation checks.
- Editing supermasters (delete and re-create).
