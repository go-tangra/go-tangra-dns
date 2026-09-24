# Quickstart: DNS Service

Validation scenarios proving the feature end to end. Assumes the `deploy/stack`
platform is up (TimescaleDB, Valkey, gateway, auth, lcm, ipam) with the dns
service registered, plus the new **pdns-auth** and **pdns-recursor** containers
(APIs internal only; DNS published on the host for `dig`: resolver
`127.0.0.1:5301`, authoritative `127.0.0.1:5300`). Contracts:
[dns-api.md](./contracts/dns-api.md); data: [data-model.md](./data-model.md).

## Prerequisites
- dns service running: gateway `/api/dns` (`registered:true`), PowerDNS API keys
  resolved from the dev `file:` references written by `dns-secrets-init`
  (production: warden references — research D14).
- An operator signed in with the dns admin role; a viewer-role user; a
  platform administrator (configuration, supermaster create/delete); a second
  tenant's admin for isolation checks.
- `docker.enabled: true` in `configs/dns.yaml` and the Docker socket mounted
  (dev stack) for Scenario 5; the optional `metrics` compose profile for
  Scenario 6.

## Scenario 1 — Zones and records (US1)
1. Create zone `example.test` (native, NS `ns1.example.test.`) → listed with its serial; `dig @127.0.0.1 -p 5300 example.test SOA` answers; the recursor lists a forward for `example.test.`.
2. Add A `www` 192.0.2.10, AAAA `www` 2001:db8::10, MX `@` `10 mail.example.test.`, TXT `@` `v=spf1 -all`, CAA `@` `0 issue "letsencrypt.org"` → `dig @127.0.0.1 -p 5301 www.example.test` resolves through the resolver within a minute.
3. Edit `www` A to two values with one disabled → only the enabled value answers; rename it → old name gone.
4. Refusals (nothing reaches PowerDNS): A `999.1.1.1`, MX without priority, CNAME at `@`, CNAME next to an A, name `foo.other.test` outside the zone, SOA edit, zone name `co.uk`, `bad..name`.
5. List records with type filter `A` and search `ww` → only matching sets; delete the zone → gone from PowerDNS, list and recursor forwards.
6. Stop pdns-auth → create zone/record fails with `pdns_unavailable`; no local row; restart it.

## Scenario 2 — IPAM sync (US2)
1. With zone `lab.example.test` present, allocate `10.20.30.40` host `srv1.lab.example.test` in IPAM (subnet `10.20.30.0/24`) → within 10 s `srv1` A in `lab.example.test.` and PTR in `30.20.10.in-addr.arpa.` (created, origin ipam).
2. Allocate `2001:db8:1:2::40` host `v6.lab.example.test` (subnet /64) → AAAA + PTR in the `/64` nibble `ip6.arpa.` zone.
3. Allocate `172.16.5.9` host `web.newcorp.co.uk` (no zone) → zone `newcorp.co.uk.` auto-created (not `co.uk.`).
4. Rename `srv1` → `srv2` → old A removed, new A + repointed PTR; clear the host name of the v6 address → AAAA and PTR removed.
5. Release both → forward + reverse records removed; zones kept.
6. Replay the same events twice / out of order → final records match IPAM's state.

## Scenario 3 — Templates, supermasters, export, NOTIFY (US3)
1. Template "std" with `@ NS ns1.[ZONE].`, `@ MX mail.[ZONE]. prio 10`, `@ TXT "v=spf1 mx -all"` → create `tpl.test` from it → records present with MX priority 10.
2. Duplicate template name → refused; edit replaces the record list.
3. As platform admin add supermaster `192.0.2.53` / `ns.primary.test.` → PowerDNS lists it; duplicate pair refused; as tenant admin create → refused (platform-admin required); delete → gone.
4. Export `tpl.test` → BIND text shown and copyable.
5. NOTIFY a master zone → 202; NOTIFY a native zone → `invalid_kind`.

## Scenario 4 — ACME DNS-01 via Freya DNS (US4)
1. In lcm create an ACME issuer (Pebble) with DNS provider **Freya DNS** (no credential fields shown).
2. Request a certificate for `app.example.test` → during validation `dig @127.0.0.1 -p 5300 _acme-challenge.app.example.test TXT` shows the token (with Pebble pointed at the platform resolver, or `PEBBLE_VA_ALWAYS_VALID` for the flow-only check); after issuance the TXT is gone; a pre-existing unrelated TXT at that name is untouched.
3. Request for `app.unhosted.test` → refused clearly, nothing written.
4. Call `dns.v1.Challenges/Present` with a non-lcm SVID (e.g. from the deployer container) → `PermissionDenied`; audit `challenge.refused`.

## Scenario 5 — Server configuration (US5)
1. As platform admin open Configuration with no saved row → defaults shown.
2. Change resolver allowed networks to add `100.64.0.0/10` → save → response lists only the recursor container as restarted; `dig` from an allowed network works.
3. Save again unchanged → nothing restarted; change only the auth port → only the auth container restarted.
4. Invalid values (`300.0.0.1`, port 70000, `0.0.0.0/0` without the open-resolver flag) → refused with reasons, no file written.
5. As tenant admin / viewer → configuration read and write refused (403).
6. Restart the dns service → stored configuration re-applied, forwards re-synced.

## Scenario 6 — Dashboard (US6)
1. With the `metrics` profile up → panels populated for 1 h / 6 h / 24 h, refreshing every 30 s.
2. Without a metrics URL → "metrics unavailable" notice, no errors.
3. `GET /dashboard?window=7d` or any `query=` parameter → refused/ignored; only catalogue panels run.

## Security checks (cross-cutting)
- Tenant B cannot list/read/export/NOTIFY/edit tenant A's zone ids (404), cannot create `example.test`, `sub.example.test` or `test`-level parents overlapping A's zone (`duplicate`, owner not revealed).
- A forged `ipam.ip_address.created` event XADDed to `platform:events:<tenant>` with an id IPAM does not know (or a hostname different from IPAM's) writes nothing / writes only IPAM's real state.
- A PTR for an address inside a reverse zone owned by another tenant is skipped and logged.
- Configuration cannot restart any container other than the two configured names (no API field carries a name); with `docker.enabled: false` saves report `restart_required`.
- Logs, events, audit and API responses contain no PowerDNS/recursor API keys (redaction scan).
- The PowerDNS and recursor API ports are not reachable from the host.
- Export/import round-trips a tenant's templates, supermasters and zone metadata; non-admin import lands only in the caller's tenant.
