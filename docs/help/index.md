---
title: DNS
summary: Run your DNS zones on the platform's PowerDNS servers, edit record sets, start zones from templates, publish IPAM addresses as A, AAAA and PTR records and answer ACME DNS-01 challenges.
kind: guide
order: 0
tags: [dns, overview, zones, records]
requires: zones:read
---
The DNS module manages zones and their records on the platform's shared
PowerDNS authoritative server. The platform's resolver (PowerDNS Recursor)
forwards every managed zone to that server, so a record you save is answered
right away, both by the authoritative server and through the resolver.

## Concepts

- **Zone** — a DNS domain such as `example.com.` or a reverse zone such as
  `10.168.192.in-addr.arpa.`. A zone name belongs to one tenant: nobody else
  can create it, or a zone inside or above it. Who owns a taken name is never
  shown.
- **Record set** — all records of one name and type, for example the two `A`
  records of `www.example.com.`. You always edit a whole set: its TTL, its
  values and a comment. Each value can be disabled without deleting it.
- **Template** — a list of records applied to a new zone, with `[ZONE]`
  standing for the zone name.
- **Supermaster** — a primary DNS server allowed to create secondary zones on
  the platform server for your tenant by sending NOTIFY.
- **IPAM sync** — addresses with a host name in IPAM become `A`/`AAAA` and
  `PTR` records automatically.

## Pages in the portal

| Page | Shows | Needs |
|---|---|---|
| Zones | your zones; open one for details, **Records**, **Edit**, **Notify**, **Export**, **Delete** | `zones:read` |
| Templates | zone templates | `zones:read` (changes: `templates:manage`) |
| Supermasters | your tenant's supermasters | `supermasters:manage` |
| Dashboard | resolver and authoritative server metrics | `dashboard:read` |
| Configuration | the DNS server settings (platform administrators) | `config:manage` |

Your role decides what you can do; see
[permissions and roles](reference.md#permissions-and-roles).

## Where to go next

- [Get started](getting-started.md): a zone and its first records.
- [Manage zones](guides/zones.md): kinds, primaries, templates, NOTIFY, export.
- [Edit record sets](guides/records.md)
- [IPAM sync and ACME challenges](guides/ipam-sync.md)
- [Example: a mail domain from a template](examples/mail-domain.md)
- [Reference](reference.md): fields, record types, permissions, API and limits.
