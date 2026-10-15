---
title: Manage zones
summary: Choose a zone kind, set primaries and name servers, start from a template, change or delete a zone, send NOTIFY, export BIND text and manage supermasters.
kind: guide
order: 20
tags: [dns, zones, templates, notify, export, supermasters]
requires: zones:manage
---
Open **DNS → Zones** to list your zones. Search by name, or filter by
**Kind** and **Origin** (`manual`, or `ipam` for zones the IPAM sync
created). Open a zone to see its details, including the serial PowerDNS last
notified.

## Zone kinds

| Kind | Use it for | Primaries |
|---|---|---|
| `native` | an ordinary zone served by the platform; the default | none |
| `master` | a primary zone whose secondaries get NOTIFY and transfer it | none |
| `slave` | a secondary copy of a zone held by another primary server | at least one |
| `producer` | a catalog zone that lists member zones for secondaries | none |
| `consumer` | a catalog zone received from a producer | at least one |

**Primaries** are `IP` or `IP:port`, comma-separated, at most 16. The records
of `slave` and `consumer` zones come from their primaries and cannot be edited
here.

**Nameservers** (at most 16) become the zone's initial `NS` set; secondaries
take theirs from the primary. **DNSSEC** is passed to PowerDNS as the zone's
DNSSEC flag.

## Start from a template

Choose a **Template** when you create the zone to add its records at once.
In a template, `[ZONE]` stands for the zone name without its trailing dot,
`@` or an empty name is the zone apex, and other names are relative to the
zone. For `MX` and `SRV` the template's **priority** is put in front of the
value when the value does not start with one.

Manage templates on **DNS → Templates** (needs `templates:manage`). A
template holds up to 200 records and is checked when you save it, with the
same rules as record sets. Changing or deleting a template does not change
zones created from it.

## Change a zone

**Edit** changes the kind, primaries, DNSSEC flag and description. The name
cannot change. Moving a zone away from `slave` or `consumer` clears its
primaries.

## Send NOTIFY

**Notify** asks PowerDNS to notify the secondaries of a `master` or
`producer` zone now. Other kinds answer `invalid_kind`.

## Export

The **Export** tab shows the zone as BIND zone text, as the server serves it,
with **Copy**. Exporting needs `zones:manage`. A zone larger than the export
limit (by default 32 MiB) is refused.

## Delete a zone

**Delete** removes the zone from the DNS server, from the resolver's forward
list and from the module, with all its records. This cannot be undone.

## Supermasters

A supermaster is a primary server (its IP and the name server name it uses)
that may create secondary zones on the platform server simply by sending
NOTIFY. Zones it creates belong to your tenant. **DNS → Supermasters** lists
your tenant's supermasters (needs `supermasters:manage`); adding or deleting
one also needs the `platform-admin` role, because it touches the shared
server.

Related: [record sets](records.md), [reference](../reference.md#zone-fields).
