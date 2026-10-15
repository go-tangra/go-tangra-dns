---
title: Edit record sets
summary: Add, change, disable and delete record sets; name and value rules, TTLs, CNAME rules and the record types you can edit.
kind: guide
order: 30
tags: [dns, records, ttl, cname]
requires: zones:manage
---
Open a zone on **DNS → Zones** and choose **Records**. The table lists the
zone's record sets in DNS order, apex first, `SOA` leading. Filter by
**Type** or search names. Records that the IPAM sync maintains carry an
**IPAM** badge.

## Add or change a record set

**Add record set** opens the editor above the table:

- **Name** — `@` for the zone itself, a relative name such as `www` (it gets
  the zone name appended; the field shows the result), or a full name ending
  with a dot. It must lie inside the zone. `*` is allowed as the whole
  left-most label (`*.dev`), `_` in any label (`_sip._tcp`).
- **Type** — one of the editable types (see the
  [reference](../reference.md#record-types)).
- **TTL** — a preset (1 minute to 1 week) or **Custom…** in seconds. The
  operator's limits apply, by default 60 seconds to 1 week.
- **Values** — one per row, up to 100. Each value can be **Disabled**: it
  stays in the set but is not served.
- **Comment** — optional, up to 512 characters.

**Save** replaces the whole set (that name and type) in one step: values you
removed are gone, values you added are live. Choosing **Edit** on a row and
changing its name or type moves the set: the new set is written and the old
one deleted together.

## Values

Each value is checked and stored in its canonical form, so what you read
back may differ in case or spacing from what you typed:

- `A` `192.0.2.10`; `AAAA` `2001:db8::10` (an IPv4-mapped IPv6 address is
  refused: use an `A` record).
- `MX` `10 mail.example.com.`; a null MX is `0 .`.
- `SRV` `10 5 5060 sip.example.com.` (priority, weight, port, target).
- `TXT` and `SPF`: plain text is quoted for you; text that already starts with
  `"` is taken as quoted strings.
- `CAA` `0 issue "letsencrypt.org"`: tag `issue`, `issuewild` or `iodef`.

Write host names inside values in full. A target without a trailing dot is
taken from the DNS root, not from the zone: `10 mail` becomes `mail.`, not
`mail.example.com.`.

Line breaks, control characters and zone-file directives (`$ORIGIN`,
`$INCLUDE`, ...) are refused. A refused value shows the reason next to the
field (`invalid_record`).

## CNAME rules

- A `CNAME` holds exactly one value.
- No `CNAME` at the zone apex.
- A `CNAME` must be alone at its name: no other record set may exist there,
  and no other set can be added where a `CNAME` exists.

## Delete

**Delete** on a row removes the whole set. The `SOA` set is read-only: its
serial is maintained by PowerDNS.

## Secondary zones

Records of `slave` and `consumer` zones come from their primaries. They are
shown but cannot be changed (`invalid_kind`).

Related: [zones](zones.md), [IPAM sync](ipam-sync.md).
