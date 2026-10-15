---
title: IPAM sync and ACME challenges
summary: How IPAM addresses become A, AAAA and PTR records, which zones they land in, and how lcm uses your zones to answer ACME DNS-01 challenges.
kind: guide
order: 40
tags: [dns, ipam, ptr, reverse, acme, certificates]
requires: zones:read
---
## IPAM sync

When the operator turns the IPAM sync on, every address in IPAM that has a
host name gets DNS records, without anyone editing a zone:

- an `A` record (IPv4) or `AAAA` record (IPv6) for the host name, and
- a `PTR` record pointing the address back to the host name.

The sync reacts to IPAM's address events (created, updated, scanned,
deleted). It never trusts the event itself: it reads the address and its
subnet from IPAM again and writes what IPAM holds.

### Which host names

The host name must be a full name with at least two labels, such as
`web1.example.com`. Single-label names (`web1`), IP literals, names with
`_` or `*` and names inside the reverse trees are ignored.

### Which zones

- **Forward.** The record goes into your longest zone that contains the host
  name: `web1.lab.example.com` lands in `lab.example.com.` if you have it,
  else in `example.com.`. When you have no such zone, the sync creates one
  for the registrable domain (`example.com.`, or `newcorp.co.uk.` for
  `web.newcorp.co.uk`) as a `native` zone with origin `ipam`.
- **Reverse.** The `PTR` goes into your longest reverse zone that contains
  it. When you have none, the sync creates one (origin `ipam`) sized from the
  IPAM subnet's prefix: for IPv4 rounded down to a whole octet between /8 and
  /24 (a /22 subnet gets the /16 zone, for example `168.192.in-addr.arpa.`),
  for IPv6 rounded down to a whole nibble between /4 and /64.

A zone that belongs to another tenant is never written; that side is
skipped.

### What changes when

| In IPAM | In DNS |
|---|---|
| an address gets a host name | `A`/`AAAA` value added to the host's set; `PTR` set to the host |
| the host name or address changes | the old values are removed and the new ones added |
| the host name is cleared | both records are removed |
| the address is deleted | both records are removed |

Several addresses with the same host name share one `A`/`AAAA` set; the sync
adds and removes only its own value and keeps the set's TTL. New sets get the
sync's TTL (by default 1 hour). Sets the sync wrote carry the comment
`managed by IPAM sync` and an **IPAM** badge. Zones the sync created are never
deleted by it.

You can edit these sets, but the next IPAM change to the address can
overwrite your edit of the `PTR` and re-add the sync's `A`/`AAAA` value.
Change the host name in IPAM instead.

## ACME DNS-01 challenges

lcm (the certificates module) can prove control of a domain to an ACME CA
through your zones: in an lcm ACME issuer, choose the DNS provider **Freya
DNS**. It needs no credentials.

For each challenge lcm asks DNS to add a `TXT` value at
`_acme-challenge.<domain>` (for `*.example.com`, at
`_acme-challenge.example.com`) and to remove it afterwards. The name must lie
in one of your zones. Other `TXT` values at that name are left alone. A
`CNAME` at the name makes the challenge fail. Values whose removal never
arrives are cleaned up after a while (by default one hour).

Related: [record sets](records.md), [reference](../reference.md).
