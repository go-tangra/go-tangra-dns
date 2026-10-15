---
title: Get started
summary: Create a zone, add an address record and a mail record, and check the answer.
kind: guide
order: 10
tags: [dns, getting-started, zones, records]
requires: zones:manage
---
This walk-through creates a zone and gives it its first records. You need
`zones:manage`; the *DNS administrator* role and the built-in `owner` and
`admin` roles have it.

## 1. Create the zone

1. Open **DNS → Zones** and choose **New zone**.
2. Type the **Zone name**, for example `example.com`. Upper-case letters and a
   missing trailing dot are fine: the name is stored as `example.com.`.
3. Leave **Kind** at `native`.
4. In **Nameservers**, list the zone's name servers, for example
   `ns1.example.com., ns2.example.com.`.
5. Choose **Create**.

If the answer is `duplicate`, the name (or a zone inside or above it) is
taken, possibly by another tenant, or it already exists on the DNS server.
Public suffixes such as `com` or `co.uk` cannot be zones.

## 2. Add an address record

1. Open the zone and choose **Records**. The list starts with the `SOA`
   record, which PowerDNS maintains and you cannot edit.
2. Choose **Add record set**.
3. **Name** `www`, **Type** `A`, **TTL** one of the presets.
4. **Value 1**: `192.0.2.10`. **Add value** for a second address if you have
   one.
5. Choose **Save**.

## 3. Add a mail record

Add another record set: **Name** `@` (the zone itself), **Type** `MX`,
**Value 1** `10 mail.example.com.`.

Write host names inside values in full, ending with a dot. A short name such
as `10 mail` is not completed with the zone name: it is saved as `mail.`, a
name at the DNS root.

## 4. Check the answer

The zone is live as soon as it is created. Ask the platform resolver (or the
authoritative server) for it, for example:

```sh
dig www.example.com A
dig example.com MX
```

## Next steps

- [Zone kinds, templates, NOTIFY and export](guides/zones.md)
- [Record set rules](guides/records.md)
- [Let IPAM write the address records](guides/ipam-sync.md)
