---
title: "Example: a mail domain from a template"
summary: Build a template with MX, SPF, DMARC and CAA records once, and create every new mail domain from it.
kind: example
order: 50
tags: [dns, example, templates, mx, txt, caa]
requires: templates:manage
---
**Goal.** Your company registers new domains from time to time. Each one
needs the same mail setup: mail handled by `mail.<domain>` at `192.0.2.25`,
an SPF policy, a DMARC policy and a CAA record that allows only Let's
Encrypt. You want to type this once.

**Plan.** One template with `[ZONE]` in place of the domain; every new zone
is created from it.

## 1. The template

On **DNS → Templates**, create a template named `mail-domain` with these
records:

| Name | Type | TTL | Value | Priority |
|---|---|---|---|---|
| `@` | `MX` | 3600 | `mail.[ZONE].` | 10 |
| `mail` | `A` | 3600 | `192.0.2.25` | |
| `@` | `TXT` | 3600 | `v=spf1 mx -all` | |
| `_dmarc` | `TXT` | 3600 | `v=DMARC1; p=quarantine; rua=mailto:dmarc@[ZONE]` | |
| `@` | `CAA` | 86400 | `0 issue "letsencrypt.org"` | |

`[ZONE]` is replaced by the zone name without its trailing dot, so the `MX`
value keeps its own final dot. The priority is put in front of the `MX`
value.

The same through the API, `POST /api/dns/v1/templates`:

```json
{
  "name": "mail-domain",
  "description": "MX, SPF, DMARC and CAA for a mail domain",
  "records": [
    {"name": "@", "type": "MX", "ttl": 3600, "content": "mail.[ZONE].", "priority": 10},
    {"name": "mail", "type": "A", "ttl": 3600, "content": "192.0.2.25"},
    {"name": "@", "type": "TXT", "ttl": 3600, "content": "v=spf1 mx -all"},
    {"name": "_dmarc", "type": "TXT", "ttl": 3600, "content": "v=DMARC1; p=quarantine; rua=mailto:dmarc@[ZONE]"},
    {"name": "@", "type": "CAA", "ttl": 86400, "content": "0 issue \"letsencrypt.org\""}
  ]
}
```

The template is checked when you save it, as if it were applied to a zone,
so a typo is caught now and not when you create a domain.

## 2. A new domain

On **DNS → Zones**, choose **New zone**: **Zone name** `example.org`,
**Nameservers** `ns1.example.com., ns2.example.com.`, **Template**
`mail-domain`. Create.

Through the API, `POST /api/dns/v1/zones` (needs `zones:manage`):

```json
{
  "name": "example.org",
  "kind": "native",
  "nameservers": ["ns1.example.com.", "ns2.example.com."],
  "template_id": "<mail-domain id>"
}
```

## 3. The result

**Records** of `example.org.` shows:

| Name | Type | Value |
|---|---|---|
| `example.org.` | `SOA` | maintained by PowerDNS |
| `example.org.` | `NS` | `ns1.example.com.`, `ns2.example.com.` |
| `example.org.` | `MX` | `10 mail.example.org.` |
| `example.org.` | `TXT` | `"v=spf1 mx -all"` |
| `example.org.` | `CAA` | `0 issue "letsencrypt.org"` |
| `_dmarc.example.org.` | `TXT` | `"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org"` |
| `mail.example.org.` | `A` | `192.0.2.25` |

The `TXT` values are stored quoted.

## Variations

- **Change the mail server later.** Editing the template does not touch
  zones already created from it. Change the `A` record of `mail` in each
  zone, or point the template at a new address for future domains.
- **Certificates for the new domain.** With the zone in place, lcm can use
  the **Freya DNS** provider to answer DNS-01 challenges for it; see
  [ACME challenges](../guides/ipam-sync.md#acme-dns-01-challenges).

Related: [zones and templates](../guides/zones.md#start-from-a-template),
[record sets](../guides/records.md).
