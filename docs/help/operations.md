---
title: Operate DNS
summary: Configuration keys and defaults, PowerDNS and the resolver, the server configuration page, IPAM sync and ACME setup, service policies and troubleshooting.
kind: reference
order: 90
tags: [dns, operations, configuration, powerdns, policy, troubleshooting]
audience: operator
---
DNS runs as `dnssvc` (image `ghcr.io/go-tangra/go-tangra-dns`) next to a
PowerDNS Authoritative server (4.9) and a PowerDNS Recursor (5.x).

```sh
dnssvc -config /app/deploy/container.yaml             # serve; applies migrations
dnssvc bootstrap -config /app/deploy/container.yaml   # apply migrations and exit
dnssvc version
```

At start it enrolls for its SVID `spiffe://<trust domain>/svc/dns`, migrates
its TimescaleDB schema, serves the browser API (through the gateway) and the
`dns.v1` gRPC API, registers with the gateway and registers its permissions
and roles with auth.

## Configuration

The file is YAML. Unknown keys are refused, so a typo stops the service at
start with `config: <file>: ...`. Besides the framework keys (`service_name`,
`trust_domain`, `env`, `identity`, `authz`, `server`, `admin`, `discovery`,
`limits`) DNS reads:

| Key | Default | Notes |
|---|---|---|
| `db.dsn`, `db.migrate_dsn`, `db.max_conns` | —, `db.dsn`, 16 | `db.dsn` required; in production `sslmode=verify-full` (or `verify-ca`) |
| `valkey.*` | — | `addresses` (required), `username` (`dns`), `password`, `ca_file`, `allow_plaintext` (refused in production) |
| `kek.source` | `file` | `file` (`kek.path`) or `env` (`kek.env`) |
| `pdns.api_url` | — | required; the Authoritative HTTP API; `http://` needs `pdns.allow_plaintext` |
| `pdns.api_key_ref` | — | required; a secret reference, `warden:<id>` or `file:<path>` |
| `pdns.server_id` | `localhost` | |
| `pdns.timeout_seconds` | 10 | 1–120 |
| `pdns.max_response_bytes` | 32 MiB | 64 KiB–256 MiB |
| `pdns.auth_forward_host`, `pdns.auth_forward_port` | `pdns-auth`, 53 | where the resolver forwards managed zones |
| `recursor.api_url` | empty | the Recursor HTTP API; empty turns resolver forwarding off |
| `recursor.api_key_ref`, `server_id`, `timeout_seconds`, `allow_plaintext` | —, `localhost`, 10, false | as for `pdns` |
| `recursor.reconcile_interval_seconds` | 300 | 10–86400 |
| `recursor.static_forwards` | empty | up to 64 forward zones the reconciler never removes |
| `managed_files.auth_path`, `managed_files.recursor_path` | empty | include files the Configuration page renders; empty: not written |
| `docker.enabled` | false | restart PowerDNS containers after a configuration change |
| `docker.socket`, `auth_container`, `recursor_container`, `timeout_seconds` | `/var/run/docker.sock`, `freya-pdns-auth`, `freya-pdns-recursor`, 60 | |
| `metrics.prometheus_url` | empty | the dashboard's data source; empty: dashboard unavailable |
| `metrics.timeout_seconds` | 10 | 1–60 |
| `ipam_sync.enabled` | false | |
| `ipam_sync.tenants` | `mesh_enroll.tenant_id` | tenants whose IPAM events are consumed |
| `ipam_sync.service` | `ipam` | |
| `ipam_sync.default_ttl` | 3600 | within the record TTL limits |
| `acme.allowed_caller` | `spiffe://example.org/svc/lcm` | the exact SPIFFE ID allowed to present challenges; set it to your trust domain |
| `acme.max_age_seconds` | 3600 | 60–86400; leftover challenge values are removed after this |
| `records.min_ttl`, `records.max_ttl` | 60, 604800 | |
| `records.max_values` | 100 | 1–1000 |
| `secrets.warden_service`, `secrets.token_file`, `secrets.refresh_seconds` | `warden`, —, 300 | how `warden:` references are resolved and how long values are cached |
| `limits_dns.max_export_bytes` | 32 MiB | BIND export cap |
| `gateway.service` | `gateway` | mesh name of the gateway; the only peer allowed to fetch the help pages |
| `gateway.issuer` | — | required, an `https://` origin |
| `mesh_enroll.*` | — | SVID enrollment with lcm |
| `events.enabled` | true | publish `dns.*` events |

These keys are accepted and range-checked but currently have no effect:
`records.max_page_size`, `limits_dns.max_request_bytes`,
`limits_dns.max_backup_bytes` and `limits_dns.max_page_size`.

### API keys

`file:` references are refused when `env` is `production`. `warden:`
references need a platform token in `secrets.token_file`; warden releases a
password only for a user token, so unattended resolution does not work today.
Deployments that use `file:` keys therefore run with a non-production `env`.

## Server configuration

**DNS → Configuration** (needs `config:manage` and the `platform-admin` role)
edits the resolver and the authoritative server:

- **Resolver:** listen addresses and port, **Allowed client networks**
  (default loopback and the private ranges), **Upstream resolvers** (empty:
  full recursion from the root), **DNSSEC validation** (`off`, `process`,
  `validate`). `0.0.0.0/0` or `::/0` is accepted only with **Allow an open
  resolver**.
- **Authoritative:** listen addresses and port, **Zone-transfer peers**
  (empty: loopback only).

**Save and apply** renders the include files (`managed_files.*`) and, when
`docker.enabled`, restarts only the container whose file changed. With
restarts off, the answer lists the server under `restart_required`: restart
it yourself. The Docker socket is root-equivalent on the host; put a proxy in
front that allows only `GET /_ping` and the restart of the two containers.

## Resolver forwarding

For every managed zone the reconciler keeps a forward zone on the Recursor
pointing at `pdns.auth_forward_host:auth_forward_port`, at start and every
`recursor.reconcile_interval_seconds`. Forwards of zones that are no longer
managed are removed, except `recursor.static_forwards`.

## Service policies

DNS's own policy must let the gateway in. Its usual rule allows every HTTP
method, which covers the help pages (`GET /docs/v1/bundle`):

```yaml
rules:
  - id: gateway-forwards
    from: ["spiffe://<trust domain>/svc/gateway"]
    to: ["dns"]
    operations: ["GET *", "HEAD *", "POST *", "PUT *", "PATCH *", "DELETE *", "OPTIONS *"]
    effect: allow
```

It also allows lcm `/dns.v1.Challenges/Present` and `/CleanUp`, and any
module `/dns.v1.Zones/List`, `/Get`, `/FindForName`.

Other modules must admit `spiffe://<trust domain>/svc/dns`:

| Module | Operations | Why |
|---|---|---|
| ipam | `/ipam.v1.IpAddressService/Get`, `/Find`, `/ipam.v1.SubnetService/Get` | IPAM sync (rule `dns-ipam-sync`) |
| warden | `/warden.v1.Secrets/GetPassword` | `warden:` API key references (see [API keys](#api-keys)) |

lcm needs `discovery.static.dns` and `dns: { service: dns }` to use the
**Freya DNS** ACME provider.

## Troubleshooting

**The service refuses to start with `config: ...`.** The message names the
key, for example `pdns.api_url uses http; set allow_plaintext (internal
network only) or use https` or `ipam_sync.tenants (or mesh_enroll.tenant_id)
is required when ipam_sync.enabled`.

**The service refuses to start with `help docs: ...`.** The help pages built
into the binary are invalid. `tangra-docs lint` in CI catches this; rebuild
from a commit that passed CI.

**Zone and record changes answer `pdns_unavailable`.** The PowerDNS API is
unreachable or refuses the API key. Check `pdns.api_url` and the key
reference.

**Names resolve on the authoritative server but not through the resolver.**
Check `recursor.api_url` and the reconciler; the forward points at
`pdns.auth_forward_host`, which must resolve from DNS's container.

**The dashboard says metrics are unavailable.** `metrics.prometheus_url` is
empty or the endpoint does not answer.

**IPAM addresses get no records.** Check `ipam_sync.enabled` and
`ipam_sync.tenants` (only those tenants are synced), ipam's `dns-ipam-sync`
rule, and that the IPAM host names have at least two labels. A reverse or
forward zone owned by another tenant is skipped and logged.

**ACME challenges fail.** The domain must lie in a zone of the issuer's
tenant, `acme.allowed_caller` must be lcm's exact SPIFFE ID, and there must be
no `CNAME` at `_acme-challenge.<domain>`.
