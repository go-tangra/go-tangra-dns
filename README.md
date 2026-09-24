# go-tangra-dns

PowerDNS management plane for the
[go-tangra v4 platform](https://github.com/go-tangra/go-tangra).

Tenants manage **zones and record sets** on one shared PowerDNS Authoritative
server, with global zone-name ownership (a name belongs to one tenant, and the
owner is never revealed to others). A PowerDNS **Recursor** forwards every managed
zone to the authoritative server. Zone templates, supermasters, BIND export and
NOTIFY, **IPAM sync** (IPAM addresses become A/AAAA and PTR records), the
**ACME DNS-01** challenge provider used by lcm, a curated metrics **dashboard**,
live updates and tenant backup come with it. Platform administrators edit the
**server configuration**: the service renders the PowerDNS include files and,
when enabled, restarts the two named PowerDNS containers through the Docker
Engine API. The PowerDNS API keys are secret **references** (warden in
production) that are resolved at use time and never logged.

Operations: [`deploy/README.md`](deploy/README.md).
Design history: `specs/015-dns-service`.

## Place in the platform

```
go-tangra/go-tangra          platform module + @go-tangra/ui kit
        |
go-tangra-auth  <---->  go-tangra-portal (gateway)  <---->  go-tangra-lcm
                                  |                              |  ACME DNS-01
go-tangra-ipam --(events)-->  go-tangra-dns  <-------------------+
                                  |
              PowerDNS Authoritative + Recursor (HTTP APIs, include files)
                                  |
                          go-tangra-warden (PowerDNS API keys)
```

- Built on `github.com/go-tangra/go-tangra/v4` (mTLS transports, identity,
  service policy, audit, observability).
- Verifies platform tokens and checks permissions through the auth SDK
  (`github.com/go-tangra/go-tangra-auth/sdk/v4`).
- Registers with the gateway through the portal SDK
  (`github.com/go-tangra/go-tangra-portal/sdk/v4`), which fronts the browser API
  (`/api/dns`) and the federated UI remote.
- Enrolls for its SVID with lcm over the network
  (`github.com/go-tangra/go-tangra-lcm/sdk/v4`), and serves lcm's DNS-01
  challenges (`dns.v1.Challenges`, only for the configured lcm SPIFFE ID).
- Reads IPAM addresses and subnets through the ipam SDK
  (`github.com/go-tangra/go-tangra-ipam/sdk/v4`) when it consumes
  `ipam.ip_address.*` events.
- Resolves `warden:` secret references through the warden SDK
  (`github.com/go-tangra/go-tangra-warden/sdk/v4`).

The repository holds one Go module, `github.com/go-tangra/go-tangra-dns/v4`.
Other services call it through `pkg/dnsclient` and the `dns.v1` protos
(not proxied by the gateway).

## Layout

| Path | What |
|------|------|
| `api/openapi/dns.yaml` | browser API contract (served under `/api/dns`) |
| `api/proto/dns/v1/` | module gRPC surface (`Zones/{List,Get,FindForName}`, `Challenges/{Present,CleanUp}`) |
| `internal/config` | configuration + validation (secure defaults, named opt-outs) |
| `internal/store`, `internal/repo` | TimescaleDB schema (RLS), repositories; `internal/memstore` is the in-memory test double |
| `internal/pdns`, `internal/recursor` | PowerDNS Authoritative and Recursor HTTP API clients (with fakes) |
| `internal/zones`, `internal/records`, `internal/templates`, `internal/supermasters`, `internal/validate` | domain services and record validation |
| `internal/dnsconf` | server configuration: include-file rendering, write-if-changed files, restart-only Docker client |
| `internal/ipamsync` | IPAM address events to A/AAAA/PTR records |
| `internal/acmechallenge` | ACME DNS-01 provider for lcm |
| `internal/secrets` | `warden:` / `file:` secret references with refresh |
| `internal/sealed` | envelope encryption with the KEK |
| `internal/authz` | permission and tenant checks |
| `internal/events`, `internal/stream` | events on the platform bus, live stream |
| `internal/backup`, `internal/dashboard`, `internal/metrics`, `internal/audit` | backup export/import, dashboard, metrics, audit |
| `internal/httpapi`, `internal/grpcapi` | browser and service APIs |
| `internal/app`, `cmd/dnssvc` | wiring and the service binary (serve, `bootstrap`, `version`) |
| `pkg/dnsmanifest` | gateway manifest and built-in role grants |
| `pkg/dnsclient` | Go client other services use |
| `testdata` | PowerDNS API, record and IPAM event fixtures |
| `tests/integration` | real TimescaleDB, Valkey and PowerDNS (testcontainers); `challengesrv` for lcm's suite |
| `tests/contract`, `tests/security` | API contract and security/redaction suites |
| `deploy` | service policy, PowerDNS base configs (`deploy/pdns`), operations notes |
| `ui/` | Vue 3 + FlyonUI federated remote on `@go-tangra/ui` |

## Build and test

You need Go 1.26, Node 22, Docker (for the integration suite and the image), and a
GitHub token with `read:packages` to install `@go-tangra/ui` from GitHub Packages.

```bash
go build ./... && go vet ./... && go test -race ./...
buf lint
make test-integration                     # -tags integration: TimescaleDB, Valkey, PowerDNS 4.9 + Recursor 5.3 via testcontainers
make lint cover vuln redaction-scan

cd ui
export NODE_AUTH_TOKEN=$(gh auth token)   # ui/.npmrc only references this variable
npm ci && npm run lint && npm run test:unit && npm run build
```

The integration suite runs the pinned PowerDNS images on a shared Docker network
and checks real DNS answers from the authoritative server and through the
recursor, including the IPAM event path over Valkey. `DNS_IT_ADMIN_DSN` points it
at an existing TimescaleDB server instead of a container. It skips when Docker is
not available.

The unit coverage gate (`make cover`) excludes generated code, SQL bindings and
wiring, which the integration suite covers instead. The Playwright specs in
`ui/tests/e2e` need a running platform and operator credentials; they skip
otherwise.

## Run

The service runs in the go-tangra platform stack (`deploy/stack` in
[go-tangra](https://github.com/go-tangra/go-tangra)), next to TimescaleDB, Valkey,
ipam and the `pdns-auth` / `pdns-recursor` containers. The stack mounts its
configuration at `/app/deploy/container.yaml` and the development key-encryption
key at `/app/deploy/kek.dev`. Its `dns-secrets-init` job generates the PowerDNS
API keys into the `dns-secrets` volume (`file:/secrets/pdns-*.key`) and writes the
API include snippets; the service renders its own include files into the shared
`pdns-auth-conf` / `pdns-recursor-conf` volumes. `deploy/kek.dev` in this
repository is a development key only; it is excluded from the image.

```bash
dnssvc bootstrap -config deploy/container.yaml    # apply migrations and exit
dnssvc -config deploy/container.yaml              # serve (applies migrations)
```

Listeners: gRPC `:9965` and HTTP `:9966` on the mesh (mTLS), admin `:9850`
(`/healthz`, `/readyz`). See `specs/015-dns-service/quickstart.md` for the
end-to-end walkthrough.

Container restart is off by default (`docker.enabled: false`). When enabled it
needs the Docker socket, which is root-equivalent on the host; the client only
restarts the two containers named in `docker.auth_container` and
`docker.recursor_container`, and only platform administrators can trigger it.
Production should put an API-filtering socket proxy in front of it
(`deploy/README.md`).

## Container image

The image is `ghcr.io/go-tangra/go-tangra-dns`, built by
`.github/workflows/ci.yaml`. It carries `dnssvc` with the embedded UI remote.

```bash
docker buildx build --secret id=npm_token,env=NODE_AUTH_TOKEN \
  --build-arg APP_VERSION=4.0.0 -t go-tangra-dns:dev .
docker run --rm go-tangra-dns:dev version
```

The image runs `dnssvc -config deploy/container.yaml` as user `app`
(uid 10001). It contains no configuration and no key material: deployments mount
their own `deploy/container.yaml`, key-encryption key and PowerDNS API key
references. `deploy/pdns/` holds the reference PowerDNS base configs; the
service does not read them at run time (the platform stack carries its own copy).

## API permissions

`zones:read/manage`, `templates:manage`, `supermasters:manage`, `dashboard:read`,
`backup:manage`, and `config:manage` (platform administrators only). The gateway
enforces the per-route permission from the manifest; the module then checks the
tenant scope. The module seeds the roles `dns admin` and `dns viewer` and the
built-in role grants (`pkg/dnsmanifest.Grants`).

## Versioning

- Releases are tagged `vX.Y.Z`. CI publishes the image as `X.Y.Z`, `X.Y`, `X`
  and `sha-<short>`. There is no `latest` tag.
- v4.0.0 rebuilds the service on the go-tangra v4 platform. The previous line
  stays on the `v3` branch and its `v3.x` tags.
