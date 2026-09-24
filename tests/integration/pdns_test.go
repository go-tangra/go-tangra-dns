//go:build integration

// Package integration runs the DNS module's services against REAL
// infrastructure (T102): TimescaleDB (migrations + RLS-scoped app role),
// Valkey (the IPAM event path: ipam.ip_address.* entries XADDed to
// platform:events:<tenant> and consumed by ipamsync.Consumer over the valkeykv
// client) and the pinned PowerDNS Authoritative + Recursor images on a shared
// Docker network. DNS answers are checked with a miekg/dns client against the
// servers' mapped UDP ports — from the authoritative server AND through the
// resolver (forward zones pointed at the authoritative container's IP).
//
//	go test -tags integration -count=1 -v ./tests/integration/...
//
// It skips cleanly when Docker/testcontainers is unavailable. Set
// DNS_IT_ADMIN_DSN (a superuser DSN of an existing TimescaleDB server) to use
// it instead of a TimescaleDB container: a throwaway database is created and
// dropped.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-dns/v4/internal/acmechallenge"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/backup"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dnsconf"
	"github.com/go-tangra/go-tangra-dns/v4/internal/events"
	"github.com/go-tangra/go-tangra-dns/v4/internal/ipamsync"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/records"
	"github.com/go-tangra/go-tangra-dns/v4/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo/repodb"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/stream"
	"github.com/go-tangra/go-tangra-dns/v4/internal/stream/valkeykv"
	"github.com/go-tangra/go-tangra-dns/v4/internal/supermasters"
	"github.com/go-tangra/go-tangra-dns/v4/internal/templates"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

const (
	authImage     = "powerdns/pdns-auth-49@sha256:b554df74bbde1afa7caedad4af9c91378be6d46d05807d089b3c7c443002e684"
	recursorImage = "powerdns/pdns-recursor-53@sha256:175d551ce52fa5c6bf0a0c19d6872791a4c928f6fb00a696534c1174693da3f7"
	authKey       = "it-auth-api-key-0123456789"
	recursorKey   = "it-recursor-api-key-0123456789"
	lcmID         = "spiffe://example.org/svc/lcm"

	tenantA = "0190aaaa-0000-7000-8000-00000000000a"
	tenantB = "0190bbbb-0000-7000-8000-00000000000b"
)

// ---- infrastructure -------------------------------------------------------

func startContainer(t *testing.T, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		if c != nil {
			_ = c.Terminate(ctx)
		}
		t.Skipf("testcontainers unavailable (%s): %v", req.Image, err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })
	return c
}

func endpoint(t *testing.T, c testcontainers.Container, port string) string {
	t.Helper()
	ctx := context.Background()
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.MappedPort(ctx, port)
	if err != nil {
		t.Fatal(err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, p.Port())
}

// startDB returns the app-role DSN of a migrated dns database.
func startDB(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	if admin := os.Getenv("DNS_IT_ADMIN_DSN"); admin != "" {
		return existingDB(t, admin)
	}
	c := startContainer(t, testcontainers.ContainerRequest{
		Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
		Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "dns"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
	})
	hp := endpoint(t, c, "5432/tcp")
	adminDSN := "postgres://postgres:test@" + hp + "/dns?sslmode=disable"
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE ROLE dns_app LOGIN PASSWORD 'app' NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	if err := store.Migrate(ctx, adminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return "postgres://dns_app:app@" + hp + "/dns?sslmode=disable"
}

func existingDB(t *testing.T, admin string) string {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Skipf("DNS_IT_ADMIN_DSN unreachable: %v", err)
	}
	var exists bool
	_ = conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dns_app')").Scan(&exists)
	if exists {
		_ = conn.Close(ctx)
		t.Skip("role dns_app already exists on this server; refusing to reuse it")
	}
	name := "dns_it_" + strings.ReplaceAll(store.NewID()[:13], "-", "")
	for _, q := range []string{"CREATE DATABASE " + name, "CREATE ROLE dns_app LOGIN PASSWORD 'app' NOBYPASSRLS"} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_, _ = conn.Exec(ctx, "DROP ROLE IF EXISTS dns_app")
		_ = conn.Close(ctx)
	})
	hp := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", cfg.User, cfg.Password, hp, name)
	db, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS timescaledb"); err != nil {
		t.Skipf("timescaledb unavailable: %v", err)
	}
	_ = db.Close(ctx)
	if err := store.Migrate(ctx, adminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return "postgres://dns_app:app@" + hp + "/" + name + "?sslmode=disable"
}

type powerDNS struct {
	authAPI, recursorAPI string // http://host:port
	authDNS, recursorDNS string // host:port (udp)
	authIP               string // the authoritative server on the shared network
}

// startPowerDNS runs the pinned Authoritative + Recursor images on one
// network with their HTTP APIs keyed (the stack's settings: primary=yes for
// NOTIFY; recursor webservice with an api_dir for API-managed forwards).
func startPowerDNS(t *testing.T) powerDNS {
	t.Helper()
	ctx := context.Background()
	nw, err := network.New(ctx)
	if err != nil {
		t.Skipf("docker network unavailable: %v", err)
	}
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })
	auth := startContainer(t, testcontainers.ContainerRequest{
		Image: authImage, ExposedPorts: []string{"53/udp", "53/tcp", "8081/tcp"},
		Env:            map[string]string{"PDNS_AUTH_API_KEY": authKey},
		Networks:       []string{nw.Name},
		NetworkAliases: map[string][]string{nw.Name: {"pdns-auth"}},
		Files: []testcontainers.ContainerFile{{Reader: strings.NewReader("primary=yes\ndefault-soa-content=ns1.@ hostmaster.@ 0 10800 3600 604800 3600\n"),
			ContainerFilePath: "/etc/powerdns/pdns.d/10-it.conf", FileMode: 0o644}},
		WaitingFor: wait.ForListeningPort("8081/tcp").WithStartupTimeout(time.Minute),
	})
	insp, err := auth.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ep := insp.NetworkSettings.Networks[nw.Name]
	if ep == nil || !ep.IPAddress.IsValid() {
		t.Fatal("no authoritative container IP on the test network")
	}
	recYAML := `webservice:
  webserver: true
  address: 0.0.0.0
  port: 8082
  api_key: "` + recursorKey + `"
  api_dir: /tmp
  allow_from: ["0.0.0.0/0"]
incoming:
  allow_from: ["0.0.0.0/0"]
`
	rec := startContainer(t, testcontainers.ContainerRequest{
		Image: recursorImage, ExposedPorts: []string{"53/udp", "53/tcp", "8082/tcp"},
		Networks: []string{nw.Name},
		Files: []testcontainers.ContainerFile{{Reader: strings.NewReader(recYAML),
			ContainerFilePath: "/etc/powerdns/recursor.d/10-it.yml", FileMode: 0o644}},
		WaitingFor: wait.ForListeningPort("8082/tcp").WithStartupTimeout(time.Minute),
	})
	return powerDNS{
		authAPI: "http://" + endpoint(t, auth, "8081/tcp"), recursorAPI: "http://" + endpoint(t, rec, "8082/tcp"),
		authDNS: endpoint(t, auth, "53/udp"), recursorDNS: endpoint(t, rec, "53/udp"), authIP: ep.IPAddress.String(),
	}
}

// ---- fakes ----------------------------------------------------------------

type fakeIPAM struct {
	mu      sync.Mutex
	addrs   map[string]ipamsync.Address
	subnets map[string]ipamsync.Subnet
}

func (f *fakeIPAM) GetAddress(_ context.Context, _, id string) (ipamsync.Address, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.addrs[id]
	if !ok {
		return ipamsync.Address{}, ipamsync.ErrNotFound
	}
	return a, nil
}

func (f *fakeIPAM) GetSubnet(_ context.Context, _, id string) (ipamsync.Subnet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subnets[id]
	if !ok {
		return ipamsync.Subnet{}, ipamsync.ErrNotFound
	}
	return s, nil
}

func (f *fakeIPAM) set(a ipamsync.Address) {
	f.mu.Lock()
	f.addrs[a.ID] = a
	f.mu.Unlock()
}

func (f *fakeIPAM) remove(id string) {
	f.mu.Lock()
	delete(f.addrs, id)
	f.mu.Unlock()
}

// ---- DNS client -----------------------------------------------------------

func query(server, name string, qtype uint16) ([]dns.RR, int, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, 0, err
	}
	return r.Answer, r.Rcode, nil
}

func values(rrs []dns.RR, qtype uint16) []string {
	var out []string
	for _, rr := range rrs {
		if rr.Header().Rrtype != qtype {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		case *dns.PTR:
			out = append(out, v.Ptr)
		case *dns.TXT:
			out = append(out, strings.Join(v.Txt, ""))
		case *dns.SOA:
			out = append(out, v.Ns)
		case *dns.MX:
			out = append(out, fmt.Sprintf("%d %s", v.Preference, v.Mx))
		default:
			out = append(out, rr.String())
		}
	}
	return out
}

// eventually polls the server until the answer set of (name, qtype) matches
// want exactly (nil/empty want = no answer).
func eventually(t *testing.T, server, name string, qtype uint16, want ...string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got []string
	var lastErr error
	for time.Now().Before(deadline) {
		rrs, _, err := query(server, name, qtype)
		lastErr = err
		if err == nil {
			got = values(rrs, qtype)
			if same(got, want) {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s %s @%s = %v (err %v), want %v", name, dns.TypeToString[qtype], server, got, lastErr, want)
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x] == 0 {
			return false
		}
		seen[x]--
	}
	return true
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ---- the suite ------------------------------------------------------------

type env struct {
	pd      powerDNS
	db      *repodb.DB
	pdns    pdns.Client
	rec     recursor.Client
	pub     *events.Recorder
	zones   *zones.Service
	records *records.Service
	tpl     *templates.Service
	sm      *supermasters.Service
	acme    *acmechallenge.Service
	backup  *backup.Service
	ipam    *fakeIPAM
	bus     stream.Client
	syncer  *ipamsync.Syncer
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	dsn := startDB(t)
	vk := startContainer(t, testcontainers.ContainerRequest{
		Image: "valkey/valkey:8", ExposedPorts: []string{"6379/tcp"},
		WaitingFor: wait.ForListeningPort("6379/tcp").WithStartupTimeout(time.Minute),
	})
	pd := startPowerDNS(t)

	st, err := store.Open(ctx, dsn, 8)
	must(t, err)
	t.Cleanup(st.Close)
	e := &env{pd: pd, db: repodb.New(st), pub: &events.Recorder{},
		ipam: &fakeIPAM{addrs: map[string]ipamsync.Address{}, subnets: map[string]ipamsync.Subnet{}}}
	pc, err := pdns.New(pdns.Config{BaseURL: pd.authAPI, Key: func(context.Context) (string, error) { return authKey, nil }, Timeout: 10 * time.Second})
	must(t, err)
	e.pdns = pc
	rc, err := recursor.New(recursor.Config{BaseURL: pd.recursorAPI, Key: func(context.Context) (string, error) { return recursorKey, nil },
		ForwardHost: pd.authIP, ForwardPort: 53, Timeout: 10 * time.Second})
	must(t, err)
	e.rec = rc
	bus, err := valkeykv.New(valkeykv.Config{Addresses: []string{endpoint(t, vk, "6379/tcp")}, AllowPlaintext: true})
	must(t, err)
	t.Cleanup(bus.Close)
	e.bus = bus

	e.tpl = templates.New(templates.Deps{Store: e.db})
	e.zones = zones.New(zones.Deps{Store: e.db, PDNS: e.pdns, Recursor: e.rec, Events: e.pub, Templates: e.tpl})
	e.records = records.New(records.Deps{Zones: e.zones, PDNS: e.pdns, Events: e.pub})
	e.sm = supermasters.New(supermasters.Deps{Store: e.db, PDNS: e.pdns})
	e.acme = acmechallenge.New(acmechallenge.Deps{Zones: e.zones, Records: e.records, Store: e.db, AllowedCaller: lcmID})
	e.backup = backup.New(backup.Deps{Store: e.db, PDNS: e.pdns})
	e.syncer = ipamsync.New(ipamsync.Deps{Store: e.db, Zones: e.zones, Records: e.records, IPAM: e.ipam, TTL: 300})
	return e
}

func TestPowerDNSIntegration(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := authz.User(tenantA, "0190aaaa-0000-7000-8000-0000000000a1", nil)
	platform := authz.User(tenantA, "0190aaaa-0000-7000-8000-0000000000a2", []string{authz.RolePlatformAdmin})
	adminB := authz.User(tenantB, "0190bbbb-0000-7000-8000-0000000000b1", nil)

	// The recursor answers from the authoritative server only once the forward exists.
	var zone store.Zone
	t.Run("zone and records via auth and resolver", func(t *testing.T) {
		var err error
		zone, err = e.zones.Create(ctx, admin, zones.CreateInput{Name: "example.test", Kind: "native", Nameservers: []string{"ns1.example.test."}})
		must(t, err)
		if zone.Name != "example.test." || zone.PDNSID == "" {
			t.Fatalf("zone = %+v", zone)
		}
		eventually(t, e.pd.authDNS, "example.test.", dns.TypeSOA, "ns1.example.test.")
		_, err = e.records.Upsert(ctx, admin, zone.ID, validate.RecordSetInput{Name: "www", Type: "A", TTL: 60,
			Values: []validate.RecordValue{{Content: "192.0.2.10"}}})
		must(t, err)
		eventually(t, e.pd.authDNS, "www.example.test.", dns.TypeA, "192.0.2.10")
		eventually(t, e.pd.recursorDNS, "www.example.test.", dns.TypeA, "192.0.2.10")
		fwd, err := e.rec.ListForwards(ctx)
		must(t, err)
		if !contains(fwd, "example.test.") {
			t.Fatalf("no resolver forward for example.test.: %v", fwd)
		}
	})

	t.Run("record edit and delete", func(t *testing.T) {
		_, err := e.records.Update(ctx, admin, zone.ID, records.Key{Name: "www.example.test.", Type: "A"},
			validate.RecordSetInput{Name: "www", Type: "A", TTL: 60, Comment: "web front", Values: []validate.RecordValue{
				{Content: "192.0.2.11"}, {Content: "192.0.2.12", Disabled: true}}})
		must(t, err)
		eventually(t, e.pd.authDNS, "www.example.test.", dns.TypeA, "192.0.2.11")
		_, err = e.records.Upsert(ctx, admin, zone.ID, validate.RecordSetInput{Name: "gone", Type: "TXT", TTL: 60,
			Values: []validate.RecordValue{{Content: `"bye"`}}})
		must(t, err)
		eventually(t, e.pd.authDNS, "gone.example.test.", dns.TypeTXT, "bye")
		must(t, e.records.Delete(ctx, admin, zone.ID, records.Key{Name: "gone.example.test.", Type: "TXT"}))
		eventually(t, e.pd.authDNS, "gone.example.test.", dns.TypeTXT)
		// refused before PowerDNS
		if _, err := e.records.Upsert(ctx, admin, zone.ID, validate.RecordSetInput{Name: "bad", Type: "A", TTL: 60,
			Values: []validate.RecordValue{{Content: "999.1.1.1"}}}); err == nil {
			t.Fatal("invalid A accepted")
		}
	})

	t.Run("cross-tenant duplicate refusal", func(t *testing.T) {
		for _, name := range []string{"example.test", "sub.example.test"} {
			if _, err := e.zones.Create(ctx, adminB, zones.CreateInput{Name: name, Kind: "native", Nameservers: []string{"ns1.example.test."}}); !errors.Is(err, zones.ErrDuplicate) {
				t.Fatalf("tenant B %s: %v", name, err)
			}
		}
		if _, err := e.zones.Get(ctx, adminB, zone.ID); err == nil {
			t.Fatal("tenant B reads tenant A's zone")
		}
	})

	t.Run("template zone, export and notify", func(t *testing.T) {
		tpl, err := e.tpl.Create(ctx, admin, templates.Input{Name: "std", Records: []store.TemplateRecord{
			{Name: "@", Type: "MX", TTL: 300, Content: "mail.[ZONE].", Priority: 10},
			{Name: "@", Type: "TXT", TTL: 300, Content: `"v=spf1 mx -all"`},
			{Name: "mail", Type: "A", TTL: 300, Content: "192.0.2.25"}}})
		must(t, err)
		tz, err := e.zones.Create(ctx, admin, zones.CreateInput{Name: "tpl.test", Kind: "master", Nameservers: []string{"ns1.tpl.test."}, TemplateID: tpl.ID})
		must(t, err)
		eventually(t, e.pd.authDNS, "tpl.test.", dns.TypeMX, "10 mail.tpl.test.")
		eventually(t, e.pd.authDNS, "mail.tpl.test.", dns.TypeA, "192.0.2.25")
		ex, err := e.zones.Export(ctx, admin, tz.ID)
		must(t, err)
		if !strings.Contains(ex.Text, "mail.tpl.test.") || !strings.Contains(ex.Text, "SOA") {
			t.Fatalf("export text = %q", ex.Text)
		}
		must(t, e.zones.Notify(ctx, admin, tz.ID))
		if err := e.zones.Notify(ctx, admin, zone.ID); !errors.Is(err, zones.ErrInvalidKind) {
			t.Fatalf("NOTIFY of a native zone: %v", err)
		}
	})

	t.Run("supermaster on the server", func(t *testing.T) {
		sm, err := e.sm.Create(ctx, platform, supermasters.Input{IP: "192.0.2.53", Nameserver: "ns.primary.test."})
		must(t, err)
		live, err := e.pdns.ListSupermasters(ctx)
		must(t, err)
		if !strings.Contains(fmt.Sprint(live), "192.0.2.53") {
			t.Fatalf("PowerDNS supermasters = %+v", live)
		}
		if _, err := e.sm.Create(ctx, admin, supermasters.Input{IP: "192.0.2.54", Nameserver: "ns.primary.test."}); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("tenant admin created a supermaster: %v", err)
		}
		must(t, e.sm.Delete(ctx, platform, sm.ID))
	})

	t.Run("ipam sync over valkey", func(t *testing.T) {
		lab, err := e.zones.Create(ctx, admin, zones.CreateInput{Name: "lab.example.test", Kind: "native", Nameservers: []string{"ns1.example.test."}})
		must(t, err)
		_ = lab
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()
		cons := &ipamsync.Consumer{Reader: e.bus, Tenants: []string{tenantA}, Handle: func(ctx context.Context, tenant string, ev ipamsync.Event) error {
			err := e.syncer.Handle(ctx, tenant, ev)
			if err != nil {
				t.Logf("sync %s %s: %v", ev.Type, ev.ID, err)
			}
			return err
		}, OnDrop: func(r string) { t.Logf("dropped: %s", r) }, Block: 500 * time.Millisecond, RetryDelay: 200 * time.Millisecond}
		go cons.Run(cctx)
		deadline := time.Now().Add(10 * time.Second)
		for !cons.Started() && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if !cons.Started() {
			t.Fatal("consumer did not start")
		}
		e.ipam.subnets["0190cccc-0000-7000-8000-000000000001"] = ipamsync.Subnet{ID: "0190cccc-0000-7000-8000-000000000001", CIDR: "10.20.30.0/24"}
		e.ipam.subnets["0190cccc-0000-7000-8000-000000000002"] = ipamsync.Subnet{ID: "0190cccc-0000-7000-8000-000000000002", CIDR: "2001:db8:1:2::/64"}
		v4 := ipamsync.Address{ID: "0190dddd-0000-7000-8000-000000000001", Address: "10.20.30.40", SubnetID: "0190cccc-0000-7000-8000-000000000001", Hostname: "srv1.lab.example.test"}
		v6 := ipamsync.Address{ID: "0190dddd-0000-7000-8000-000000000002", Address: "2001:db8:1:2::40", SubnetID: "0190cccc-0000-7000-8000-000000000002", Hostname: "v6.lab.example.test"}
		publish := func(typ string, a ipamsync.Address) {
			data, _ := json.Marshal(map[string]string{"action": strings.TrimPrefix(typ, "ipam.ip_address."), "id": a.ID, "address": a.Address,
				"subnet_id": a.SubnetID, "hostname": a.Hostname})
			_, err := e.bus.XAdd(ctx, stream.Key(tenantA), map[string]string{"type": typ, "to": "*",
				"at": fmt.Sprint(time.Now().UnixMilli()), "data": string(data)}, 1000)
			must(t, err)
		}
		e.ipam.set(v4)
		e.ipam.set(v6)
		publish("ipam.ip_address.created", v4)
		publish("ipam.ip_address.created", v6)
		eventually(t, e.pd.authDNS, "srv1.lab.example.test.", dns.TypeA, "10.20.30.40")
		eventually(t, e.pd.authDNS, "40.30.20.10.in-addr.arpa.", dns.TypePTR, "srv1.lab.example.test.")
		eventually(t, e.pd.authDNS, "v6.lab.example.test.", dns.TypeAAAA, "2001:db8:1:2::40")
		ptr6, _ := dns.ReverseAddr("2001:db8:1:2::40")
		eventually(t, e.pd.authDNS, ptr6, dns.TypePTR, "v6.lab.example.test.")
		eventually(t, e.pd.recursorDNS, "srv1.lab.example.test.", dns.TypeA, "10.20.30.40")

		// rename, then release
		v4.Hostname = "srv2.lab.example.test"
		e.ipam.set(v4)
		publish("ipam.ip_address.updated", v4)
		eventually(t, e.pd.authDNS, "srv2.lab.example.test.", dns.TypeA, "10.20.30.40")
		eventually(t, e.pd.authDNS, "srv1.lab.example.test.", dns.TypeA)
		eventually(t, e.pd.authDNS, "40.30.20.10.in-addr.arpa.", dns.TypePTR, "srv2.lab.example.test.")
		e.ipam.remove(v4.ID)
		publish("ipam.ip_address.deleted", v4)
		eventually(t, e.pd.authDNS, "srv2.lab.example.test.", dns.TypeA)
		eventually(t, e.pd.authDNS, "40.30.20.10.in-addr.arpa.", dns.TypePTR)
		// a forged event for an address IPAM does not know writes nothing
		publish("ipam.ip_address.created", ipamsync.Address{ID: "0190dddd-0000-7000-8000-00000000ffff", Address: "10.20.30.99",
			SubnetID: "0190cccc-0000-7000-8000-000000000001", Hostname: "forged.lab.example.test"})
		time.Sleep(2 * time.Second)
		if rrs, _, _ := query(e.pd.authDNS, "forged.lab.example.test.", dns.TypeA); len(values(rrs, dns.TypeA)) != 0 {
			t.Fatal("forged event wrote a record")
		}
	})

	t.Run("acme challenge present and cleanup", func(t *testing.T) {
		lcm := authz.Module(tenantA, lcmID)
		value := strings.Repeat("a", 43)
		req := acmechallenge.Request{Domain: "app.example.test", FQDN: "_acme-challenge.app.example.test", Value: value}
		z, err := e.acme.Present(ctx, lcm, req)
		must(t, err)
		if z != "example.test." {
			t.Fatalf("challenge zone = %q", z)
		}
		eventually(t, e.pd.authDNS, "_acme-challenge.app.example.test.", dns.TypeTXT, value)
		eventually(t, e.pd.recursorDNS, "_acme-challenge.app.example.test.", dns.TypeTXT, value)
		_, err = e.acme.CleanUp(ctx, lcm, req)
		must(t, err)
		eventually(t, e.pd.authDNS, "_acme-challenge.app.example.test.", dns.TypeTXT)
		// another module is refused, nothing written
		if _, err := e.acme.Present(ctx, authz.Module(tenantA, "spiffe://example.org/svc/deployer"), req); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("non-lcm caller: %v", err)
		}
		if _, err := e.acme.Present(ctx, lcm, acmechallenge.Request{Domain: "app.unhosted.test", FQDN: "_acme-challenge.app.unhosted.test", Value: value}); err == nil {
			t.Fatal("challenge for an unhosted name accepted")
		}
	})

	t.Run("config render and file write", func(t *testing.T) {
		dir := t.TempDir()
		fake := dnsconf.NewFake(true)
		svc := dnsconf.New(dnsconf.ServiceDeps{Store: e.db, Restarter: fake,
			RecursorPath: filepath.Join(dir, "50-freya.yml"), AuthPath: filepath.Join(dir, "50-freya.conf")})
		m := dnsconf.Defaults()
		m.Recursor.AllowedNetworks = append(m.Recursor.AllowedNetworks, "100.64.0.0/10")
		res, err := svc.Update(ctx, platform, m)
		must(t, err)
		if !strings.Contains(strings.Join(res.Restarted, ","), "freya-pdns-recursor") {
			t.Fatalf("restarted = %v", res.Restarted)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "50-freya.yml"))
		must(t, err)
		if !strings.Contains(string(raw), "100.64.0.0/10") || !strings.Contains(string(raw), "Managed by Freya DNS") {
			t.Fatalf("recursor file = %s", raw)
		}
		if _, err := os.Stat(filepath.Join(dir, "50-freya.conf")); err != nil {
			t.Fatalf("auth file not written: %v", err)
		}
		res, err = svc.Update(ctx, platform, m)
		must(t, err)
		if len(res.Restarted) != 0 {
			t.Fatalf("unchanged save restarted %v", res.Restarted)
		}
		if _, err := svc.Update(ctx, admin, m); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("tenant admin saved the configuration: %v", err)
		}
	})

	t.Run("backup export and relink", func(t *testing.T) {
		b, err := e.backup.Export(ctx, admin, "")
		must(t, err)
		if len(b.Zones) < 3 || len(b.Templates) != 1 {
			t.Fatalf("export: %d zones %d templates", len(b.Zones), len(b.Templates))
		}
		raw, _ := json.Marshal(b)
		if strings.Contains(string(raw), authKey) || strings.Contains(string(raw), recursorKey) {
			t.Fatal("backup carries an API key")
		}
		// the local row of tpl.test vanishes; PowerDNS still serves it
		tz, err := e.db.GetZoneByName(ctx, tenantA, "tpl.test.")
		must(t, err)
		must(t, e.db.DeleteZone(ctx, tenantA, tz.ID))
		res, err := e.backup.Import(ctx, admin, b, backup.Options{})
		must(t, err)
		if res.Imported[backup.CZones] != 1 || len(res.MissingInPDNS) != 0 {
			t.Fatalf("import = %+v", res)
		}
		back, err := e.db.GetZoneByName(ctx, tenantA, "tpl.test.")
		must(t, err)
		if back.PDNSID == "" || back.Kind != store.KindMaster {
			t.Fatalf("relinked = %+v", back)
		}
		// tenant B importing A's document adopts nothing
		res, err = e.backup.Import(ctx, adminB, b, backup.Options{})
		must(t, err)
		if res.Imported[backup.CZones] != 0 {
			t.Fatalf("tenant B adopted zones: %+v", res)
		}
	})

	t.Run("zone delete removes server data and forward", func(t *testing.T) {
		must(t, e.zones.Delete(ctx, admin, zone.ID))
		eventually(t, e.pd.authDNS, "www.example.test.", dns.TypeA)
		fwd, err := e.rec.ListForwards(ctx)
		must(t, err)
		for _, f := range fwd {
			if f == "example.test." {
				t.Fatalf("forward left behind: %v", fwd)
			}
		}
	})
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
