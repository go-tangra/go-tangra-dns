package app

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/go-freya/freya"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/config"
	"github.com/go-freya/freya/services/dns/internal/dashboard"
	"github.com/go-freya/freya/services/dns/internal/dnsconf"
	"github.com/go-freya/freya/services/dns/internal/ipamsync"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/recursor"
	"github.com/go-freya/freya/services/dns/internal/secrets"
	"github.com/go-freya/freya/services/dns/internal/stream"
)

const (
	appTenant = "11111111-1111-7111-8111-111111111111"
	apiKey    = "pdns-app-test-key"
)

type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	switch token {
	case "viewer":
		return authclient.Identity{UserID: "u1", TenantID: appTenant}, nil
	case "owner":
		return authclient.Identity{UserID: "u2", TenantID: appTenant, Roles: []string{"owner"}}, nil
	case "platform":
		return authclient.Identity{UserID: "u3", TenantID: appTenant, Roles: []string{authz.RolePlatformAdmin}}, nil
	}
	return authclient.Identity{}, errors.New("unauthenticated")
}

func testConfig() config.Config {
	c := config.Default()
	c.ServiceName, c.TrustDomain, c.Env = "dns", "example.org", "dev"
	c.DB.DSN = "postgres://unused"
	c.Valkey.Addresses, c.Valkey.AllowPlaintext = []string{"127.0.0.1:1"}, true
	c.Server.GRPCAddr, c.Server.HTTPAddr, c.Admin.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	c.Discovery.Static = map[string][]string{"lcm": {"127.0.0.1:1"}, "auth": {"127.0.0.1:1"}, "gateway": {"127.0.0.1:1"}, "warden": {"127.0.0.1:1"}}
	c.PDNS.APIURL, c.PDNS.APIKeyRef, c.PDNS.AllowPlaintext = "http://127.0.0.1:1", "warden:pdns", true
	c.Gateway.Service, c.Gateway.Issuer = "gateway", "https://localhost:8443"
	return c
}

func options() Options {
	return Options{
		KEK: make([]byte, 32), Verifier: fakeVerifier{},
		Checker: authz.Static{"u1": {authz.ZonesRead}, "u2": {authz.ZonesRead, authz.ZonesManage, authz.ConfigManage, authz.DashboardRead},
			"u3": {authz.ConfigManage}},
		Repo: memstore.New(), Secrets: &secrets.Fake{PDNS: apiKey, Recursor: "rec-key"},
		Stream: stream.NewMemory(), PDNS: pdns.NewFake(), Recursor: recursor.NewFake(),
		Freya: []freya.Option{freya.WithInsecureLocalDev(), freya.WithAllowAllPolicy()},
	}
}

func TestBuildWiresTheService(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer a.Close()
	if a.Freya == nil || a.Repo == nil || a.Env == nil || a.HTTP == nil || a.Hub == nil || a.Audit == nil ||
		a.Metrics == nil || a.Secrets == nil || a.Events == nil || a.PDNS == nil || a.Recursor == nil || a.Checker == nil {
		t.Fatalf("app not fully wired: %+v", a)
	}
	do := func(path, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://localhost"+path, nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		a.HTTP.Handler().ServeHTTP(w, r)
		return w
	}
	w := do("/api/dns/v1/health", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pdns":"ok"`) || !strings.Contains(w.Body.String(), `"recursor":"ok"`) ||
		!strings.Contains(w.Body.String(), `"status":"ok"`) || strings.Contains(w.Body.String(), apiKey) {
		t.Fatalf("health: %d %s", w.Code, w.Body)
	}
	if w := do("/api/dns/v1/zones", ""); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := do("/api/dns/v1/zones", "viewer"); w.Code != 200 || !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatalf("zones (US1): %d %s", w.Code, w.Body)
	}
	if w := do("/api/dns/v1/templates", "viewer"); w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) {
		t.Fatalf("templates (US3): %d %s", w.Code, w.Body)
	}
	// US6: dashboard:read is required; without a metrics URL it is unavailable.
	if w := do("/api/dns/v1/dashboard", "viewer"); w.Code != 403 {
		t.Fatalf("dashboard without permission: %d %s", w.Code, w.Body)
	}
	if w := do("/api/dns/v1/dashboard?window=6h", "owner"); w.Code != 200 || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatalf("dashboard (US6): %d %s", w.Code, w.Body)
	}
	// US5: config:manage alone is not enough for a tenant owner (platform-admin).
	if w := do("/api/dns/v1/config", "viewer"); w.Code != 403 {
		t.Fatalf("permission not enforced: %d", w.Code)
	}
	if w := do("/api/dns/v1/config", "owner"); w.Code != 403 {
		t.Fatalf("tenant owner reached the configuration: %d", w.Code)
	}
	if w := do("/api/dns/v1/config", "platform"); w.Code != 200 || !strings.Contains(w.Body.String(), `"defaults":true`) ||
		!strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("config (US5): %d %s", w.Code, w.Body)
	}
	if a.Challenges == nil || a.Config == nil || a.Dashboard == nil {
		t.Fatal("US4-US6 services not wired")
	}
	// The module's instruments render on the framework's metrics handler.
	a.Metrics.PDNSCall("GetZone", "ok", time.Millisecond)
	rec := httptest.NewRecorder()
	a.Freya.Metrics().Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `dns_pdns_calls_total{op="GetZone",result="ok"} 1`) {
		t.Fatalf("module metrics not exposed:\n%s", rec.Body)
	}
	// Degraded components are reported without error text.
	a.PDNS.(*pdns.Fake).SetDown(true)
	a.Recursor.(*recursor.Fake).SetReady(false)
	a.Secrets = &secrets.Fake{}
	w = do("/api/dns/v1/health", "")
	for _, want := range []string{`"pdns":"unreachable"`, `"recursor":"unreachable"`, `"pdns_api_key":"unavailable"`, `"degraded"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("degraded health lacks %s: %s", want, w.Body)
		}
	}
	a.Close()
	a.Close() // idempotent
}

func TestBuildDefaultsAndRefusals(t *testing.T) {
	// Default clients: a real PowerDNS client over config and a disabled recursor.
	o := options()
	o.PDNS, o.Recursor = nil, nil
	a, err := Build(context.Background(), testConfig(), o)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := a.PDNS.(*pdns.HTTPClient); !ok || a.Recursor.Enabled() {
		t.Fatalf("default clients: %T enabled=%v", a.PDNS, a.Recursor.Enabled())
	}
	if w := a.health(); w["recursor"] != "" || w["pdns"] != "unreachable" {
		t.Fatalf("health = %v", w)
	}
	a.Close()

	c := testConfig()
	c.Recursor.APIURL, c.Recursor.APIKeyRef = "http://127.0.0.1:1", "warden:rec"
	a, err = Build(context.Background(), c, o)
	if err != nil || !a.Recursor.Enabled() {
		t.Fatalf("recursor client: %v", err)
	}
	a.Close()

	for name, mut := range map[string]func(*config.Config, *Options){
		"bad kek":      func(_ *config.Config, o *Options) { o.KEK = []byte("short") },
		"no pdns url":  func(c *config.Config, o *Options) { c.PDNS.APIURL, o.PDNS = "", nil },
		"bad recursor": func(c *config.Config, o *Options) { c.Recursor.APIURL, o.Recursor = "ftp://x", nil },
		"bad kek source": func(c *config.Config, o *Options) {
			o.KEK = nil
			c.KEK = config.KEK{Source: "file", Path: "/nonexistent/kek"}
		},
		"no enroll token": func(c *config.Config, _ *Options) {
			c.MeshEnroll.Enabled, c.MeshEnroll.TokenFile = true, "/nonexistent/token"
		},
		"bad docker": func(c *config.Config, _ *Options) {
			c.Docker.Enabled, c.Docker.AuthContainer = true, "../x"
		},
		"bad metrics url": func(c *config.Config, _ *Options) { c.Metrics.PrometheusURL = "ftp://prom" },
	} {
		c, o := testConfig(), options()
		mut(&c, &o)
		if _, err := Build(context.Background(), c, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunStartsWorkersAndStops(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer a.Close()
	var ran atomic.Bool
	stopped := make(chan struct{})
	a.AddWorker("probe", func(ctx context.Context) {
		ran.Store(true)
		<-ctx.Done()
		close(stopped)
	})
	// US1 registers the recursor reconciler, US4 the challenge sweeper and
	// US5 the start-up configuration re-apply.
	if w := a.Workers(); len(w) != 4 || w[0].Name != "recursor-reconciler" || w[1].Name != "acme-sweeper" || w[2].Name != "config-reapply" || w[3].Name != "probe" {
		t.Fatalf("workers = %+v", a.Workers())
	}
	if a.Zones == nil || a.Records == nil || a.Recon == nil || a.Tpl == nil || a.Masters == nil {
		t.Fatal("US1/US3 services not wired")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for !ran.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !ran.Load() {
		t.Fatal("worker not started")
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("worker not stopped")
	}
}

type fakeAuthz struct {
	authv1.AuthorizationClient
	allow bool
	err   error
	got   *authv1.CheckRequest
}

func (f *fakeAuthz) Check(_ context.Context, in *authv1.CheckRequest, _ ...grpc.CallOption) (*authv1.CheckResponse, error) {
	f.got = in
	if f.err != nil {
		return nil, f.err
	}
	return &authv1.CheckResponse{Allowed: f.allow}, nil
}

func TestAuthPerms(t *testing.T) {
	f := &fakeAuthz{allow: true}
	p := AuthPerms{Client: f}
	if !p.Has(context.Background(), appTenant, "u1", authz.ZonesManage) || f.got.GetResource() != "zones" || f.got.GetAction() != "manage" {
		t.Fatalf("check = %+v", f.got)
	}
	f.allow = false
	if p.Has(context.Background(), appTenant, "u1", authz.ZonesRead) {
		t.Fatal("denied allowed")
	}
	f.err = errors.New("down")
	if p.Has(context.Background(), appTenant, "u1", authz.ZonesRead) {
		t.Fatal("error must be a no")
	}
	if (AuthPerms{}).Has(context.Background(), appTenant, "u1", authz.ZonesRead) || p.Has(context.Background(), appTenant, "u1", "bogus") {
		t.Fatal("nil client / malformed permission")
	}
}

func TestLazyWardenUnavailable(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	l := &lazyWarden{app: a}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := l.Fetch(ctx, "x"); err == nil {
		t.Fatal("unreachable warden returned a value")
	}
}

type appIPAM struct{}

func (appIPAM) GetAddress(_ context.Context, _, id string) (ipamsync.Address, error) {
	return ipamsync.Address{ID: id, Address: "192.0.2.10", Hostname: "web.example.com"}, nil
}

func (appIPAM) GetSubnet(context.Context, string, string) (ipamsync.Subnet, error) {
	return ipamsync.Subnet{}, errors.New("no subnet")
}

// US2: with ipam_sync enabled the consumer worker is registered and an
// address event on the bus ends up as records in PowerDNS.
func TestIPAMSyncWorker(t *testing.T) {
	c, o := testConfig(), options()
	c.IPAMSync.Enabled, c.IPAMSync.Tenants = true, []string{appTenant}
	o.IPAM = appIPAM{}
	bus := stream.NewMemory()
	o.Stream = bus
	pd := pdns.NewFake()
	o.PDNS = pd
	a, err := Build(context.Background(), c, o)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer a.Close()
	var sync *Worker
	for _, w := range a.Workers() {
		if w.Name == "ipam-sync" {
			w := w
			sync = &w
		}
	}
	if sync == nil || a.Sync == nil {
		t.Fatalf("ipam-sync worker missing: %+v", a.Workers())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sync.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = bus.XAdd(ctx, stream.Key(appTenant), map[string]string{"type": ipamsync.TypeCreated,
			"data": `{"id":"0190f7c2-0000-7000-8000-00000000a001","address":"192.0.2.10"}`}, 0)
		if z, err := pd.GetZone(ctx, "example.com."); err == nil && len(z.RRsets) > 0 {
			for _, r := range z.RRsets {
				if r.Name == "web.example.com." && r.Type == "A" {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("IPAM event not applied")
}

func TestLazyIPAMUnavailable(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	l := &lazyIPAM{app: a, service: "ipam-missing"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := l.GetAddress(ctx, appTenant, "x"); err == nil {
		t.Fatal("no error without discovery entry")
	}
	if _, err := l.GetSubnet(ctx, appTenant, "x"); err == nil {
		t.Fatal("no error without discovery entry")
	}
}

func TestOperationsWiring(t *testing.T) {
	o := options()
	o.Restarter = dnsconf.NewFake(true)
	o.Metrics = dashboard.NewFake()
	c := testConfig()
	c.Metrics.PrometheusURL = "http://127.0.0.1:1"
	a, err := Build(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r := httptest.NewRequest("GET", "https://localhost/api/dns/v1/config", nil)
	r.Header.Set("Authorization", "Bearer platform")
	w := httptest.NewRecorder()
	a.HTTP.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("config with a restarter: %d %s", w.Code, w.Body)
	}
	// The default Prometheus client is built from the configured URL.
	o.Metrics = nil
	a2, err := Build(context.Background(), c, o)
	if err != nil {
		t.Fatal(err)
	}
	a2.Close()
}
