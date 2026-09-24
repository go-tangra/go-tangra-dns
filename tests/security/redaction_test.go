// Package security holds the cross-cutting security tests of the DNS module.
package security

// T100 (SR-002, SC-007): the PowerDNS Authoritative and Recursor API keys never
// leave the HTTP clients. Every service path — zones, records, templates,
// supermasters, configuration (with a fake restarter and a resolver
// re-sync), dashboard, ACME challenges over dns.v1 gRPC and the IPAM sync — is
// driven through the real pdns/recursor HTTP clients (keys resolved from dev
// file: secret references) against stub servers that first behave and then
// turn hostile: every hostile reply echoes the X-API-Key it received in its
// error body, including one where the key straddles the truncation boundary.
// The sentinels must never appear in captured slog output, audit events,
// published events, HTTP responses, gRPC responses or returned error strings.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/go-tangra/go-tangra/v4/identity"

	dnsv1 "github.com/go-tangra/go-tangra-dns/v4/api/proto/dns/v1"
	"github.com/go-tangra/go-tangra-dns/v4/internal/acmechallenge"
	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dashboard"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dnsconf"
	"github.com/go-tangra/go-tangra-dns/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-dns/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-dns/v4/internal/ipamsync"
	"github.com/go-tangra/go-tangra-dns/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/records"
	"github.com/go-tangra/go-tangra-dns/v4/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-dns/v4/internal/supermasters"
	"github.com/go-tangra/go-tangra-dns/v4/internal/templates"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

const (
	authKey  = "DNS-MARKER-KEY-auth-7f3c9a1e"
	recKey   = "DNS-MARKER-KEY-recursor-51b2e0d4"
	marker   = "MARKER-KEY" // any fragment of either key
	tenant   = "11111111-1111-7111-8111-111111111111"
	platform = "33333333-3333-7333-8333-333333333333"
	lcmID    = "spiffe://example.org/svc/lcm"
	sub4     = "0198a0c0-0000-7000-8000-000000000004"
	addr1    = "0198a0c0-0000-7000-8000-0000000000a1"
	p        = "/api/dns/v1"
)

// leakFree fails when s carries any part of a sentinel key.
func leakFree(t *testing.T, where, s string) {
	t.Helper()
	for _, k := range []string{marker, authKey[len(authKey)-8:], recKey[len(recKey)-8:]} {
		if strings.Contains(s, k) {
			t.Errorf("%s leaks an API key: %s", where, s)
			return
		}
	}
}

// ---- capture sinks

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type auditCap struct {
	mu sync.Mutex
	ev []audit.Event
}

func (a *auditCap) Record(_ context.Context, e audit.Event) error {
	if err := audit.Validate(e); err != nil {
		return err
	}
	a.mu.Lock()
	a.ev = append(a.ev, e)
	a.mu.Unlock()
	return nil
}

func (a *auditCap) dump() (string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, _ := json.Marshal(a.ev)
	return string(raw), len(a.ev)
}

type eventCap struct {
	mu  sync.Mutex
	evs []any
}

func (e *eventCap) Publish(_ context.Context, tenantID, eventType string, payload any) {
	e.mu.Lock()
	e.evs = append(e.evs, map[string]any{"tenant": tenantID, "type": eventType, "payload": payload})
	e.mu.Unlock()
}

func (e *eventCap) dump() (string, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	raw, _ := json.Marshal(e.evs)
	return string(raw), len(e.evs)
}

// ---- stub servers

// hostile replies echo the received key: PowerDNS-style JSON errors with the
// key in the message, a plain-text body, and a padded body whose key crosses
// the client's truncation limit.
func hostile(w http.ResponseWriter, r *http.Request, key string, n int64) {
	switch n % 4 {
	case 0:
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `{"error":"backend failure for X-API-Key: %s"}`, key)
	case 1:
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = fmt.Fprintf(w, `{"error":"rejected","errors":["key %s is not allowed on %s"]}`, key, r.URL.Path)
	case 2:
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(w, "already exists (auth %s)\n\x00%s", key, key)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, `{"error":"%s%s"}`, strings.Repeat("x", pdns.MaxErrorMessage-8), key)
	}
}

// pdnsStub serves the PowerDNS Authoritative API over a pdns.Fake; it checks
// the key on every call and, when turned hostile, fails every call echoing it.
type pdnsStub struct {
	f       *pdns.Fake
	hostile atomic.Bool
	n       atomic.Int64
	badKey  atomic.Int64
}

func (s *pdnsStub) fail(w http.ResponseWriter, err error) {
	code := http.StatusUnprocessableEntity
	switch {
	case errors.Is(err, pdns.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, pdns.ErrConflict):
		code = http.StatusConflict
	}
	w.WriteHeader(code)
	// Even the "honest" errors carry the key, as a misconfigured proxy might.
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error() + " [api-key " + authKey + "]"})
}

func (s *pdnsStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-API-Key")
	if key != authKey {
		s.badKey.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if s.hostile.Load() {
		hostile(w, r, key, s.n.Add(1))
		return
	}
	ctx := r.Context()
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/api/v1/servers/localhost")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	seg := strings.Split(strings.Trim(rest, "/"), "/")
	for i := range seg {
		seg[i], _ = url.PathUnescape(seg[i])
	}
	reply := func(code int, v any, err error) {
		if err != nil {
			s.fail(w, err)
			return
		}
		if v == nil {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case rest == "" || rest == "/":
		reply(200, map[string]string{"id": "localhost"}, nil)
	case seg[0] == "zones" && len(seg) == 1 && r.Method == http.MethodGet:
		names, err := s.f.ListZoneNames(ctx)
		refs := []map[string]string{}
		for _, n := range names {
			refs = append(refs, map[string]string{"id": n, "name": n})
		}
		reply(200, refs, err)
	case seg[0] == "zones" && len(seg) == 1 && r.Method == http.MethodPost:
		var z pdns.Zone
		_ = json.NewDecoder(r.Body).Decode(&z)
		out, err := s.f.CreateZone(ctx, z)
		reply(201, out, err)
	case seg[0] == "zones" && len(seg) == 2:
		id := seg[1]
		switch r.Method {
		case http.MethodGet:
			z, err := s.f.GetZone(ctx, id)
			reply(200, z, err)
		case http.MethodPut:
			var z pdns.Zone
			_ = json.NewDecoder(r.Body).Decode(&z)
			reply(204, nil, s.f.UpdateZoneMetadata(ctx, id, z))
		case http.MethodDelete:
			reply(204, nil, s.f.DeleteZone(ctx, id))
		case http.MethodPatch:
			var body struct {
				RRsets []pdns.RRset `json:"rrsets"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			reply(204, nil, s.f.PatchRRsets(ctx, id, body.RRsets))
		}
	case seg[0] == "zones" && len(seg) == 3 && seg[2] == "notify":
		reply(200, map[string]string{"result": "Notification queued"}, s.f.NotifyZone(ctx, seg[1]))
	case seg[0] == "zones" && len(seg) == 3 && seg[2] == "export":
		txt, err := s.f.ExportZone(ctx, seg[1])
		if err != nil {
			s.fail(w, err)
			return
		}
		_, _ = io.WriteString(w, txt)
	case seg[0] == "autoprimaries" && len(seg) == 1 && r.Method == http.MethodGet:
		out, err := s.f.ListSupermasters(ctx)
		reply(200, out, err)
	case seg[0] == "autoprimaries" && len(seg) == 1 && r.Method == http.MethodPost:
		var sm pdns.Supermaster
		_ = json.NewDecoder(r.Body).Decode(&sm)
		reply(201, nil, s.f.CreateSupermaster(ctx, sm))
	case seg[0] == "autoprimaries" && len(seg) == 3 && r.Method == http.MethodDelete:
		reply(204, nil, s.f.DeleteSupermaster(ctx, seg[1], seg[2]))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// recStub serves the PowerDNS Recursor zones API (forward zones in a map).
type recStub struct {
	mu      sync.Mutex
	fwd     map[string]bool
	hostile atomic.Bool
	n       atomic.Int64
	badKey  atomic.Int64
}

func (s *recStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-API-Key")
	if key != recKey {
		s.badKey.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if s.hostile.Load() {
		hostile(w, r, key, s.n.Add(1))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	const zp = "/api/v1/servers/localhost/zones"
	switch {
	case r.URL.Path == "/api/v1/servers/localhost":
		_, _ = io.WriteString(w, `{"id":"localhost"}`)
	case r.URL.Path == zp && r.Method == http.MethodGet:
		out := []map[string]string{}
		for n := range s.fwd {
			out = append(out, map[string]string{"name": n, "kind": "Forwarded"})
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.URL.Path == zp && r.Method == http.MethodPost:
		var z struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&z)
		s.fwd[z.Name] = true
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(r.URL.Path, zp+"/") && r.Method == http.MethodDelete:
		name := strings.TrimPrefix(r.URL.Path, zp+"/")
		if !s.fwd[name] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, `{"error":"no zone %s (key %s)"}`, name, key)
			return
		}
		delete(s.fwd, name)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// ---- IPAM double

type fakeIPAM struct{ addrs map[string]ipamsync.Address }

func (f *fakeIPAM) GetAddress(_ context.Context, _, id string) (ipamsync.Address, error) {
	a, ok := f.addrs[id]
	if !ok {
		return ipamsync.Address{}, ipamsync.ErrNotFound
	}
	return a, nil
}

func (f *fakeIPAM) GetSubnet(_ context.Context, _, id string) (ipamsync.Subnet, error) {
	return ipamsync.Subnet{ID: id, CIDR: "192.0.2.0/24"}, nil
}

// ---- harness

type verifier map[string]authclient.Identity

func (v verifier) Verify(_ context.Context, tok string) (authclient.Identity, error) {
	if id, ok := v[tok]; ok {
		return id, nil
	}
	return authclient.Identity{}, errors.New("unauthenticated")
}

type world struct {
	t      *testing.T
	logs   *syncBuf
	aud    *auditCap
	pub    *eventCap
	pd     *pdnsStub
	rec    *recStub
	api    *httpapi.Server
	zs     *zones.Service
	sync   *ipamsync.Syncer
	ipam   *fakeIPAM
	grpc   dnsv1.ChallengesClient
	errs   []string // every error string a service or gRPC call returned
	bodies []string // every HTTP response
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	authFile, recFile := filepath.Join(dir, "pdns-api-key"), filepath.Join(dir, "recursor-api-key")
	if err := os.WriteFile(authFile, []byte(authKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recFile, []byte(recKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"recursor.d", "pdns.d"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	w := &world{t: t, logs: &syncBuf{}, aud: &auditCap{}, pub: &eventCap{},
		pd: &pdnsStub{f: pdns.NewFake()}, rec: &recStub{fwd: map[string]bool{}},
		ipam: &fakeIPAM{addrs: map[string]ipamsync.Address{}}}
	log := slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	pdSrv, recSrv := httptest.NewServer(w.pd), httptest.NewServer(w.rec)
	t.Cleanup(pdSrv.Close)
	t.Cleanup(recSrv.Close)

	src := secrets.NewCached(secrets.Resolver{AllowFile: true}, "file:"+authFile, "file:"+recFile, time.Minute)
	pc, err := pdns.New(pdns.Config{BaseURL: pdSrv.URL, Key: src.PDNSAPIKey, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rc, err := recursor.New(recursor.Config{BaseURL: recSrv.URL, Key: src.RecursorAPIKey, ForwardHost: "127.0.0.1", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	all := []string{}
	all = append(all, authz.Permissions...)
	checker := authz.Static{platform: all}
	tpl := templates.New(templates.Deps{Store: st, Audit: w.aud, Checker: checker, Log: log})
	w.zs = zones.New(zones.Deps{Store: st, PDNS: pc, Recursor: rc, Events: w.pub, Audit: w.aud, Checker: checker, Templates: tpl, Log: log})
	rs := records.New(records.Deps{Zones: w.zs, PDNS: pc, Events: w.pub, Audit: w.aud, Log: log})
	sm := supermasters.New(supermasters.Deps{Store: st, PDNS: pc, Audit: w.aud, Checker: checker, Log: log})
	rcn := &recursor.Reconciler{Client: rc, Names: st.AllZoneNames, ReadyAttempts: 2, ReadyDelay: time.Millisecond, Log: log}
	cfg := dnsconf.New(dnsconf.ServiceDeps{Store: st, Restarter: dnsconf.NewFake(true), Reconcile: rcn.ReconcileNow,
		Checker: checker, Audit: w.aud, Log: log,
		RecursorPath: filepath.Join(dir, "recursor.d", "freya.yml"), AuthPath: filepath.Join(dir, "pdns.d", "freya.conf")})
	dash := dashboard.New(dashboard.Deps{Client: dashboard.NewFake(), Checker: checker, Log: log})
	ch := acmechallenge.New(acmechallenge.Deps{Zones: w.zs, Records: rs, Store: st, Audit: w.aud, AllowedCaller: lcmID, Log: log})
	w.sync = ipamsync.New(ipamsync.Deps{Store: st, Zones: w.zs, Records: rs, IPAM: w.ipam, Audit: w.aud, Log: log})

	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := verifier{"platform": {UserID: platform, TenantID: tenant, Roles: []string{authz.RolePlatformAdmin}}}
	w.api, err = httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(checker), httpapi.WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	w.api.Register(httpapi.Deps{
		Health: func() map[string]string {
			out := map[string]string{"pdns": "ok", "recursor": "ok"}
			if err := pc.Ping(context.Background()); err != nil {
				out["pdns"] = err.Error()
			}
			if err := rc.Ready(context.Background()); err != nil {
				out["recursor"] = err.Error()
			}
			return out
		},
		Zones: w.zs, Records: rs, Templates: tpl, Supermasters: sm, Config: cfg, Dashboard: dash,
	})

	// dns.v1 over a real gRPC server; the interceptor stands in for the mTLS
	// authn middleware by placing the verified lcm peer.
	lcm, _ := identity.ParseSPIFFEID(lcmID)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		return h(authn.WithPeer(ctx, authn.PeerIdentity{ID: lcm, ServiceName: "lcm"}), req)
	}))
	grpcapi.Register(gs, grpcapi.Deps{AllowedChallengeCaller: lcmID, Zones: w.zs, Challenges: ch})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	w.grpc = dnsv1.NewChallengesClient(conn)
	return w
}

func (w *world) do(method, path, body string) (int, string) {
	w.t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer platform")
	if method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", "csrf")
	}
	rec := httptest.NewRecorder()
	w.api.Handler().ServeHTTP(rec, r)
	out := rec.Body.String()
	w.bodies = append(w.bodies, method+" "+path+" -> "+out)
	for k, vs := range rec.Header() {
		w.bodies = append(w.bodies, k+": "+strings.Join(vs, ","))
	}
	return rec.Code, out
}

func (w *world) id(code int, body string) string {
	w.t.Helper()
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil || v.ID == "" {
		w.t.Fatalf("no id (%d): %s", code, body)
	}
	return v.ID
}

func (w *world) grpcCalls(domain string) {
	ctx := context.Background()
	req := &dnsv1.ChallengeRequest{TenantId: tenant, Domain: domain, Fqdn: "_acme-challenge." + domain, Value: strings.Repeat("a", 43)}
	for _, f := range []func(context.Context, *dnsv1.ChallengeRequest, ...grpc.CallOption) (*dnsv1.ChallengeResponse, error){w.grpc.Present, w.grpc.CleanUp} {
		resp, err := f(ctx, req)
		if err != nil {
			st, _ := status.FromError(err)
			w.errs = append(w.errs, err.Error(), st.Message())
		} else {
			w.bodies = append(w.bodies, resp.String())
		}
	}
}

func (w *world) ipamCalls(host string) {
	ctx := context.Background()
	w.ipam.addrs[addr1] = ipamsync.Address{ID: addr1, Address: "192.0.2.44", SubnetID: sub4, Hostname: host}
	if err := w.sync.Handle(ctx, tenant, ipamsync.Event{Type: ipamsync.TypeCreated, ID: addr1, Address: "192.0.2.44", SubnetID: sub4, Hostname: host}); err != nil {
		w.errs = append(w.errs, err.Error())
	}
	delete(w.ipam.addrs, addr1)
	if err := w.sync.Handle(ctx, tenant, ipamsync.Event{Type: ipamsync.TypeDeleted, ID: addr1}); err != nil {
		w.errs = append(w.errs, err.Error())
	}
}

const cfgBody = `{"recursor":{"listen_addresses":["0.0.0.0"],"port":53,"allowed_networks":["10.0.0.0/8"],"upstream_resolvers":["9.9.9.9"],"dnssec_validation":"%s"},
 "authoritative":{"listen_addresses":["0.0.0.0"],"port":53,"transfer_peers":[]}}`

func TestAPIKeysNeverLeak(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// ---- phase 1: a well-behaved PowerDNS (success paths).
	code, body := w.do("POST", p+"/templates", `{"name":"base","records":[{"name":"www.[ZONE]","type":"A","ttl":300,"content":"192.0.2.10"}]}`)
	tid := w.id(code, body)
	w.do("GET", p+"/templates", "")
	w.do("GET", p+"/templates/"+tid, "")
	w.do("PUT", p+"/templates/"+tid, `{"name":"base","description":"d","records":[{"name":"www.[ZONE]","type":"A","ttl":300,"content":"192.0.2.11"}]}`)

	code, body = w.do("POST", p+"/zones", `{"name":"example.test","kind":"master","nameservers":["ns1.example.test"],"template_id":"`+tid+`"}`)
	zid := w.id(code, body)
	code, body = w.do("POST", p+"/zones", `{"name":"keep.test","kind":"master","nameservers":["ns1.keep.test"]}`)
	keep := w.id(code, body)
	w.do("POST", p+"/zones", `{"name":"2.0.192.in-addr.arpa","kind":"native","nameservers":["ns1.example.test"]}`)
	w.do("GET", p+"/zones", "")
	w.do("GET", p+"/zones/"+zid, "")
	w.do("PUT", p+"/zones/"+zid, `{"description":"primary"}`)
	w.do("POST", p+"/zones/"+zid+"/records", `{"name":"api","type":"A","ttl":300,"values":[{"content":"192.0.2.20"}]}`)
	w.do("PUT", p+"/zones/"+zid+"/records", `{"original":{"name":"api.example.test.","type":"A"},"record":{"name":"api2","type":"A","ttl":300,"values":[{"content":"192.0.2.21"}]}}`)
	w.do("GET", p+"/zones/"+zid+"/records", "")
	w.do("GET", p+"/zones/"+zid+"/export", "")
	w.do("POST", p+"/zones/"+zid+"/notify", "")
	w.do("DELETE", p+"/zones/"+zid+"/records?name=api2.example.test.&type=A", "")
	code, body = w.do("POST", p+"/supermasters", `{"ip":"192.0.2.53","nameserver":"ns.primary.test"}`)
	smID := w.id(code, body)
	code, body = w.do("POST", p+"/supermasters", `{"ip":"192.0.2.54","nameserver":"ns2.primary.test"}`)
	smKeep := w.id(code, body)
	w.do("GET", p+"/supermasters", "")
	w.do("GET", p+"/supermasters/"+smID, "")
	w.do("DELETE", p+"/supermasters/"+smID, "")
	w.do("GET", p+"/config", "")
	if code, body = w.do("PUT", p+"/config", fmt.Sprintf(cfgBody, "process")); code != 200 {
		t.Fatalf("config save = %d %s", code, body)
	}
	w.do("GET", p+"/dashboard", "")
	w.do("GET", p+"/health", "")
	w.grpcCalls("example.test")
	w.ipamCalls("host.example.test")
	w.do("DELETE", p+"/zones/"+zid, "")
	w.do("DELETE", p+"/templates/"+tid, "")
	if w.pd.badKey.Load() != 0 || w.rec.badKey.Load() != 0 {
		t.Fatalf("clients sent a wrong key (%d/%d)", w.pd.badKey.Load(), w.rec.badKey.Load())
	}
	if len(w.pd.f.CallLog()) < 10 {
		t.Fatalf("phase 1 barely reached PowerDNS: %v", w.pd.f.CallLog())
	}

	// ---- phase 2: hostile servers echo the key in every reply.
	w.pd.hostile.Store(true)
	w.rec.hostile.Store(true)
	failures := 0
	for i := 0; i < 4; i++ { // cycle through every hostile reply shape
		for _, c := range []struct{ m, path, body string }{
			{"POST", p + "/zones", fmt.Sprintf(`{"name":"new%d.test","kind":"native","nameservers":["ns1.new.test"]}`, i)},
			{"GET", p + "/zones/" + keep, ""},
			{"PUT", p + "/zones/" + keep, `{"kind":"native"}`},
			{"POST", p + "/zones/" + keep + "/records", `{"name":"x","type":"TXT","ttl":60,"values":[{"content":"\"v\""}]}`},
			{"GET", p + "/zones/" + keep + "/records", ""},
			{"DELETE", p + "/zones/" + keep + "/records?name=x.keep.test.&type=TXT", ""},
			{"GET", p + "/zones/" + keep + "/export", ""},
			{"POST", p + "/zones/" + keep + "/notify", ""},
			{"POST", p + "/supermasters", fmt.Sprintf(`{"ip":"192.0.2.%d","nameserver":"ns.bad.test"}`, 60+i)},
			{"DELETE", p + "/supermasters/" + smKeep, ""},
			{"PUT", p + "/config", fmt.Sprintf(cfgBody, []string{"off", "process-no-validate", "log-fail", "validate"}[i])},
			{"GET", p + "/health", ""},
			{"DELETE", p + "/zones/" + keep, ""},
		} {
			if code, _ := w.do(c.m, c.path, c.body); code >= 400 {
				failures++
			}
		}
		w.grpcCalls("keep.test")
		w.ipamCalls("host.keep.test")
		// Direct service calls: the returned error strings themselves.
		if _, err := w.zs.Create(ctx, authz.Internal(tenant), zones.CreateInput{Name: fmt.Sprintf("direct%d.test", i), Kind: "native"}); err != nil {
			w.errs = append(w.errs, err.Error(), fmt.Sprintf("%+v", err))
		}
		if _, err := w.zs.Export(ctx, authz.Internal(tenant), keep); err != nil {
			w.errs = append(w.errs, err.Error(), fmt.Sprintf("%#v", err))
		}
	}
	if failures == 0 || w.pd.n.Load() < 20 || w.rec.n.Load() == 0 {
		t.Fatalf("hostile phase not exercised: failures=%d pdns=%d recursor=%d", failures, w.pd.n.Load(), w.rec.n.Load())
	}

	// ---- assertions over every sink.
	for _, b := range w.bodies {
		leakFree(t, "HTTP/gRPC response", b)
	}
	for _, e := range w.errs {
		leakFree(t, "error", e)
	}
	if len(w.errs) == 0 {
		t.Fatal("no errors captured in the hostile phase")
	}
	logs := w.logs.String()
	leakFree(t, "logs", logs)
	if logs == "" {
		t.Fatal("no log output captured")
	}
	auditDump, n := w.aud.dump()
	leakFree(t, "audit", auditDump)
	if n == 0 {
		t.Fatal("no audit events captured")
	}
	evDump, n := w.pub.dump()
	leakFree(t, "events", evDump)
	if n == 0 {
		t.Fatal("no platform events captured")
	}
	if dir := os.Getenv("FREYA_CAPTURE_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "dns-redaction.log"), []byte(strings.Join(append(append(w.bodies, w.errs...), logs, auditDump, evDump), "\n")), 0o600) // #nosec G306 -- test artefact
	}
}
