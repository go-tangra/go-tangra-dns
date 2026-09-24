package recursor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const apiKey = "recursor-s3cr3t-key"

var ctx = context.Background()

type req struct {
	Method, Path, RawPath, Key string
	Body                       map[string]any
}

type fakeAPI struct {
	mu     sync.Mutex
	reqs   []req
	status map[string]int // "METHOD" -> status override
	body   []byte         // GET body
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.reqs = append(f.reqs, req{Method: r.Method, Path: r.URL.Path, RawPath: r.URL.EscapedPath(), Key: r.Header.Get("X-API-Key"), Body: body})
	st, ok := f.status[r.Method]
	gb := f.body
	f.mu.Unlock()
	switch {
	case ok:
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"error":"status ` + http.StatusText(st) + ` key=` + apiKey + `"}`))
	case r.Method == http.MethodPost:
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet:
		_, _ = w.Write(gb)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakeAPI) all() []req {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]req(nil), f.reqs...)
}

func (f *fakeAPI) reset(status map[string]int) {
	f.mu.Lock()
	f.reqs, f.status = nil, status
	f.mu.Unlock()
}

type staticResolver map[string][]net.IPAddr

func (s staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if a, ok := s[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func newTest(t *testing.T, host string) (*HTTPClient, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{}
	ts := httptest.NewServer(api)
	t.Cleanup(ts.Close)
	c, err := New(Config{BaseURL: ts.URL, Key: func(context.Context) (string, error) { return apiKey, nil }, ForwardHost: host, ForwardPort: 53,
		Timeout: 5 * time.Second, Resolver: staticResolver{
			"pdns-auth": {{IP: net.ParseIP("2001:db8::5")}, {IP: net.ParseIP("172.20.0.5")}},
			"v6only":    {{IP: net.ParseIP("2001:db8::6")}},
			"empty":     {},
		}})
	if err != nil {
		t.Fatal(err)
	}
	return c, api
}

func TestSyncForwardPayloadAndIdempotency(t *testing.T) {
	c, api := newTest(t, "pdns-auth")
	if !c.Enabled() {
		t.Fatal("configured client disabled")
	}
	if err := c.SyncForward(ctx, "Example.COM"); err != nil {
		t.Fatal(err)
	}
	reqs := api.all()
	if len(reqs) != 2 || reqs[0].Method != "DELETE" || reqs[0].Path != "/api/v1/servers/localhost/zones/example.com." || reqs[1].Method != "POST" ||
		reqs[1].Path != "/api/v1/servers/localhost/zones" || reqs[0].Key != apiKey || reqs[1].Key != apiKey {
		t.Fatalf("requests = %+v", reqs)
	}
	b := reqs[1].Body
	servers := b["servers"].([]any)
	if b["name"] != "example.com." || b["kind"] != "Forwarded" || b["recursion_desired"] != false || len(servers) != 1 || servers[0] != "172.20.0.5:53" {
		t.Fatalf("payload = %+v", b)
	}
	// delete-then-create: a second sync re-points the entry the same way
	api.reset(nil)
	if err := c.SyncForward(ctx, "example.com."); err != nil || len(api.all()) != 2 {
		t.Fatalf("resync: %v %d", err, len(api.all()))
	}
	// the delete of a missing entry does not stop the create
	api.reset(map[string]int{"DELETE": 422})
	if err := c.SyncForward(ctx, "example.com."); err != nil {
		t.Fatalf("sync after 422 delete: %v", err)
	}
	api.reset(map[string]int{"POST": 422})
	err := c.SyncForward(ctx, "example.com.")
	if err == nil || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("failed create: %v", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 422 {
		t.Fatalf("status error: %v", err)
	}
}

func TestForwardTargetResolution(t *testing.T) {
	for host, want := range map[string]string{"10.9.8.7": "10.9.8.7:53", "2001:db8::9": "[2001:db8::9]:53", "v6only": "[2001:db8::6]:53"} {
		c, api := newTest(t, host)
		if err := c.SyncForward(ctx, "a.example."); err != nil {
			t.Fatal(err)
		}
		if got := api.all()[1].Body["servers"].([]any)[0]; got != want {
			t.Errorf("%s -> %v, want %s", host, got, want)
		}
	}
	for _, host := range []string{"unknown-host", "empty"} {
		c, api := newTest(t, host)
		if err := c.SyncForward(ctx, "a.example."); !errors.Is(err, ErrUnavailable) || len(api.all()) != 0 {
			t.Errorf("%s: %v (%d requests)", host, err, len(api.all()))
		}
	}
}

func TestRemoveForward(t *testing.T) {
	c, api := newTest(t, "pdns-auth")
	for _, st := range []int{0, 404, 422} {
		if st == 0 {
			api.reset(nil)
		} else {
			api.reset(map[string]int{"DELETE": st})
		}
		if err := c.RemoveForward(ctx, "example.com"); err != nil {
			t.Fatalf("status %d: %v", st, err)
		}
		if r := api.all()[0]; r.Method != "DELETE" || r.Path != "/api/v1/servers/localhost/zones/example.com." {
			t.Fatalf("request = %+v", r)
		}
	}
	api.reset(map[string]int{"DELETE": 500})
	if err := c.RemoveForward(ctx, "example.com."); err == nil || strings.Contains(err.Error(), apiKey) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("500: %v", err)
	}
	api.reset(map[string]int{"DELETE": 403})
	if err := c.RemoveForward(ctx, "example.com."); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("403: %v", err)
	}
	// names are path-escaped
	api.reset(nil)
	_ = c.RemoveForward(ctx, "a/b.example.")
	if r := api.all()[0]; strings.Count(strings.TrimPrefix(r.RawPath, "/api/v1/servers/localhost/zones/"), "/") != 0 {
		t.Fatalf("unescaped name: %s", r.RawPath)
	}
	for _, bad := range []string{"", ".", " "} {
		if err := c.RemoveForward(ctx, bad); err == nil {
			t.Fatalf("remove %q accepted", bad)
		}
		if err := c.SyncForward(ctx, bad); err == nil {
			t.Fatalf("sync %q accepted", bad)
		}
	}
}

func TestListForwardsAndReady(t *testing.T) {
	c, api := newTest(t, "pdns-auth")
	raw, err := os.ReadFile("../../testdata/pdns/recursor_zones.json")
	if err != nil {
		t.Fatal(err)
	}
	api.body = raw
	got, err := c.ListForwards(ctx)
	if err != nil || strings.Join(got, ",") != "example.com.,stale.example." {
		t.Fatalf("forwards = %v %v", got, err)
	}
	if err := c.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if r := api.all()[1]; r.Method != "GET" || r.Path != "/api/v1/servers/localhost" {
		t.Fatalf("ready request = %+v", r)
	}
	api.body = []byte("not json")
	if _, err := c.ListForwards(ctx); err == nil {
		t.Fatal("bad json accepted")
	}
	api.reset(map[string]int{"GET": 503})
	if _, err := c.ListForwards(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("list 503: %v", err)
	}
	if err := c.Ready(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ready 503: %v", err)
	}
}

func TestDisabledClientIsANoOp(t *testing.T) {
	c, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled() {
		t.Fatal("empty config enabled")
	}
	if err := c.SyncForward(ctx, "a."); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveForward(ctx, "a."); err != nil {
		t.Fatal(err)
	}
	if f, err := c.ListForwards(ctx); err != nil || f != nil {
		t.Fatal(err)
	}
	if err := c.Ready(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidatesAndKeyHandling(t *testing.T) {
	key := func(context.Context) (string, error) { return apiKey, nil }
	for _, cfg := range []Config{
		{BaseURL: "ftp://rec", Key: key},
		{BaseURL: "http://", Key: key},
		{BaseURL: "http://u:p@rec", Key: key},
		{BaseURL: "http://rec", Key: nil},
		{BaseURL: "http://rec", Key: key, ServerID: "a b"},
		{BaseURL: "http://rec", Key: key, ForwardPort: 70000},
		{BaseURL: "http://rec", Key: key, ForwardHost: "bad host"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) accepted", cfg)
		}
	}
	c, err := New(Config{BaseURL: "http://rec:8082", Key: key})
	if err != nil || c.fwdHost != "pdns-auth" || c.fwdPort != 53 || c.timeout != DefaultTimeout || c.resolver == nil {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	api := &fakeAPI{}
	ts := httptest.NewServer(api)
	defer ts.Close()
	failing, _ := New(Config{BaseURL: ts.URL, ForwardHost: "10.0.0.1", Key: func(context.Context) (string, error) { return "", errors.New("down") }})
	if err := failing.SyncForward(ctx, "a."); !errors.Is(err, ErrUnavailable) || len(api.all()) != 0 {
		t.Fatalf("key failure: %v", err)
	}
	// connection refused
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	dead, _ := New(Config{BaseURL: "http://" + addr, ForwardHost: "10.0.0.1", Key: key, Timeout: time.Second})
	if err := dead.RemoveForward(ctx, "a."); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("refused: %v", err)
	}
	if err := dead.SyncForward(ctx, "a."); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refused sync: %v", err)
	}
}
