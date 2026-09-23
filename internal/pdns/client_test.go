package pdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

const apiKey = "pdns-s3cr3t-api-key"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/pdns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seen is one request the fake PowerDNS received.
type seen struct {
	Method, Path, RawPath, Query, Key, ContentType string
	Body                                           map[string]any
}

type server struct {
	t    *testing.T
	mu   sync.Mutex
	reqs []seen
	// reply decides the response per request (default 204).
	reply func(w http.ResponseWriter, r *http.Request)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	s.mu.Lock()
	s.reqs = append(s.reqs, seen{Method: r.Method, Path: r.URL.Path, RawPath: r.URL.EscapedPath(), Query: r.URL.RawQuery,
		Key: r.Header.Get("X-API-Key"), ContentType: r.Header.Get("Content-Type"), Body: body})
	reply := s.reply
	s.mu.Unlock()
	if reply == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	reply(w, r)
}

func (s *server) last() seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		s.t.Fatal("no request received")
	}
	return s.reqs[len(s.reqs)-1]
}

func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func (s *server) set(fn func(w http.ResponseWriter, r *http.Request)) {
	s.mu.Lock()
	s.reply = fn
	s.mu.Unlock()
}

func jsonReply(status int, body []byte) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

type keySource struct {
	mu  sync.Mutex
	key string
	err error
	n   int
}

func (k *keySource) get(context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.n++
	return k.key, k.err
}

func newTest(t *testing.T) (*HTTPClient, *server, *keySource) {
	t.Helper()
	srv := &server{t: t}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	ks := &keySource{key: apiKey}
	c, err := New(Config{BaseURL: ts.URL + "/", ServerID: "localhost", Key: ks.get, Timeout: 5 * time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv, ks
}

var ctx = context.Background()

func TestNewValidates(t *testing.T) {
	key := func(context.Context) (string, error) { return "k", nil }
	for _, cfg := range []Config{
		{BaseURL: "", Key: key},
		{BaseURL: "ftp://pdns", Key: key},
		{BaseURL: "http://", Key: key},
		{BaseURL: "http://u:p@pdns", Key: key},
		{BaseURL: "http://pdns", Key: nil},
		{BaseURL: "http://pdns", Key: key, ServerID: "a/b"},
		{BaseURL: "http://pdns\x7f", Key: key},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) accepted", cfg.BaseURL)
		}
	}
	c, err := New(Config{BaseURL: "http://pdns:8081", Key: key})
	if err != nil || c.serverID != "localhost" || c.timeout != DefaultTimeout || c.maxLarge != DefaultMaxResponse || c.hc == nil {
		t.Fatalf("defaults: %+v %v", c, err)
	}
}

func TestZonesWire(t *testing.T) {
	c, srv, _ := newTest(t)

	srv.set(jsonReply(200, fixture(t, "zones.json")))
	names, err := c.ListZoneNames(ctx)
	if err != nil || strings.Join(names, ",") != "example.com.,2.0.192.in-addr.arpa.,auto.example.net." {
		t.Fatalf("list = %v %v", names, err)
	}
	if r := srv.last(); r.Method != "GET" || r.Path != "/api/v1/servers/localhost/zones" || r.Query != "dnssec=false" || r.Key != apiKey {
		t.Fatalf("list request = %+v", r)
	}

	srv.set(jsonReply(200, fixture(t, "zone.json")))
	z, err := c.GetZone(ctx, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if z.ID != "example.com." || z.Kind != "Native" || z.Serial != 2026092301 || len(z.RRsets) != 5 || z.RRsets[2].Records[1].Disabled != true ||
		z.RRsets[2].Comments[0].Content != "web tier" || z.Account == "" {
		t.Fatalf("zone = %+v", z)
	}
	if r := srv.last(); r.Method != "GET" || r.Path != "/api/v1/servers/localhost/zones/example.com." {
		t.Fatalf("get request = %+v", r)
	}

	srv.set(jsonReply(201, fixture(t, "zone.json")))
	in := Zone{Name: "example.com.", Kind: "Native", Nameservers: []string{"ns1.example.com."}, Account: "t1",
		RRsets: []RRset{{Name: "www.example.com.", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.10"}}}}}
	created, err := c.CreateZone(ctx, in)
	if err != nil || created.ID != "example.com." {
		t.Fatalf("create = %+v %v", created, err)
	}
	r := srv.last()
	if r.Method != "POST" || r.Path != "/api/v1/servers/localhost/zones" || r.ContentType != "application/json" ||
		r.Body["name"] != "example.com." || r.Body["kind"] != "Native" || r.Body["account"] != "t1" {
		t.Fatalf("create request = %+v", r)
	}
	if ns := r.Body["nameservers"].([]any); len(ns) != 1 || r.Body["rrsets"] == nil {
		t.Fatalf("create body = %+v", r.Body)
	}
	if _, has := r.Body["serial"]; has {
		t.Fatal("create body carries read-only serial")
	}

	srv.set(nil)
	if err := c.UpdateZoneMetadata(ctx, "example.com.", Zone{Kind: "Master", DNSSEC: false}); err != nil {
		t.Fatal(err)
	}
	r = srv.last()
	if r.Method != "PUT" || r.Path != "/api/v1/servers/localhost/zones/example.com." || r.Body["kind"] != "Master" || r.Body["dnssec"] != false {
		t.Fatalf("update request = %+v", r)
	}
	if m, ok := r.Body["masters"].([]any); !ok || len(m) != 0 {
		t.Fatalf("masters must be sent explicitly (clearing): %+v", r.Body)
	}
	if _, has := r.Body["rrsets"]; has {
		t.Fatal("metadata update carries rrsets")
	}

	if err := c.DeleteZone(ctx, "example.com."); err != nil {
		t.Fatal(err)
	}
	if r := srv.last(); r.Method != "DELETE" || r.Path != "/api/v1/servers/localhost/zones/example.com." {
		t.Fatalf("delete request = %+v", r)
	}

	patch := []RRset{
		{Name: "www.example.com.", Type: "A", TTL: 300, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.20", Disabled: true}},
			Comments: []Comment{{Content: "moved", Account: "u1"}}},
		{Name: "old.example.com.", Type: "A", ChangeType: ChangeDelete},
	}
	if err := c.PatchRRsets(ctx, "example.com.", patch); err != nil {
		t.Fatal(err)
	}
	r = srv.last()
	sets := r.Body["rrsets"].([]any)
	first, second := sets[0].(map[string]any), sets[1].(map[string]any)
	if r.Method != "PATCH" || len(sets) != 2 || first["changetype"] != "REPLACE" || second["changetype"] != "DELETE" ||
		first["records"].([]any)[0].(map[string]any)["disabled"] != true || first["comments"] == nil {
		t.Fatalf("patch request = %+v", r)
	}
	if _, has := second["records"]; has {
		t.Fatal("DELETE rrset carries records")
	}

	if err := c.NotifyZone(ctx, "example.com."); err != nil {
		t.Fatal(err)
	}
	if r := srv.last(); r.Method != "PUT" || r.Path != "/api/v1/servers/localhost/zones/example.com./notify" {
		t.Fatalf("notify request = %+v", r)
	}

	srv.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(fixture(t, "export.txt"))
	})
	text, err := c.ExportZone(ctx, "example.com.")
	if err != nil || !strings.HasPrefix(text, "example.com.\t3600\tIN\tSOA") || !strings.Contains(text, "www.example.com.\t300\tIN\tA\t192.0.2.10") {
		t.Fatalf("export = %q %v", text, err)
	}
	if r := srv.last(); r.Method != "GET" || r.Path != "/api/v1/servers/localhost/zones/example.com./export" {
		t.Fatalf("export request = %+v", r)
	}
	// PowerDNS 4.9 wraps the text in {"zone": ...} for a JSON Accept header.
	srv.set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"zone": "example.com.\t3600\tIN\tSOA\tns1.example.com. h. 1 2 3 4 5\n"}`))
	})
	if text, err := c.ExportZone(ctx, "example.com."); err != nil || text != "example.com.\t3600\tIN\tSOA\tns1.example.com. h. 1 2 3 4 5\n" {
		t.Fatalf("wrapped export = %q %v", text, err)
	}

	srv.set(jsonReply(200, fixture(t, "server.json")))
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if r := srv.last(); r.Method != "GET" || r.Path != "/api/v1/servers/localhost" {
		t.Fatalf("ping request = %+v", r)
	}
}

func TestSupermastersWire(t *testing.T) {
	c, srv, _ := newTest(t)
	srv.set(jsonReply(200, fixture(t, "supermasters.json")))
	list, err := c.ListSupermasters(ctx)
	if err != nil || len(list) != 2 || list[1].IP != "2001:db8::53" || list[0].Nameserver != "ns1.example.net." {
		t.Fatalf("list = %+v %v", list, err)
	}
	if r := srv.last(); r.Method != "GET" || r.Path != "/api/v1/servers/localhost/autoprimaries" {
		t.Fatalf("list request = %+v", r)
	}
	srv.set(jsonReply(201, nil))
	if err := c.CreateSupermaster(ctx, Supermaster{IP: "192.0.2.53", Nameserver: "ns1.example.net.", Account: "t1"}); err != nil {
		t.Fatal(err)
	}
	if r := srv.last(); r.Method != "POST" || r.Path != "/api/v1/servers/localhost/autoprimaries" || r.Body["ip"] != "192.0.2.53" || r.Body["account"] != "t1" {
		t.Fatalf("create request = %+v", r)
	}
	srv.set(nil)
	if err := c.DeleteSupermaster(ctx, "2001:db8::53", "ns2.example.net."); err != nil {
		t.Fatal(err)
	}
	if r := srv.last(); r.Method != "DELETE" || r.Path != "/api/v1/servers/localhost/autoprimaries/2001:db8::53/ns2.example.net." {
		t.Fatalf("delete request = %+v", r)
	}
}

// Zone ids are path-escaped: a crafted id can never address another resource.
func TestZoneIDPathEscaping(t *testing.T) {
	c, srv, _ := newTest(t)
	srv.set(jsonReply(200, fixture(t, "zone.json")))
	for _, id := range []string{"a/b.", "../../servers/other/zones/x.", "x.?y=1", "x.#frag"} {
		_, _ = c.GetZone(ctx, id)
		r := srv.last()
		if !strings.HasPrefix(r.RawPath, "/api/v1/servers/localhost/zones/") || strings.Count(strings.TrimPrefix(r.RawPath, "/api/v1/servers/localhost/zones/"), "/") != 0 || r.Query != "" {
			t.Errorf("id %q reached %q ?%q", id, r.RawPath, r.Query)
		}
	}
	for _, id := range []string{"", ".", ".."} {
		if _, err := c.GetZone(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("id %q: %v", id, err)
		}
	}
	before := srv.count()
	_ = c.DeleteSupermaster(ctx, "../x", "ns.")
	if srv.count() != before+1 || strings.Count(strings.TrimPrefix(srv.last().RawPath, "/api/v1/servers/localhost/autoprimaries/"), "/") != 1 {
		t.Fatalf("supermaster path = %q", srv.last().RawPath)
	}
}

// The key is read from the secret source on every call (rotation without restart).
func TestKeyPerCall(t *testing.T) {
	c, srv, ks := newTest(t)
	_ = c.DeleteZone(ctx, "a.")
	ks.mu.Lock()
	ks.key = "rotated-key"
	ks.mu.Unlock()
	_ = c.DeleteZone(ctx, "a.")
	if srv.last().Key != "rotated-key" || ks.n != 2 {
		t.Fatalf("key not re-read per call: %q (%d reads)", srv.last().Key, ks.n)
	}
	ks.mu.Lock()
	ks.err = errors.New("secrets: unavailable")
	ks.mu.Unlock()
	before := srv.count()
	if err := c.DeleteZone(ctx, "a."); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("key failure: %v", err)
	}
	if srv.count() != before {
		t.Fatal("a request was sent without a key")
	}
	ks.mu.Lock()
	ks.err, ks.key = nil, ""
	ks.mu.Unlock()
	if err := c.DeleteZone(ctx, "a."); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty key: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	c, srv, _ := newTest(t)
	cases := []struct {
		status int
		body   []byte
		want   error
	}{
		{404, fixture(t, "error_404.json"), ErrNotFound},
		{409, fixture(t, "error_409.json"), ErrConflict},
		{422, fixture(t, "error_422_exists.json"), ErrConflict},
		{500, []byte(`{"error":"backend down"}`), ErrUnavailable},
		{503, []byte(`<html>bad gateway</html>`), ErrUnavailable},
	}
	for _, cs := range cases {
		srv.set(jsonReply(cs.status, cs.body))
		_, err := c.GetZone(ctx, "example.com.")
		var ae *APIError
		if !errors.Is(err, cs.want) || !errors.As(err, &ae) || ae.Status != cs.status {
			t.Errorf("%d: %v", cs.status, err)
		}
	}
	// A validation 422 is an APIError, not a conflict.
	srv.set(jsonReply(422, fixture(t, "error_422.json")))
	err := c.PatchRRsets(ctx, "example.com.", nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 422 || errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) || !strings.Contains(ae.Message, "out of zone") {
		t.Fatalf("422: %v", err)
	}
	// Garbage JSON on success is a decode error, not a panic.
	srv.set(jsonReply(200, []byte(`{"id": 5`)))
	if _, err := c.GetZone(ctx, "example.com."); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("bad json: %v", err)
	}
	srv.set(jsonReply(200, []byte(`not json`)))
	if _, err := c.ListSupermasters(ctx); err == nil {
		t.Fatal("bad json list accepted")
	}
	srv.set(jsonReply(404, nil))
	if _, err := c.ExportZone(ctx, "x."); !errors.Is(err, ErrNotFound) {
		t.Fatalf("export 404: %v", err)
	}
	srv.set(jsonReply(400, []byte(`{"error":"bad"}`)))
	for name, call := range map[string]func() error{
		"list":        func() error { _, err := c.ListZoneNames(ctx); return err },
		"create":      func() error { _, err := c.CreateZone(ctx, Zone{Name: "x."}); return err },
		"export":      func() error { _, err := c.ExportZone(ctx, "x."); return err },
		"supermaster": func() error { return c.CreateSupermaster(ctx, Supermaster{}) },
		"ping":        func() error { return c.Ping(ctx) },
		"sm list":     func() error { _, err := c.ListSupermasters(ctx); return err },
	} {
		if err := call(); !errors.As(err, &ae) || ae.Status != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUnavailable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // nothing listens: connection refused
	c, err := New(Config{BaseURL: "http://" + addr, Key: func(context.Context) (string, error) { return apiKey, nil }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"get":    func() error { _, err := c.GetZone(ctx, "x."); return err },
		"export": func() error { _, err := c.ExportZone(ctx, "x."); return err },
		"patch":  func() error { return c.PatchRRsets(ctx, "x.", nil) },
	} {
		err := call()
		if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), apiKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A slow server hits the per-call timeout.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	c2, _ := New(Config{BaseURL: slow.URL, Key: func(context.Context) (string, error) { return apiKey, nil }, Timeout: 50 * time.Millisecond})
	if err := c2.DeleteZone(ctx, "x."); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("timeout: %v", err)
	}
}

func TestBodyCaps(t *testing.T) {
	c, srv, _ := newTest(t) // large cap 1 MiB, small cap 64 KiB
	big := `{"id":"x.","name":"x.","rrsets":[{"name":"x.","type":"TXT","records":[{"content":"` + strings.Repeat("a", 2<<20) + `"}]}]}`
	srv.set(jsonReply(200, []byte(big)))
	if _, err := c.GetZone(ctx, "x."); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("zone cap: %v", err)
	}
	srv.set(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 2<<20))) })
	if _, err := c.ExportZone(ctx, "x."); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("export cap: %v", err)
	}
	srv.set(jsonReply(200, []byte(`[`+strings.Repeat(`{"ip":"192.0.2.1","nameserver":"ns."},`, 4000)+`{}]`)))
	if _, err := c.ListSupermasters(ctx); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("small cap: %v", err)
	}
	// error bodies are capped and truncated too
	srv.set(jsonReply(422, []byte(`{"error":"`+strings.Repeat("e", 100000)+`"}`)))
	err := c.PatchRRsets(ctx, "x.", nil)
	var ae *APIError
	if !errors.As(err, &ae) || len(ae.Message) > MaxErrorMessage {
		t.Fatalf("error message not truncated: %d", len(ae.Message))
	}
}

// The API key never appears in an error, even when PowerDNS echoes it back.
func TestErrorsNeverCarryTheKey(t *testing.T) {
	c, srv, _ := newTest(t)
	for _, body := range []string{
		`{"error":"invalid key ` + apiKey + `"}`,
		`plain text ` + apiKey + "\n\x1b[31mcontrol",
		`{"error":"","errors":["` + apiKey + `"]}`,
	} {
		for _, status := range []int{400, 401, 404, 409, 422, 500} {
			srv.set(jsonReply(status, []byte(body)))
			for _, err := range []error{
				func() error { _, err := c.GetZone(ctx, "x."); return err }(),
				func() error { _, err := c.ExportZone(ctx, "x."); return err }(),
				c.PatchRRsets(ctx, "x.", nil),
			} {
				if err == nil || strings.Contains(err.Error(), apiKey) || strings.Contains(fmt.Sprintf("%+v", err), apiKey) {
					t.Fatalf("%d: key leaked or no error: %v", status, err)
				}
				if strings.ContainsAny(err.Error(), "\n\x1b") {
					t.Fatalf("control characters in error: %q", err.Error())
				}
			}
		}
	}
}

// An explicit empty comment list is sent on REPLACE (PowerDNS then clears the
// rrset's comments); a nil list is omitted (comments kept).
func TestPatchSendsEmptyCommentsToClear(t *testing.T) {
	c, srv, _ := newTest(t)
	srv.set(jsonReply(204, nil))
	patch := []RRset{
		{Name: "www.example.com.", Type: "A", TTL: 300, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.20"}}, Comments: []Comment{}},
		{Name: "api.example.com.", Type: "A", TTL: 300, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.21"}}},
	}
	if err := c.PatchRRsets(ctx, "example.com.", patch); err != nil {
		t.Fatal(err)
	}
	sets := srv.last().Body["rrsets"].([]any)
	first, second := sets[0].(map[string]any), sets[1].(map[string]any)
	if cm, ok := first["comments"].([]any); !ok || len(cm) != 0 {
		t.Fatalf("empty comments not sent: %+v", first)
	}
	if _, has := second["comments"]; has {
		t.Fatalf("nil comments sent: %+v", second)
	}
}
