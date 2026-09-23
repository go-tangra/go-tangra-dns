package contract

// T029: the zones surface of contracts §A over the full HTTP chain (OpenAPI
// validation, platform token, per-route permission, handlers, services,
// in-memory store, fake PowerDNS/recursor): shapes, filters and paging,
// refusal reasons, global uniqueness and overlap without revealing the owner,
// tenant isolation and viewer refusal on every mutation.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/pkg/authclient"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/httpapi"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/recursor"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
	adminA  = "33333333-3333-7333-8333-333333333333"
	viewerA = "44444444-4444-7444-8444-444444444444"
	adminB  = "55555555-5555-7555-8555-555555555555"
	p       = "/api/dns/v1"
)

type verifier map[string]authclient.Identity

func (v verifier) Verify(_ context.Context, tok string) (authclient.Identity, error) {
	if id, ok := v[tok]; ok {
		return id, nil
	}
	return authclient.Identity{}, errors.New("unauthenticated")
}

type harness struct {
	t   *testing.T
	s   *httpapi.Server
	rtr routers.Router
	st  *memstore.Mem
	pd  *pdns.Fake
	rec *recursor.Fake
	pub *events.Recorder
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := verifier{
		"admin-a":  {UserID: adminA, TenantID: tenantA},
		"viewer-a": {UserID: viewerA, TenantID: tenantA},
		"admin-b":  {UserID: adminB, TenantID: tenantB},
	}
	manage := []string{authz.ZonesRead, authz.ZonesManage}
	checker := authz.Static{adminA: manage, adminB: manage, viewerA: {authz.ZonesRead}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(checker))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	doc.Servers = nil
	rtr, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, s: s, rtr: rtr, st: memstore.New(), pd: pdns.NewFake(), rec: recursor.NewFake(), pub: &events.Recorder{}}
	zs := zones.New(zones.Deps{Store: h.st, PDNS: h.pd, Recursor: h.rec, Events: h.pub})
	rs := records.New(records.Deps{Zones: zs, PDNS: h.pd, Events: h.pub})
	s.Register(httpapi.Deps{Zones: zs, Records: rs})
	return h
}

func (h *harness) do(method, path, tok, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	if method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", "csrf")
	}
	w := httptest.NewRecorder()
	h.s.Handler().ServeHTTP(w, r)
	h.checkResponse(method, path, w)
	return w
}

// checkResponse validates every response (successes and refusals) against
// the OpenAPI document so the handlers and the contract cannot drift.
func (h *harness) checkResponse(method, path string, w *httptest.ResponseRecorder) {
	h.t.Helper()
	r := httptest.NewRequest(method, path, nil)
	route, params, err := h.rtr.FindRoute(r)
	if err != nil {
		h.t.Fatalf("%s %s: no route: %v", method, path, err)
	}
	in := &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc}}
	res := &openapi3filter.ResponseValidationInput{RequestValidationInput: in, Status: w.Code, Header: w.Header(),
		Body: io.NopCloser(bytes.NewReader(w.Body.Bytes())), Options: &openapi3filter.Options{IncludeResponseStatus: true}}
	if err := openapi3filter.ValidateResponse(context.Background(), res); err != nil {
		h.t.Errorf("%s %s response violates the contract: %v\n%s", method, path, err, w.Body)
	}
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", w.Body, err)
	}
	return v
}

func reason(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[map[string]any](t, w)["reason"].(string)
}

type zoneJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Masters     []string `json:"masters"`
	Nameservers []string `json:"nameservers"`
	Origin      string   `json:"origin"`
	Serial      *int     `json:"serial"`
	PDNSID      string   `json:"pdns_id"`
}

type errJSON struct {
	Reason string         `json:"reason"`
	Detail map[string]any `json:"detail"`
}

type page[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

func (h *harness) createZone(tok, body string) zoneJSON {
	h.t.Helper()
	w := h.do("POST", p+"/zones", tok, body)
	if w.Code != 201 {
		h.t.Fatalf("create %s = %d %s", body, w.Code, w.Body)
	}
	return decode[zoneJSON](h.t, w)
}

func TestZoneShapes(t *testing.T) {
	h := newHarness(t)
	z := h.createZone("admin-a", `{"name":"Example.test","kind":"native","nameservers":["ns1.example.test"],"description":"main"}`)
	if z.ID == "" || z.Name != "example.test." || z.Kind != "native" || z.Origin != "manual" || z.Masters == nil || len(z.Nameservers) != 1 || z.PDNSID != "" {
		t.Fatalf("created = %+v", z)
	}
	if _, ok := h.rec.Forwards()["example.test."]; !ok {
		t.Fatal("resolver forward missing")
	}
	w := h.do("GET", p+"/zones/"+z.ID, "viewer-a", "")
	d := decode[zoneJSON](t, w)
	if w.Code != 200 || d.Serial == nil || *d.Serial != 1 {
		t.Fatalf("get = %d %s", w.Code, w.Body)
	}
	w = h.do("PUT", p+"/zones/"+z.ID, "admin-a", `{"kind":"master","description":"primary","dnssec":true}`)
	if w.Code != 200 || decode[zoneJSON](t, w).Kind != "master" {
		t.Fatalf("update = %d %s", w.Code, w.Body)
	}
	w = h.do("PUT", p+"/zones/"+z.ID, "admin-a", `{"kind":"slave"}`)
	if w.Code != 422 || reason(t, w) != "invalid_kind" {
		t.Fatalf("slave without masters = %d %s", w.Code, w.Body)
	}
	w = h.do("PUT", p+"/zones/"+z.ID, "admin-a", `{"masters":["127.0.0.1"]}`)
	if w.Code != 400 || reason(t, w) != "bad_request" || !strings.Contains(w.Body.String(), "message") {
		t.Fatalf("bad masters = %d %s", w.Code, w.Body)
	}
	if w := h.do("DELETE", p+"/zones/"+z.ID, "admin-a", ""); w.Code != 204 {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/zones/"+z.ID, "admin-a", ""); w.Code != 404 || reason(t, w) != "zone_not_found" {
		t.Fatalf("get deleted = %d %s", w.Code, w.Body)
	}
	if _, ok := h.rec.Forwards()["example.test."]; ok {
		t.Fatal("resolver forward kept")
	}
	if _, err := h.pd.GetZone(context.Background(), "example.test."); !errors.Is(err, pdns.ErrNotFound) {
		t.Fatal("PowerDNS zone kept")
	}
}

func TestZoneListFiltersAndPaging(t *testing.T) {
	h := newHarness(t)
	for _, n := range []string{"alpha.test", "beta.test", "gamma.test"} {
		h.createZone("admin-a", `{"name":"`+n+`","kind":"native"}`)
	}
	h.createZone("admin-a", `{"name":"delta.test","kind":"master"}`)
	h.createZone("admin-b", `{"name":"other.test","kind":"native"}`)

	pg := decode[page[zoneJSON]](t, h.do("GET", p+"/zones", "viewer-a", ""))
	if pg.Total != 4 || len(pg.Items) != 4 || pg.Items[0].Name != "alpha.test." {
		t.Fatalf("list = %+v", pg)
	}
	pg = decode[page[zoneJSON]](t, h.do("GET", p+"/zones?query=ET&page_size=1", "viewer-a", ""))
	if pg.Total != 1 || len(pg.Items) != 1 || pg.Items[0].Name != "beta.test." {
		t.Fatalf("query = %+v", pg)
	}
	pg = decode[page[zoneJSON]](t, h.do("GET", p+"/zones?kind=master", "viewer-a", ""))
	if pg.Total != 1 || pg.Items[0].Name != "delta.test." {
		t.Fatalf("kind = %+v", pg)
	}
	pg = decode[page[zoneJSON]](t, h.do("GET", p+"/zones?page=2&page_size=3", "viewer-a", ""))
	if pg.Total != 4 || len(pg.Items) != 1 {
		t.Fatalf("paging = %+v", pg)
	}
	pg = decode[page[zoneJSON]](t, h.do("GET", p+"/zones?origin=ipam", "viewer-a", ""))
	if pg.Total != 0 || pg.Items == nil {
		t.Fatalf("origin = %+v", pg)
	}
	if w := h.do("GET", p+"/zones?page_size=101", "viewer-a", ""); w.Code != 422 {
		t.Fatalf("page_size cap = %d", w.Code)
	}
}

func TestZoneRefusals(t *testing.T) {
	h := newHarness(t)
	a := h.createZone("admin-a", `{"name":"example.test","kind":"native"}`)
	h.pd.Seed(pdns.Zone{Name: "outside.test.", Kind: "Native"})
	cases := []struct {
		tok, body string
		status    int
		reason    string
	}{
		{"admin-a", `{"name":"bad..name","kind":"native"}`, 422, "invalid_name"},
		{"admin-a", `{"name":"co.uk","kind":"native"}`, 422, "invalid_name"},
		{"admin-a", `{"name":"x.test","kind":"slave"}`, 422, "invalid_kind"},
		{"admin-a", `{"name":"x.test","kind":"native","template_id":"nope"}`, 404, "template_not_found"},
		{"admin-a", `{"name":"example.test","kind":"native"}`, 409, "duplicate"},
		{"admin-b", `{"name":"example.test.","kind":"native"}`, 409, "duplicate"},
		{"admin-b", `{"name":"sub.example.test","kind":"native"}`, 409, "duplicate"},
		{"admin-a", `{"name":"outside.test","kind":"native"}`, 409, "duplicate"},
		{"viewer-a", `{"name":"v.test","kind":"native"}`, 403, "forbidden"},
	}
	for _, c := range cases {
		w := h.do("POST", p+"/zones", c.tok, c.body)
		if w.Code != c.status || reason(t, w) != c.reason {
			t.Errorf("%s %s = %d %s, want %d %s", c.tok, c.body, w.Code, w.Body, c.status, c.reason)
		}
		// the duplicate refusal never names the owner
		if strings.Contains(w.Body.String(), tenantA) || strings.Contains(w.Body.String(), adminA) {
			t.Errorf("owner revealed: %s", w.Body)
		}
	}
	w := h.do("POST", p+"/zones", "admin-a", `{"name":"co.uk","kind":"native"}`)
	if msg := decode[errJSON](t, w).Detail["message"]; msg == nil || strings.Contains(msg.(string), "validate:") {
		t.Fatalf("invalid_name detail = %s", w.Body)
	}
	// tenant B sees 404 on tenant A's zone for every operation
	for _, c := range [][3]string{{"GET", "/zones/" + a.ID, ""}, {"PUT", "/zones/" + a.ID, `{"description":"x"}`}, {"DELETE", "/zones/" + a.ID, ""},
		{"GET", "/zones/" + a.ID + "/records", ""}, {"POST", "/zones/" + a.ID + "/records", `{"name":"x","type":"A","ttl":300,"values":[{"content":"192.0.2.1"}]}`},
		{"DELETE", "/zones/" + a.ID + "/records?name=x&type=A", ""}} {
		if w := h.do(c[0], p+c[1], "admin-b", c[2]); w.Code != 404 || reason(t, w) != "zone_not_found" {
			t.Errorf("tenant B %s %s = %d %s", c[0], c[1], w.Code, w.Body)
		}
	}
	// viewer: 403 on every mutation
	for _, c := range [][3]string{{"PUT", "/zones/" + a.ID, `{"description":"x"}`}, {"DELETE", "/zones/" + a.ID, ""},
		{"POST", "/zones/" + a.ID + "/records", `{"name":"x","type":"A","ttl":300,"values":[{"content":"192.0.2.1"}]}`},
		{"PUT", "/zones/" + a.ID + "/records", `{"original":{"name":"x","type":"A"},"record":{"name":"x","type":"A","ttl":300,"values":[{"content":"192.0.2.1"}]}}`},
		{"DELETE", "/zones/" + a.ID + "/records?name=x&type=A", ""}} {
		if w := h.do(c[0], p+c[1], "viewer-a", c[2]); w.Code != 403 {
			t.Errorf("viewer %s %s = %d", c[0], c[1], w.Code)
		}
	}
	// PowerDNS unreachable: pdns_unavailable, nothing written locally
	h.pd.SetDown(true)
	if w := h.do("POST", p+"/zones", "admin-a", `{"name":"down.test","kind":"native"}`); w.Code != 503 || reason(t, w) != "pdns_unavailable" {
		t.Fatalf("down = %d %s", w.Code, w.Body)
	}
	h.pd.SetDown(false)
	pg := decode[page[zoneJSON]](t, h.do("GET", p+"/zones?query=down", "admin-a", ""))
	if pg.Total != 0 {
		t.Fatal("local row written while PowerDNS was down")
	}
	if w := h.do("POST", p+"/zones", "admin-a", `{"name":"x.test","kind":"native","origin":"ipam"}`); w.Code != 422 && w.Code != 400 {
		t.Fatalf("origin field accepted = %d", w.Code)
	}
}
