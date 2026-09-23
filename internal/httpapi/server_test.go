package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/pkg/authclient"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

const (
	tenant  = "11111111-1111-7111-8111-111111111111"
	viewer  = "44444444-4444-7444-8444-444444444444"
	admin   = "55555555-5555-7555-8555-555555555555"
	padmin  = "66666666-6666-7666-8666-666666666666"
	session = "csrf"
)

type fakeVerifier map[string]authclient.Identity

func (f fakeVerifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	if id, ok := f[token]; ok {
		return id, nil
	}
	return authclient.Identity{}, ErrUnauthenticated
}

func newServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := fakeVerifier{
		"tok-viewer": {UserID: viewer, TenantID: tenant},
		"tok-admin":  {UserID: admin, TenantID: tenant, Roles: []string{"owner", "admin"}},
		"tok-padmin": {UserID: padmin, TenantID: tenant, Roles: []string{authz.RolePlatformAdmin}},
		"tok-notent": {UserID: admin},
	}
	checker := authz.Static{
		viewer: {authz.ZonesRead, authz.DashboardRead},
		admin:  {authz.ZonesRead, authz.ZonesManage, authz.TemplatesManage, authz.SupermastersManage, authz.DashboardRead, authz.BackupManage},
		padmin: authz.Permissions,
	}
	s, err := NewHandler(rt, append([]Option{WithVerifier(v), WithChecker(checker)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", session)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func reason(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	r, _ := m["reason"].(string)
	return r
}

func TestHealthIsPublicAndReportsComponents(t *testing.T) {
	s := newServer(t)
	s.Register(Deps{Health: func() map[string]string { return map[string]string{"store": "ok", "pdns": "unreachable"} }})
	w := do(s, "GET", Prefix+"/health", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"degraded"`) {
		t.Fatalf("health = %d %s", w.Code, w.Body)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secure headers missing")
	}
	s2 := newServer(t)
	s2.Register(Deps{})
	if w := do(s2, "GET", Prefix+"/health", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("bare health = %s", w.Body)
	}
	if s2.IsPublic("GET", Prefix+"/zones") || !s2.IsPublic("GET", Prefix+"/health") {
		t.Fatal("public flags")
	}
}

// Per-route permission enforcement inside the module (defence in depth): the
// declared x-freya-permission of every route is checked for the verified user.
func TestPermissionEnforcement(t *testing.T) {
	s := newServer(t)
	s.Register(Deps{})
	ok := func(w http.ResponseWriter, _ *http.Request) {
		WriteJSON(w, 200, map[string]any{"items": []any{}, "total": 0})
	}
	s.MustHandle("GET", Prefix+"/zones", ok)
	s.MustHandle("POST", Prefix+"/zones", ok)
	s.MustHandle("GET", Prefix+"/config", ok)
	s.MustHandle("PUT", Prefix+"/config", ok)

	if w := do(s, "GET", Prefix+"/zones", "", ""); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("anonymous = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/zones", "bogus", ""); w.Code != 401 {
		t.Fatalf("bad token = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/zones", "tok-notent", ""); w.Code != 401 {
		t.Fatalf("tenantless identity = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/zones", "tok-viewer", ""); w.Code != 200 {
		t.Fatalf("viewer read = %d %s", w.Code, w.Body)
	}
	body := `{"name":"example.com","kind":"native"}`
	if w := do(s, "POST", Prefix+"/zones", "tok-viewer", body); w.Code != 403 || reason(t, w) != "forbidden" {
		t.Fatalf("viewer create = %d %s", w.Code, w.Body)
	}
	if w := do(s, "POST", Prefix+"/zones", "tok-admin", body); w.Code != 200 {
		t.Fatalf("admin create = %d %s", w.Code, w.Body)
	}
	// config:manage is granted to no tenant role: a tenant owner/admin is refused
	if w := do(s, "GET", Prefix+"/config", "tok-admin", ""); w.Code != 403 {
		t.Fatalf("tenant admin config = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/config", "tok-padmin", ""); w.Code != 200 {
		t.Fatalf("platform admin config = %d", w.Code)
	}
	if s.Permission("PUT", Prefix+"/config") != authz.ConfigManage || s.Permission("GET", Prefix+"/health") != "" {
		t.Fatal("permission lookup")
	}

	// no checker installed: fail closed
	closed := newServer(t, WithChecker(nil))
	closed.MustHandle("GET", Prefix+"/zones", ok)
	if w := do(closed, "GET", Prefix+"/zones", "tok-admin", ""); w.Code != 403 {
		t.Fatalf("nil checker = %d", w.Code)
	}
	// no verifier installed: unauthenticated
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	nov, err := NewHandler(rt)
	if err != nil {
		t.Fatal(err)
	}
	nov.MustHandle("GET", Prefix+"/zones", ok)
	if w := do(nov, "GET", Prefix+"/zones", "tok-admin", ""); w.Code != 401 {
		t.Fatalf("nil verifier = %d", w.Code)
	}
}

func TestContractValidation(t *testing.T) {
	s := newServer(t)
	s.MustHandle("GET", Prefix+"/zones", func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 200, map[string]any{}) })
	s.MustHandle("POST", Prefix+"/zones", func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 201, map[string]any{}) })
	s.MustHandle("POST", Prefix+"/zones/{id}/records", func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 200, map[string]any{}) })
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"GET", Prefix + "/zones?page_size=1000", "", 422},
		{"GET", Prefix + "/zones?page=0", "", 422},
		{"GET", Prefix + "/zones?kind=bogus", "", 422},
		{"GET", Prefix + "/zones?page=2&page_size=50&kind=master&origin=ipam", "", 200},
		{"POST", Prefix + "/zones", `{"name":""}`, 422},
		{"POST", Prefix + "/zones", `{"name":"x.example","kind":"native","api_key":"k"}`, 422},
		{"POST", Prefix + "/zones", `{"name":"x.example","kind":"hidden"}`, 422},
		{"POST", Prefix + "/zones", `{not json`, 400},
		{"POST", Prefix + "/zones", `{"name":"x.example","kind":"slave","masters":["192.0.2.1"]}`, 201},
		{"POST", Prefix + "/zones/abc/records", `{"name":"www","type":"A","ttl":300,"values":[{"content":"192.0.2.1"}]}`, 200},
		{"POST", Prefix + "/zones/abc/records", `{"name":"www","type":"SOA","ttl":300,"values":[{"content":"x"}]}`, 422},
		{"POST", Prefix + "/zones/abc/records", `{"name":"www","type":"A","ttl":300,"values":[]}`, 422},
		{"PATCH", Prefix + "/zones", "", 405},
		{"GET", "/api/dns/v1/nowhere", "", 404},
		{"GET", Prefix + "/zones/abc", "", 501},
	}
	for _, c := range cases {
		w := do(s, c.method, c.path, "tok-padmin", c.body)
		if w.Code != c.want {
			t.Errorf("%s %s %s = %d (%s), want %d", c.method, c.path, c.body, w.Code, w.Body, c.want)
		}
	}
	big := `{"name":"` + strings.Repeat("a", MaxBodyBytes) + `","kind":"native"}`
	if w := do(s, "POST", Prefix+"/zones", "tok-padmin", big); w.Code != 413 {
		t.Errorf("oversized = %d", w.Code)
	}
	// CSRF header is required on mutations
	r := httptest.NewRequest("POST", Prefix+"/zones", strings.NewReader(`{"name":"x.example","kind":"native"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer tok-padmin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 422 {
		t.Errorf("missing csrf = %d", w.Code)
	}
}

func TestRouteBookkeeping(t *testing.T) {
	s := newServer(t)
	if err := s.HandleFunc("GET", "/api/dns/v1/undeclared", func(http.ResponseWriter, *http.Request) {}); err == nil {
		t.Fatal("undeclared route accepted")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("MustHandle on undeclared route must panic")
			}
		}()
		s.MustHandle("GET", "/nope", func(http.ResponseWriter, *http.Request) {})
	}()
	before := len(s.Missing())
	s.Register(Deps{})
	if len(s.Implemented()) != 1 || len(s.Missing()) != before-1 || len(s.Declared()) != before {
		t.Fatalf("implemented=%d missing=%d declared=%d", len(s.Implemented()), len(s.Missing()), len(s.Declared()))
	}
	if s.Document() == nil || s.Edge() != nil {
		t.Fatal("accessors")
	}
}

func TestRemoteServing(t *testing.T) {
	dist := fstest.MapFS{
		"mf-manifest.json":  {Data: []byte(`{}`)},
		"assets/app-abc.js": {Data: []byte(`console.log(1)`)},
		"remoteEntry.js":    {Data: []byte(`export {}`)},
	}
	s := newServer(t, WithRemote(dist))
	w := do(s, "GET", "/ui/assets/app-abc.js", "", "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset = %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	if w := do(s, "GET", "/ui/mf-manifest.json", "", ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest = %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	for _, p := range []string{"/ui/", "/ui/assets/", "/ui/missing.js"} {
		if w := do(s, "GET", p, "", ""); w.Code != 404 {
			t.Errorf("%s = %d", p, w.Code)
		}
	}
}

func TestSubjectsCarryVerifiedRolesOnly(t *testing.T) {
	if _, err := Subjects(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("subjects without identity")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(authclient.WithIdentity(r.Context(), authclient.Identity{UserID: padmin, TenantID: tenant, Roles: []string{authz.RolePlatformAdmin}}))
	s, err := Subjects(r)
	if err != nil || s.ActorKind != authz.ActorUser || !s.IsPlatformAdmin() || s.TenantID != tenant {
		t.Fatalf("subjects = %+v %v", s, err)
	}
	if c, err := Caller(r); err != nil || c.UserID != padmin || RequestID(r) != "" {
		t.Fatal("caller")
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		reason string
	}{
		{ErrInvalidRecord, 422, "invalid_record"},
		{fmt.Errorf("wrap: %w", ErrDuplicate), 409, "duplicate"},
		{&http.MaxBytesError{Limit: 1}, 413, "body_too_large"},
		{authz.ErrForbidden, 403, "forbidden"},
		{fmt.Errorf("%w: x", validate.ErrName), 422, "invalid_name"},
		{fmt.Errorf("%w: x", validate.ErrMasters), 400, "bad_request"},
		{repo.ErrNotFound, 404, "not_found"},
		{repo.ErrConflict, 409, "conflict"},
		{fmt.Errorf("%w: down", pdns.ErrUnavailable), 503, "pdns_unavailable"},
		{errors.New("db exploded"), 503, "temporarily_unavailable"},
	}
	for _, c := range cases {
		st, r := Status(c.err)
		if st != c.status || r != c.reason {
			t.Errorf("%v => %d %s", c.err, st, r)
		}
	}
	for _, e := range []*Error{ErrInvalidName, ErrInvalidKind, ErrInvalidConfig, ErrZoneNotFound, ErrRecordNotFound, ErrTemplateNotFound,
		ErrPDNSUnavailable, ErrMetricsUnavailable, ErrRateLimited, ErrBadRequest, ErrNotImplemented} {
		if st, r := Status(e); st != e.Status || r != e.Reason || r == "" {
			t.Errorf("%s mapping", e.Reason)
		}
	}
	w := httptest.NewRecorder()
	Fail(w, httptest.NewRequest("GET", "/x", nil), nil, errors.New("secret detail"))
	if strings.Contains(w.Body.String(), "secret detail") || w.Code != 503 {
		t.Fatalf("fail leaked: %s", w.Body)
	}
	w = httptest.NewRecorder()
	WriteDetail(w, ErrInvalidRecord, map[string]any{"field": "values[0]"})
	if !strings.Contains(w.Body.String(), `"field":"values[0]"`) || w.Code != 422 {
		t.Fatal("detail")
	}
	if ErrConflict.Error() != "conflict" {
		t.Fatal("error string")
	}
}

func TestDecodeJSON(t *testing.T) {
	var v struct{ A int }
	req := func(b string) *http.Request { return httptest.NewRequest("POST", "/", strings.NewReader(b)) }
	if err := DecodeJSON(req(`{"A":1}`), &v, 0); err != nil || v.A != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"B":1}`, `{"A":1} {}`, `nope`} {
		if err := DecodeJSON(req(bad), &v, 0); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := DecodeJSON(req(`{"A":1111111}`), &v, 4); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("limit: %v", err)
	}
}
