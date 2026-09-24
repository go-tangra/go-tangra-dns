// Package contract verifies the DNS OpenAPI document against the mounted HTTP
// surface and the gateway manifest (T024): the document parses and validates;
// it declares exactly the routes of contracts/dns-api.md §A; every route
// declares a permission (only /health is public); configuration routes carry
// config:manage; every mutating route requires the CSRF header; every route the
// server mounts is declared; and no schema — request or response — can carry an
// API key, password or token.
package contract

import (
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-dns/v4/pkg/dnsmanifest"
)

// contractRoutes are the routes of contracts/dns-api.md §A.
var contractRoutes = []string{
	"GET /api/dns/v1/zones", "POST /api/dns/v1/zones",
	"GET /api/dns/v1/zones/{id}", "PUT /api/dns/v1/zones/{id}", "DELETE /api/dns/v1/zones/{id}",
	"GET /api/dns/v1/zones/{id}/export", "POST /api/dns/v1/zones/{id}/notify",
	"GET /api/dns/v1/zones/{id}/records", "POST /api/dns/v1/zones/{id}/records",
	"PUT /api/dns/v1/zones/{id}/records", "DELETE /api/dns/v1/zones/{id}/records",
	"GET /api/dns/v1/templates", "POST /api/dns/v1/templates",
	"GET /api/dns/v1/templates/{id}", "PUT /api/dns/v1/templates/{id}", "DELETE /api/dns/v1/templates/{id}",
	"GET /api/dns/v1/supermasters", "POST /api/dns/v1/supermasters",
	"GET /api/dns/v1/supermasters/{id}", "DELETE /api/dns/v1/supermasters/{id}",
	"GET /api/dns/v1/config", "PUT /api/dns/v1/config",
	"GET /api/dns/v1/dashboard", "GET /api/dns/v1/stream",
	"POST /api/dns/v1/backup/export", "POST /api/dns/v1/backup/import",
	"GET /api/dns/v1/health",
}

func TestDocumentMatchesContract(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatalf("document: %v", err)
	}
	declared := map[string]bool{}
	for _, r := range httpapi.DeclaredRoutes(doc) {
		declared[r.String()] = true
	}
	for _, want := range contractRoutes {
		if !declared[want] {
			t.Errorf("contract route %s is not declared", want)
		}
	}
	if len(declared) != len(contractRoutes) {
		t.Errorf("declared %d routes, contract lists %d", len(declared), len(contractRoutes))
	}
	if declared["PUT /api/dns/v1/supermasters/{id}"] {
		t.Error("supermasters have no update route (FR-007)")
	}

	routes, err := dnsmanifest.Routes(doc)
	if err != nil {
		t.Fatalf("manifest routes: %v", err)
	}
	public := httpapi.PublicRoutes(doc)
	if len(public) != 1 || !public[httpapi.Route{Method: "GET", Path: "/api/dns/v1/health"}] {
		t.Fatalf("exactly /health is public: %v", public)
	}
	perms := httpapi.RoutePermissions(doc)
	for _, r := range routes {
		if r.Public {
			continue
		}
		if !authz.Known(r.Permission) {
			t.Errorf("%s %s: unknown permission %q", r.Method, r.Path, r.Permission)
		}
		if r.Path == "/api/dns/v1/stream" && r.Timeout != 5*time.Minute {
			t.Errorf("/stream must declare the 300 s route maximum, got %v", r.Timeout)
		}
	}
	// Server configuration is config:manage (plus platform-admin in the handler);
	// no other route uses config:manage.
	for key, p := range perms {
		isConfig := strings.HasSuffix(key, " /api/dns/v1/config")
		if isConfig != (p == authz.ConfigManage) {
			t.Errorf("%s declares %s", key, p)
		}
	}
	for key, want := range map[string]string{
		"GET /api/dns/v1/zones": authz.ZonesRead, "POST /api/dns/v1/zones": authz.ZonesManage,
		"DELETE /api/dns/v1/zones/{id}/records": authz.ZonesManage, "GET /api/dns/v1/zones/{id}/records": authz.ZonesRead,
		"GET /api/dns/v1/templates": authz.ZonesRead, "POST /api/dns/v1/templates": authz.TemplatesManage,
		"POST /api/dns/v1/supermasters": authz.SupermastersManage, "GET /api/dns/v1/dashboard": authz.DashboardRead,
		"POST /api/dns/v1/backup/import": authz.BackupManage, "GET /api/dns/v1/stream": authz.ZonesRead,
		"POST /api/dns/v1/zones/{id}/notify": authz.ZonesManage,
	} {
		if perms[key] != want {
			t.Errorf("%s = %q, want %q", key, perms[key], want)
		}
	}
}

func TestMutationsRequireCSRF(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			if m == "GET" || m == "HEAD" {
				continue
			}
			found := false
			for _, prm := range op.Parameters {
				if prm.Value != nil && prm.Value.In == "header" && prm.Value.Name == "X-CSRF-Token" && prm.Value.Required {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s does not require X-CSRF-Token", m, p)
			}
		}
	}
}

// forbiddenFields must never appear in any schema of the document.
var forbiddenFields = []string{"api_key", "apikey", "x-api-key", "api_key_ref", "password", "token", "secret", "rendered", "file_content"}

// schemaFields collects (recursively) every property name of s.
func schemaFields(s *openapi3.SchemaRef, out map[string]bool, seen map[*openapi3.Schema]bool) {
	if s == nil || s.Value == nil || seen[s.Value] {
		return
	}
	v := s.Value
	seen[v] = true
	for k, p := range v.Properties {
		out[strings.ToLower(k)] = true
		schemaFields(p, out, seen)
	}
	schemaFields(v.Items, out, seen)
	if v.AdditionalProperties.Schema != nil {
		schemaFields(v.AdditionalProperties.Schema, out, seen)
	}
	for _, group := range []openapi3.SchemaRefs{v.AllOf, v.AnyOf, v.OneOf} {
		for _, sub := range group {
			schemaFields(sub, out, seen)
		}
	}
}

// No request or response schema, and no parameter, carries an API key (SR-002).
func TestNoSchemaCarriesAnAPIKey(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	for _, s := range doc.Components.Schemas {
		schemaFields(s, fields, map[*openapi3.Schema]bool{})
	}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			for _, prm := range op.Parameters {
				if prm.Value != nil && prm.Value.Name != "X-CSRF-Token" {
					fields[strings.ToLower(prm.Value.Name)] = true
				}
			}
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, media := range op.RequestBody.Value.Content {
					schemaFields(media.Schema, fields, map[*openapi3.Schema]bool{})
				}
			}
			if op.Responses == nil {
				continue
			}
			for _, resp := range op.Responses.Map() {
				if resp.Value == nil {
					continue
				}
				for _, media := range resp.Value.Content {
					schemaFields(media.Schema, fields, map[*openapi3.Schema]bool{})
				}
			}
		}
	}
	if len(fields) < 20 {
		t.Fatalf("schema walk found only %d fields", len(fields))
	}
	for f := range fields {
		for _, bad := range forbiddenFields {
			if strings.Contains(f, bad) {
				t.Errorf("the document exposes field %q", f)
			}
		}
	}
}

// Every route the server mounts is declared (Handle refuses anything else),
// and the foundational /health route is mounted.
func TestMountedRoutesAreDeclared(t *testing.T) {
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	s, err := httpapi.NewHandler(rt)
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{})
	declared := map[string]bool{}
	for _, r := range s.Declared() {
		declared[r.String()] = true
	}
	impl := s.Implemented()
	for _, r := range impl {
		if !declared[r.String()] {
			t.Errorf("mounted but undeclared: %s", r)
		}
	}
	got := []string{}
	for _, r := range impl {
		got = append(got, r.String())
	}
	if !strings.Contains(strings.Join(got, ","), "GET /api/dns/v1/health") {
		t.Errorf("/health not mounted (have %v)", got)
	}
	if err := s.HandleFunc("GET", "/api/dns/v1/query", nil); err == nil {
		t.Fatal("an undeclared route (arbitrary PromQL proxy) was mounted")
	}
}
