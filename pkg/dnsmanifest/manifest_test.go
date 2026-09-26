package dnsmanifest

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-tangra/go-tangra-dns/v4/api/openapi"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
)

func TestOpenAPIParsesAndValidates(t *testing.T) {
	openapi3.DefineStringFormatValidator("uuid", openapi3.NewRegexpFormatValidator(openapi3.FormatOfStringForUUIDOfRFC9562))
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(openapi.DNS)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := doc.Validate(loader.Context, openapi3.DisableExamplesValidation()); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestManifestBuilds(t *testing.T) {
	m, err := Manifest()
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.Module != "dns" || len(m.Prefixes) != 1 || m.Prefixes[0] != "/api/dns" || len(m.Methods) != 0 {
		t.Fatalf("identity = %+v", m)
	}
	if len(m.Routes) != 27 {
		t.Fatalf("routes = %d", len(m.Routes))
	}
	public := 0
	for _, r := range m.Routes {
		if !strings.HasPrefix(r.Path, "/api/dns/v1/") {
			t.Fatalf("route outside prefix: %s", r.Path)
		}
		if r.Public {
			public++
			if r.Path != "/api/dns/v1/health" {
				t.Fatalf("unexpected public route %s", r.Path)
			}
		}
		if r.Path == "/api/dns/v1/config" && r.Permission != "config:manage" {
			t.Fatalf("config route permission = %s", r.Permission)
		}
		if r.Path == "/api/dns/v1/stream" && r.Timeout.Seconds() != 300 {
			t.Fatalf("stream timeout = %v", r.Timeout)
		}
		if r.Path == "/api/dns/v1/backup/import" && r.MaxBodyBytes != 64<<20 {
			t.Fatalf("import body limit = %d", r.MaxBodyBytes)
		}
	}
	if public != 1 {
		t.Fatalf("public routes = %d", public)
	}
	titles := []string{}
	for _, n := range m.Nav {
		titles = append(titles, n.Title)
	}
	if strings.Join(titles, ",") != "Zones,Templates,Supermasters,Dashboard,Configuration" {
		t.Fatalf("nav = %v", titles)
	}
	if len(m.Abilities) != 8 || len(m.Permissions) != 7 {
		t.Fatalf("abilities/permissions = %d/%d", len(m.Abilities), len(m.Permissions))
	}
}

// The manifest's permission vocabulary is exactly the module's authz set.
func TestPermissionsMatchAuthz(t *testing.T) {
	got := PermissionRefs()
	want := append([]string(nil), authz.Permissions...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("manifest %v != authz %v", got, want)
	}
}

// TestRoles pins the module role set (feature 019, research D9).
func TestRoles(t *testing.T) {
	want := map[string][]string{
		"administrator": {"zones:read", "zones:manage", "templates:manage", "supermasters:manage", "dashboard:read", "backup:manage"},
		"viewer":        {"zones:read", "dashboard:read"},
	}
	names := map[string]string{"administrator": "DNS administrator", "viewer": "DNS viewer"}
	if len(Roles) != len(want) {
		t.Fatalf("want %d roles, got %d", len(want), len(Roles))
	}
	own := map[string]bool{}
	for _, r := range PermissionRefs() {
		own[r] = true
	}
	slug := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	for _, r := range Roles {
		if !slug.MatchString(r.Slug) {
			t.Errorf("role slug %q", r.Slug)
		}
		if r.DisplayName != names[r.Slug] || r.Description == "" {
			t.Errorf("role %q: display name %q, description %q", r.Slug, r.DisplayName, r.Description)
		}
		if !reflect.DeepEqual(r.Permissions, want[r.Slug]) {
			t.Errorf("role %q: permissions %v, want %v", r.Slug, r.Permissions, want[r.Slug])
		}
		for _, p := range r.Permissions {
			if !own[p] {
				t.Errorf("role %q names %q, not a DNS permission", r.Slug, p)
			}
			if p == "config:manage" {
				t.Errorf("role %q holds config:manage (platform administrators only)", r.Slug)
			}
		}
	}
}

// TestBuiltinGrantsUnchanged: the built-in grants are those registered before
// module roles existed (auth now scopes them to the module).
func TestBuiltinGrantsUnchanged(t *testing.T) {
	admin := []string{"zones:read", "zones:manage", "templates:manage", "supermasters:manage", "dashboard:read", "backup:manage"}
	viewer := []string{"zones:read", "dashboard:read"}
	want := map[string][]string{"owner": admin, "admin": admin, "operator": viewer, "member": viewer, "auditor": viewer}
	if !reflect.DeepEqual(Grants, want) {
		t.Fatalf("built-in grants changed:\n got %v\nwant %v", Grants, want)
	}
	if len(BuiltinRoles) != len(Grants) {
		t.Fatalf("BuiltinRoles %v vs grants %v", BuiltinRoles, Grants)
	}
	for _, slug := range BuiltinRoles {
		if len(Grants[slug]) == 0 {
			t.Fatalf("no grant for %s", slug)
		}
	}
}

// TestRegistration: the auth registration carries the module identity, every
// permission, the complete role set and the built-in grants, and is valid.
func TestRegistration(t *testing.T) {
	reg := Registration()
	if err := reg.Validate(); err != nil {
		t.Fatal(err)
	}
	req := reg.Request()
	if req.GetModule() != "dns" || req.GetModuleDisplayName() != "DNS" || !req.GetDeclaresRoles() {
		t.Fatalf("module %q display %q declares_roles %v", req.GetModule(), req.GetModuleDisplayName(), req.GetDeclaresRoles())
	}
	if len(req.GetPermissions()) != 7 || len(req.GetRoles()) != 2 {
		t.Fatalf("%d permissions, %d roles", len(req.GetPermissions()), len(req.GetRoles()))
	}
	got := map[string][]string{}
	for _, g := range req.GetBuiltinGrants() {
		got[g.GetRole()] = g.GetPermissions()
	}
	if !reflect.DeepEqual(got, Grants) {
		t.Fatalf("builtin grants %v", got)
	}
}

func docWith(ext map[string]any) *openapi3.T {
	paths := openapi3.NewPaths()
	paths.Set("/x", &openapi3.PathItem{Get: &openapi3.Operation{Extensions: ext}})
	return &openapi3.T{Paths: paths}
}

func TestRoutesValidationBranches(t *testing.T) {
	routes, err := Routes(docWith(map[string]any{PublicExtension: true}))
	if err != nil || !routes[0].Public {
		t.Fatalf("public: %v", err)
	}
	routes, err = Routes(docWith(map[string]any{PermissionExtension: "zones:read", BodyLimitExtension: float64(2048), TimeoutExtension: float64(30)}))
	if err != nil || routes[0].MaxBodyBytes != 2048 || routes[0].Timeout.Seconds() != 30 {
		t.Fatalf("valid: %v %+v", err, routes)
	}
	bad := []map[string]any{
		{},
		{PermissionExtension: "made:up"},
		{PermissionExtension: "zones:read", BodyLimitExtension: float64(0)},
		{PermissionExtension: "zones:read", BodyLimitExtension: "big"},
		{PermissionExtension: "zones:read", TimeoutExtension: float64(9999)},
		{PermissionExtension: "zones:read", TimeoutExtension: "slow"},
	}
	for i, ext := range bad {
		if _, err := Routes(docWith(ext)); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
