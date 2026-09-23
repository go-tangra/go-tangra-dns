// Package dnsmanifest declares what the DNS module registers with the
// application gateway: routes derived from the embedded OpenAPI document, the
// API permissions, the CASL abilities and the navigation entries; plus the
// built-in role grants it seeds with the auth service. The dns.v1 gRPC surface
// is service-to-service and is not proxied by the gateway.
package dnsmanifest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"google.golang.org/grpc"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/dns/api/openapi"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
)

// Module identity.
const (
	Module       = "dns"
	DisplayName  = "DNS"
	Version      = "1.0.0"
	RemotePrefix = "/ui"
	APIPrefix    = "/api/dns"
)

// OpenAPI operation extensions.
const (
	PermissionExtension = "x-freya-permission"
	PublicExtension     = "x-freya-public"
	BodyLimitExtension  = "x-freya-max-body-bytes"
	TimeoutExtension    = "x-freya-timeout-seconds"
)

// Permissions the module registers (research D16).
var Permissions = []gatewayclient.Permission{
	{Resource: "zones", Action: "read", Description: "List and read zones, record sets and templates, and the live stream"},
	{Resource: "zones", Action: "manage", Description: "Create, edit and delete zones and record sets; export zones and send NOTIFY"},
	{Resource: "templates", Action: "manage", Description: "Manage zone templates"},
	{Resource: "supermasters", Action: "manage", Description: "View supermasters (create/delete also need platform administration)"},
	{Resource: "dashboard", Action: "read", Description: "Read the DNS health dashboard"},
	{Resource: "backup", Action: "manage", Description: "Export and import tenant DNS data"},
	{Resource: "config", Action: "manage", Description: "Edit the DNS server configuration (platform administrators only)"},
}

// TenantPermissions are every permission a tenant role may hold: all but
// config:manage, which is granted to no built-in tenant role (the handlers
// additionally require platform-admin).
func TenantPermissions() []string {
	var out []string
	for _, p := range PermissionRefs() {
		if p != "config:manage" {
			out = append(out, p)
		}
	}
	return out
}

// Module roles (research D16): what each seeded role may do.
var Roles = map[string][]string{
	"dns admin":  TenantPermissions(),
	"dns viewer": {"zones:read", "dashboard:read"},
}

// Grants maps the platform's built-in role slugs to the module roles: owners
// and admins are DNS admins; operators, members and auditors are DNS viewers.
var Grants = map[string][]string{
	"owner":    Roles["dns admin"],
	"admin":    Roles["dns admin"],
	"operator": Roles["dns viewer"],
	"member":   Roles["dns viewer"],
	"auditor":  Roles["dns viewer"],
}

// Methods proxied by the gateway: none (dns gRPC is service to service).
var Methods []gatewayclient.Method

// Abilities are the CASL rules bound to the permissions.
var Abilities = []gatewayclient.Ability{
	{Action: []string{"read"}, Subject: []string{"DnsZone", "DnsRecord", "DnsTemplate"}, Requires: "zones:read"},
	{Action: []string{"create", "update", "delete", "export", "notify"}, Subject: []string{"DnsZone", "DnsRecord"}, Requires: "zones:manage"},
	{Action: []string{"manage"}, Subject: []string{"DnsTemplate"}, Requires: "templates:manage"},
	{Action: []string{"read"}, Subject: []string{"DnsSupermaster"}, Requires: "supermasters:manage"},
	// Creating/deleting supermasters needs platform administration (research
	// D15, enforced server-side); config:manage is held only by platform
	// administrators (no tenant role grants it), so it gates the UI actions.
	{Action: []string{"create", "delete"}, Subject: []string{"DnsSupermaster"}, Requires: "config:manage"},
	{Action: []string{"read"}, Subject: []string{"DnsDashboard"}, Requires: "dashboard:read"},
	{Action: []string{"manage"}, Subject: []string{"DnsBackup"}, Requires: "backup:manage"},
	{Action: []string{"manage"}, Subject: []string{"DnsConfig"}, Requires: "config:manage"},
}

// Nav lists the navigation contributions.
var Nav = []gatewayclient.NavEntry{
	{Title: "Zones", Path: "/dns", Icon: "mdi-dns-outline", Order: 980, Requires: "zones:read"},
	{Title: "Templates", Path: "/dns/templates", Icon: "mdi-file-document-multiple-outline", Order: 982, Requires: "zones:read"},
	{Title: "Supermasters", Path: "/dns/supermasters", Icon: "mdi-server-network", Order: 984, Requires: "supermasters:manage"},
	{Title: "Dashboard", Path: "/dns/dashboard", Icon: "mdi-chart-line", Order: 986, Requires: "dashboard:read"},
	{Title: "Configuration", Path: "/dns/configuration", Icon: "mdi-cog-outline", Order: 988, Requires: "config:manage"},
}

// PermissionRefs lists "resource:action" for every declared permission.
func PermissionRefs() []string {
	out := make([]string, 0, len(Permissions))
	for _, p := range Permissions {
		out = append(out, p.Resource+":"+p.Action)
	}
	return out
}

// Routes derives the gateway routes from the OpenAPI document.
func Routes(doc *openapi3.T) ([]gatewayclient.Route, error) {
	known := map[string]bool{}
	for _, p := range PermissionRefs() {
		known[p] = true
	}
	var routes []gatewayclient.Route
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			r := gatewayclient.Route{Method: strings.ToUpper(m), Path: p}
			perm, _ := op.Extensions[PermissionExtension].(string)
			public, _ := op.Extensions[PublicExtension].(bool)
			switch {
			case public:
				r.Public = true
			case perm == "":
				return nil, fmt.Errorf("dnsmanifest: %s %s declares no permission", r.Method, p)
			case !known[perm]:
				return nil, fmt.Errorf("dnsmanifest: %s %s uses undeclared permission %q", r.Method, p, perm)
			default:
				r.Permission = perm
			}
			if v, ok := op.Extensions[BodyLimitExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 {
					return nil, fmt.Errorf("dnsmanifest: %s %s has a bad body limit", r.Method, p)
				}
				r.MaxBodyBytes = uint64(n)
			}
			if v, ok := op.Extensions[TimeoutExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 || n > 600 {
					return nil, fmt.Errorf("dnsmanifest: %s %s has a bad timeout", r.Method, p)
				}
				r.Timeout = time.Duration(n) * time.Second
			}
			routes = append(routes, r)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path })
	return routes, nil
}

// Load parses the embedded document.
func Load() (*openapi3.T, error) {
	return openapi3.NewLoader().LoadFromData(openapi.DNS)
}

// Manifest builds the gateway manifest from the embedded OpenAPI document.
func Manifest() (gatewayclient.Manifest, error) {
	doc, err := Load()
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	routes, err := Routes(doc)
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	return gatewayclient.Manifest{
		Module: Module, DisplayName: DisplayName, Version: Version,
		Prefixes:    []string{APIPrefix},
		Routes:      routes,
		Methods:     Methods,
		Permissions: Permissions,
		Abilities:   Abilities,
		Exposes:     []string{"./routes", "./nav"},
		Nav:         Nav,
	}, nil
}

// BuiltinRoles lists the built-in role slugs seeded, in a stable order.
var BuiltinRoles = []string{"owner", "admin", "member", "auditor", "operator"}

// SeedRequest builds the auth registration request: every module permission
// plus the built-in role grants.
func SeedRequest() *authv1.RegisterPermissionsRequest {
	req := &authv1.RegisterPermissionsRequest{}
	for _, p := range Permissions {
		req.Permissions = append(req.Permissions, &authv1.PermissionDef{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	for _, slug := range BuiltinRoles {
		req.BuiltinGrants = append(req.BuiltinGrants, &authv1.BuiltinGrant{Role: slug, Permissions: Grants[slug]})
	}
	return req
}

// SeedPermissions registers the module's permissions with the auth service and
// grants them to the built-in roles (idempotent).
func SeedPermissions(ctx context.Context, cc grpc.ClientConnInterface) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := authv1.NewAuthorizationClient(cc).RegisterPermissions(ctx, SeedRequest())
	return err
}
