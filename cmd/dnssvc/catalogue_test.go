package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/catalogue"
	"github.com/go-tangra/go-tangra/v4/identity"

	"github.com/go-tangra/go-tangra-dns/v4/pkg/dnsmanifest"
)

var placeholderRE = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// joinValues are values of the shape the gateway fills in: core values,
// generated secrets and the host inputs.
var joinValues = map[string]string{
	"TRUST_DOMAIN": "infra.example.org", "GATEWAY_ISSUER": "https://portal.example.org:8443",
	"LCM_ENROLL_URL": "https://portal.example.org:8443/api/lcm/v1/enroll", "LCM_GRPC": "portal.example.org:9945",
	"GATEWAY_GRPC": "portal.example.org:9643", "AUTH_GRPC": "portal.example.org:9543", "MESH_TENANT_ID": "00000000-0000-0000-0000-000000000001",
	"MODULE_IMAGE": "ghcr.io/go-tangra/go-tangra-dns", "MODULE_VERSION": "4.2.0",
	"GEN_PASSWORD_1": strings.Repeat("a", 48), "GEN_PASSWORD_2": strings.Repeat("b", 48),
	"GEN_KEY_1":             "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	"MODULE_ADVERTISE_HOST": "dns.example.org", "MODULE_BIND_IP": "10.0.0.5",
	"VALKEY_ADDRESS": "valkey.example.org:6380", "VALKEY_PASSWORD": strings.Repeat("c", 32), "VALKEY_CA_FILE": "/etc/tangra/valkey-ca.pem",
	"PDNS_AUTH_BIND_IP": "0.0.0.0", "PDNS_AUTH_PORT": "53", "PDNS_RECURSOR_BIND_IP": "127.0.0.1", "PDNS_RECURSOR_PORT": "5301",
}

func readRepoFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// tangra-module.yaml passes the catalogue's own checks, names this module
// and asks only for its own routes; compose.yaml (interpolated from the
// gateway's .env) uses only values the gateway writes there.
func TestCatalogueDescriptor(t *testing.T) {
	d, err := catalogue.ParseDescriptor(readRepoFile(t, "tangra-module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Module != dnsmanifest.Module || d.Bundle.Dir != "deploy/bundle" || !slices.Contains(d.Routes.Prefixes, dnsmanifest.APIPrefix) {
		t.Fatalf("%+v", d)
	}
	inputs := map[string]bool{}
	for _, in := range d.HostInputs {
		inputs[in.Key] = true
		if !regexp.MustCompile(in.Pattern).MatchString(joinValues[in.Key]) {
			t.Errorf("host input %s refuses %q", in.Key, joinValues[in.Key])
		}
		if in.Default != "" && !regexp.MustCompile(in.Pattern).MatchString(in.Default) {
			t.Errorf("host input %s refuses its own default %q", in.Key, in.Default)
		}
	}
	for _, m := range placeholderRE.FindAllStringSubmatch(string(readRepoFile(t, "deploy", "bundle", "compose.yaml")), -1) {
		if k := m[1]; !inputs[k] && !catalogue.Reserved(k) {
			t.Errorf("compose.yaml uses %s, which the gateway does not write to .env", k)
		}
	}
	bundle, err := catalogue.PackBundle(os.DirFS(filepath.Join("..", "..", d.Bundle.Dir)))
	if err != nil {
		t.Fatal(err)
	}
	e, err := catalogue.BuildEntry(d, "4.2.0", "go-tangra/go-tangra-dns", dnsmanifest.PermissionRefs(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.CheckBundle(bundle); err != nil {
		t.Fatal(err)
	}
	files, err := catalogue.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append([]string{"compose.yaml", "init-db.sh", "init-pdns.sh", "pdns/pdns.conf", "pdns/recursor.yml"}, d.Bundle.Templates...) {
		if _, ok := files[name]; !ok {
			t.Errorf("%s missing from the bundle", name)
		}
	}
}

// The join bundle's templates, rendered with values of the shape the gateway
// fills in, are a valid configuration and policy with the production TLS
// guards met (env stays "dev" only for the file: PowerDNS key references).
func TestJoinBundleRendersToValidConfig(t *testing.T) {
	values := joinValues
	dir := t.TempDir()
	for _, name := range []string{"config.yaml", "policy.yaml"} {
		raw := readRepoFile(t, "deploy", "bundle", name)
		var missing []string
		rendered := placeholderRE.ReplaceAllStringFunc(string(raw), func(m string) string {
			k := placeholderRE.FindStringSubmatch(m)[1]
			v, ok := values[k]
			if !ok {
				missing = append(missing, k)
			}
			return v
		})
		if len(missing) > 0 {
			t.Fatalf("%s uses placeholders the gateway does not fill: %v", name, missing)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := loadConfig([]string{"-config", filepath.Join(dir, "config.yaml")})
	if err != nil {
		t.Fatalf("rendered config invalid: %v", err)
	}
	if cfg.Gateway.Issuer != "https://portal.example.org:8443" || cfg.ACME.AllowedCaller != "spiffe://infra.example.org/svc/lcm" {
		t.Fatalf("%+v %+v", cfg.Gateway, cfg.ACME)
	}
	if !strings.Contains(cfg.DB.DSN, "sslmode=verify-full") || !strings.Contains(cfg.DB.MigrateDSN, "sslmode=verify-full") ||
		cfg.Valkey.AllowPlaintext || cfg.Valkey.CAFile != "/tls/valkey-ca.pem" || cfg.Valkey.Username != "dns" ||
		cfg.Valkey.Addresses[0] != "valkey.example.org:6380" || cfg.Valkey.Password != strings.Repeat("c", 32) || cfg.MeshEnroll.Insecure || cfg.Docker.Enabled || cfg.IPAMSync.Enabled {
		t.Fatalf("production guards not met: %+v %+v %+v", cfg.DB, cfg.MeshEnroll, cfg.Docker)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	pol, err := authz.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		peer, op string
		want     bool
	}{
		{"spiffe://infra.example.org/svc/gateway", "GET /api/dns/v1/zones", true},
		{"spiffe://infra.example.org/svc/lcm", "/dns.v1.Challenges/Present", true},
		{"spiffe://infra.example.org/svc/ipam", "/dns.v1.Zones/Get", true},
		{"spiffe://infra.example.org/svc/ipam", "/dns.v1.Challenges/Present", false},
		{"spiffe://example.org/svc/gateway", "GET /api/dns/v1/zones", false},
	} {
		id, err := identity.ParseSPIFFEID(c.peer)
		if err != nil {
			t.Fatal(err)
		}
		if got := pol.Authorize(context.Background(), id, "dns", c.op).Allowed; got != c.want {
			t.Errorf("%s %s: allowed=%v", c.peer, c.op, got)
		}
	}
}
