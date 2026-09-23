package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tenant = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

// valid returns a Config that passes both the framework and module Validate.
func valid() Config {
	c := Default()
	c.ServiceName = "dns"
	c.TrustDomain = "example.org"
	c.Authz.Path = "/etc/dns/policy.yaml"
	c.DB.DSN = "postgres://localhost/dns"
	c.Valkey.Addresses = []string{"valkey:6379"}
	c.KEK = KEK{Source: "file", Path: "/etc/dns/kek"}
	c.PDNS.APIURL = "https://pdns-auth:8081"
	c.PDNS.APIKeyRef = "warden:0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	c.Gateway.Issuer = "https://gw.example.org"
	return c
}

func TestDefaultSecure(t *testing.T) {
	d := Default()
	if d.KEK.Source != "file" || d.Valkey.AllowPlaintext || !d.Events.Enabled || d.Docker.Enabled || d.PDNS.AllowPlaintext || d.IPAMSync.Enabled {
		t.Fatalf("insecure defaults: %+v", d)
	}
	if d.PDNS.ServerID != "localhost" || d.PDNS.TimeoutSeconds != 10 || d.PDNS.MaxResponseBytes != 32<<20 || d.PDNS.AuthForwardPort != 53 {
		t.Fatalf("pdns defaults: %+v", d.PDNS)
	}
	if d.Recursor.ReconcileIntervalSeconds != 300 || d.ACME.MaxAgeSeconds != 3600 || d.ACME.AllowedCaller != "spiffe://example.org/svc/lcm" {
		t.Fatalf("recursor/acme defaults: %+v %+v", d.Recursor, d.ACME)
	}
	if d.Records != (Records{MinTTL: 60, MaxTTL: 604800, MaxValues: 100, MaxPageSize: 500}) || d.Limits.MaxPageSize != 100 {
		t.Fatalf("records/limits defaults: %+v %+v", d.Records, d.Limits)
	}
	if err := Default().Validate(); err == nil {
		t.Fatal("Default() must not validate without required fields")
	}
}

func TestValidateOK(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	c := valid()
	c.KEK = KEK{Source: "env", Env: "DNS_KEK"}
	c.PDNS.APIURL, c.PDNS.AllowPlaintext, c.PDNS.APIKeyRef = "http://pdns-auth:8081", true, "file:/secrets/pdns.key"
	c.Recursor = Recursor{APIURL: "http://pdns-recursor:8082", ServerID: "localhost", APIKeyRef: "file:/secrets/rec.key", TimeoutSeconds: 5,
		AllowPlaintext: true, ReconcileIntervalSeconds: 60, StaticForwards: []string{".", "corp.internal."}}
	c.Docker = Docker{Enabled: true, Socket: "/var/run/docker.sock", AuthContainer: "freya-pdns-auth", RecursorContainer: "freya-pdns-recursor", TimeoutSeconds: 30}
	c.ManagedFiles = ManagedFiles{RecursorPath: "/managed/recursor/freya.yml", AuthPath: "/managed/auth/freya.conf"}
	c.Metrics = Metrics{PrometheusURL: "http://prometheus:9090", TimeoutSeconds: 5}
	c.IPAMSync = IPAMSync{Enabled: true, Tenants: []string{tenant}, Service: "ipam", DefaultTTL: 300}
	if err := c.Validate(); err != nil {
		t.Fatalf("full dev config rejected: %v", err)
	}
	c = valid()
	c.IPAMSync = IPAMSync{Enabled: true, Service: "ipam", DefaultTTL: 3600}
	c.MeshEnroll.TenantID = tenant
	if err := c.Validate(); err != nil {
		t.Fatalf("sync on the enroll tenant rejected: %v", err)
	}
	c = valid()
	c.Env = "production"
	c.DB.DSN = "postgres://db/dns?sslmode=verify-full"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]func(*Config){
		"no dsn":            func(c *Config) { c.DB.DSN = "" },
		"prod plaintext db": func(c *Config) { c.Env = "production" },
		"no valkey":         func(c *Config) { c.Valkey.Addresses = nil },
		"prod plaintext valkey": func(c *Config) {
			c.Env = "production"
			c.DB.DSN += "?sslmode=verify-full"
			c.Valkey.AllowPlaintext = true
		},
		"kek file no path":       func(c *Config) { c.KEK = KEK{Source: "file"} },
		"kek env no var":         func(c *Config) { c.KEK = KEK{Source: "env"} },
		"kek bad source":         func(c *Config) { c.KEK = KEK{Source: "vault"} },
		"no pdns url":            func(c *Config) { c.PDNS.APIURL = "" },
		"pdns url no host":       func(c *Config) { c.PDNS.APIURL = "https://" },
		"pdns url credentials":   func(c *Config) { c.PDNS.APIURL = "https://u:p@pdns:8081" },
		"pdns url query":         func(c *Config) { c.PDNS.APIURL = "https://pdns:8081/?x=1" },
		"pdns url scheme":        func(c *Config) { c.PDNS.APIURL = "ftp://pdns" },
		"pdns plaintext no flag": func(c *Config) { c.PDNS.APIURL = "http://pdns:8081" },
		"no pdns key ref":        func(c *Config) { c.PDNS.APIKeyRef = " " },
		"pdns server id":         func(c *Config) { c.PDNS.ServerID = "local host/x" },
		"pdns timeout":           func(c *Config) { c.PDNS.TimeoutSeconds = 0 },
		"pdns response cap":      func(c *Config) { c.PDNS.MaxResponseBytes = 10 },
		"pdns forward host":      func(c *Config) { c.PDNS.AuthForwardHost = "bad host" },
		"pdns forward port":      func(c *Config) { c.PDNS.AuthForwardPort = 70000 },
		"recursor plaintext":     func(c *Config) { c.Recursor.APIURL = "http://rec:8082"; c.Recursor.APIKeyRef = "x" },
		"recursor no key":        func(c *Config) { c.Recursor.APIURL = "https://rec:8082" },
		"recursor server id": func(c *Config) {
			c.Recursor.APIURL, c.Recursor.APIKeyRef, c.Recursor.ServerID = "https://rec:8082", "x", ""
		},
		"recursor timeout": func(c *Config) {
			c.Recursor.APIURL, c.Recursor.APIKeyRef, c.Recursor.TimeoutSeconds = "https://rec:8082", "x", 500
		},
		"recursor interval": func(c *Config) {
			c.Recursor.APIURL, c.Recursor.APIKeyRef, c.Recursor.ReconcileIntervalSeconds = "https://rec:8082", "x", 1
		},
		"recursor static bad": func(c *Config) {
			c.Recursor.APIURL, c.Recursor.APIKeyRef, c.Recursor.StaticForwards = "https://rec:8082", "x", []string{"bad zone"}
		},
		"recursor static many": func(c *Config) {
			c.Recursor.APIURL, c.Recursor.APIKeyRef = "https://rec:8082", "x"
			c.Recursor.StaticForwards = make([]string, 65)
		},
		"docker relative socket": func(c *Config) { c.Docker.Enabled, c.Docker.Socket = true, "docker.sock" },
		"docker unclean socket":  func(c *Config) { c.Docker.Enabled, c.Docker.Socket = true, "/var/run/../docker.sock" },
		"docker name injection":  func(c *Config) { c.Docker.Enabled, c.Docker.AuthContainer = true, "pdns/../../x" },
		"docker name leading -":  func(c *Config) { c.Docker.Enabled, c.Docker.RecursorContainer = true, "-rec" },
		"docker same names":      func(c *Config) { c.Docker.Enabled, c.Docker.RecursorContainer = true, c.Docker.AuthContainer },
		"docker timeout":         func(c *Config) { c.Docker.Enabled, c.Docker.TimeoutSeconds = true, 0 },
		"files relative":         func(c *Config) { c.ManagedFiles.AuthPath = "auth.conf" },
		"files same":             func(c *Config) { c.ManagedFiles = ManagedFiles{RecursorPath: "/m/x", AuthPath: "/m/x"} },
		"metrics url":            func(c *Config) { c.Metrics.PrometheusURL = "prom:9090" },
		"metrics timeout":        func(c *Config) { c.Metrics.TimeoutSeconds = 0 },
		"sync bad tenant":        func(c *Config) { c.IPAMSync.Tenants = []string{"acme"} },
		"sync no service":        func(c *Config) { c.IPAMSync = IPAMSync{Enabled: true, Tenants: []string{tenant}, DefaultTTL: 3600} },
		"sync no tenants":        func(c *Config) { c.IPAMSync = IPAMSync{Enabled: true, Service: "ipam", DefaultTTL: 3600} },
		"sync ttl": func(c *Config) {
			c.IPAMSync = IPAMSync{Enabled: true, Service: "ipam", Tenants: []string{tenant}, DefaultTTL: 5}
		},
		"acme caller":        func(c *Config) { c.ACME.AllowedCaller = "spiffe://example.org/svc/*" },
		"acme caller scheme": func(c *Config) { c.ACME.AllowedCaller = "lcm" },
		"acme max age":       func(c *Config) { c.ACME.MaxAgeSeconds = 1 },
		"records ttl order":  func(c *Config) { c.Records.MinTTL, c.Records.MaxTTL = 600, 60 },
		"records min ttl":    func(c *Config) { c.Records.MinTTL = 0 },
		"records values":     func(c *Config) { c.Records.MaxValues = 0 },
		"records page":       func(c *Config) { c.Records.MaxPageSize = 501 },
		"no warden":          func(c *Config) { c.Secrets.WardenService = "" },
		"refresh":            func(c *Config) { c.Secrets.RefreshSecs = 1 },
		"no gateway":         func(c *Config) { c.Gateway.Service = "" },
		"issuer http":        func(c *Config) { c.Gateway.Issuer = "http://gw" },
		"prod insecure enroll": func(c *Config) {
			c.Env = "production"
			c.DB.DSN += "?sslmode=verify-full"
			c.MeshEnroll.Enabled, c.MeshEnroll.Insecure = true, true
		},
		"request bytes": func(c *Config) { c.Limits.MaxRequestBytes = 1 },
		"backup bytes":  func(c *Config) { c.Limits.MaxBackupBytes = 1 << 40 },
		"export bytes":  func(c *Config) { c.Limits.MaxExportBytes = 1 },
		"page size":     func(c *Config) { c.Limits.MaxPageSize = 101 },
		"framework":     func(c *Config) { c.ServiceName = "" },
	}
	for name, mut := range cases {
		c := valid()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWarnings(t *testing.T) {
	c := valid()
	c.Metrics.PrometheusURL = "http://prom:9090"
	c.Recursor.APIURL = "https://rec:8082"
	for _, w := range c.Warnings() {
		if strings.Contains(w, "development only") || strings.Contains(w, "docker") {
			t.Fatalf("secure config warns: %v", w)
		}
	}
	c = valid()
	c.Valkey.AllowPlaintext = true
	c.MeshEnroll.Enabled, c.MeshEnroll.Insecure = true, true
	c.PDNS.APIURL, c.PDNS.APIKeyRef = "http://pdns:8081", "file:/k"
	c.Recursor.APIURL = "http://rec:8082"
	c.Docker.Enabled = true
	joined := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"valkey.allow_plaintext", "mesh_enroll.insecure", "pdns.api_url is plaintext", "recursor.api_url is plaintext",
		"file:", "docker.enabled", "freya-pdns-auth", "metrics.prometheus_url empty"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
	c.Recursor.APIURL = ""
	if !strings.Contains(strings.Join(c.Warnings(), "\n"), "resolver forwarding for managed zones is disabled") {
		t.Fatal("disabled recursor not warned")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dns.yaml")
	_ = os.WriteFile(p, []byte(`service_name: dns
trust_domain: example.org
pdns:
  api_url: http://pdns-auth:8081
  api_key_ref: file:/secrets/pdns.key
  allow_plaintext: true
recursor:
  api_url: http://pdns-recursor:8082
  api_key_ref: file:/secrets/recursor.key
  allow_plaintext: true
docker:
  enabled: true
limits_dns:
  max_page_size: 50
`), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.PDNS.APIURL != "http://pdns-auth:8081" || !c.Docker.Enabled || c.Docker.AuthContainer != "freya-pdns-auth" || c.Limits.MaxPageSize != 50 || c.PDNS.ServerID != "localhost" {
		t.Fatalf("loaded = %+v", c)
	}
	_ = os.WriteFile(p, []byte("pdns:\n  api_key: plaintext-secret\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field (a raw api_key) accepted")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestAccessors(t *testing.T) {
	c := valid()
	c.Server.GRPCAddr, c.Server.HTTPAddr, c.Admin.Addr = ":9965", ":9966", ":9850"
	if c.GRPCAddr() != ":9965" || c.HTTPAddr() != ":9966" || c.AdminAddr() != ":9850" {
		t.Fatal("addresses")
	}
	if c.PDNSTimeout() != 10*time.Second || c.RecursorTimeout() != 10*time.Second || c.ReconcileInterval() != 5*time.Minute ||
		c.SecretRefresh() != 5*time.Minute || c.ChallengeMaxAge() != time.Hour || c.MetricsTimeout() != 10*time.Second {
		t.Fatal("durations")
	}
	if c.RecursorEnabled() || c.AuthForwardTarget() != "pdns-auth:53" || c.AuthForwardIsIP() {
		t.Fatal("recursor/forward")
	}
	c.PDNS.AuthForwardHost = "10.0.0.5"
	if !c.AuthForwardIsIP() {
		t.Fatal("forward ip")
	}
	if got := (IPAMSync{}).SyncTenants(tenant); len(got) != 1 || got[0] != tenant {
		t.Fatalf("enroll tenant = %v", got)
	}
	if got := (IPAMSync{}).SyncTenants("nope"); got != nil {
		t.Fatalf("bad enroll tenant = %v", got)
	}
	if got := (IPAMSync{Tenants: []string{"a"}}).SyncTenants(tenant); len(got) != 1 || got[0] != "a" {
		t.Fatal("configured tenants win")
	}
}
