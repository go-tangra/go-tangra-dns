// Package config loads and validates the DNS service configuration: the Freya
// framework config plus the module's own sections. Every value is explicit and
// typed (the source read them from environment variables at call sites);
// insecure opt-outs are named and surfaced at start (Constitution I/VII). The
// service refuses to start without a KEK, a store, a PowerDNS API URL and a
// PowerDNS API-key reference.
//
// Secrets never live in this file: the PowerDNS and recursor API keys are
// secret references (warden:<id>, or file:<path> in development) resolved at
// use time by the secrets package (research D14). The module's request bounds
// live under "limits_dns", never the framework "limits".
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"gopkg.in/yaml.v3"
)

// Config is the DNS service configuration. The embedded framework config
// (inline) already carries service_name, trust_domain, env, identity, authz,
// limits, admin, discovery and server (grpc_addr/http_addr).
type Config struct {
	fconfig.Config `yaml:",inline"`

	DB           DB           `yaml:"db"`
	Valkey       Valkey       `yaml:"valkey"`
	KEK          KEK          `yaml:"kek"`
	PDNS         PDNS         `yaml:"pdns"`
	Recursor     Recursor     `yaml:"recursor"`
	Docker       Docker       `yaml:"docker"`
	ManagedFiles ManagedFiles `yaml:"managed_files"`
	Metrics      Metrics      `yaml:"metrics"`
	IPAMSync     IPAMSync     `yaml:"ipam_sync"`
	ACME         ACME         `yaml:"acme"`
	Records      Records      `yaml:"records"`
	Secrets      Secrets      `yaml:"secrets"`
	Events       Events       `yaml:"events"`
	Gateway      Gateway      `yaml:"gateway"`
	MeshEnroll   MeshEnroll   `yaml:"mesh_enroll"`
	Limits       Limits       `yaml:"limits_dns"`
}

// DB configures the PostgreSQL/TimescaleDB store.
type DB struct {
	DSN        string `yaml:"dsn"`
	MigrateDSN string `yaml:"migrate_dsn"`
	MaxConns   int32  `yaml:"max_conns"`
}

// Valkey configures the platform event bus.
type Valkey struct {
	Addresses      []string `yaml:"addresses"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	AllowPlaintext bool     `yaml:"allow_plaintext"`
	CAFile         string   `yaml:"ca_file"`
}

// KEK names where the 32-byte key-encryption key comes from.
type KEK struct {
	Source string `yaml:"source"` // file | env
	Path   string `yaml:"path"`
	Env    string `yaml:"env"`
}

// PDNS configures the PowerDNS Authoritative HTTP API (research D3). The API
// key is a secret reference; the API is reached on the internal network only.
type PDNS struct {
	APIURL           string `yaml:"api_url"`
	ServerID         string `yaml:"server_id"`
	APIKeyRef        string `yaml:"api_key_ref"`
	TimeoutSeconds   int    `yaml:"timeout_seconds"`
	MaxResponseBytes int64  `yaml:"max_response_bytes"`
	// AllowPlaintext permits an http:// API URL (PowerDNS has no mTLS; the
	// accepted exception is internal-network-only exposure).
	AllowPlaintext bool `yaml:"allow_plaintext"`
	// AuthForwardHost/Port is where the recursor forwards managed zones: the
	// authoritative server's DNS listener (resolved to an IP at sync time).
	AuthForwardHost string `yaml:"auth_forward_host"`
	AuthForwardPort int    `yaml:"auth_forward_port"`
}

// Recursor configures the PowerDNS Recursor HTTP API (research D10). An empty
// api_url disables resolver forwarding (every call is a no-op).
type Recursor struct {
	APIURL                   string `yaml:"api_url"`
	ServerID                 string `yaml:"server_id"`
	APIKeyRef                string `yaml:"api_key_ref"`
	TimeoutSeconds           int    `yaml:"timeout_seconds"`
	AllowPlaintext           bool   `yaml:"allow_plaintext"`
	ReconcileIntervalSeconds int    `yaml:"reconcile_interval_seconds"`
	// StaticForwards are forward zones the reconciler never removes.
	StaticForwards []string `yaml:"static_forwards"`
}

// Docker configures the restart-only Docker Engine client (research D11). It
// is OFF unless enabled; it can only restart the two configured containers.
type Docker struct {
	Enabled           bool   `yaml:"enabled"`
	Socket            string `yaml:"socket"`
	AuthContainer     string `yaml:"auth_container"`
	RecursorContainer string `yaml:"recursor_container"`
	TimeoutSeconds    int    `yaml:"timeout_seconds"`
}

// ManagedFiles are the include-dir files the server configuration is rendered
// to (shared volumes with the PowerDNS containers). Empty = not applied.
type ManagedFiles struct {
	RecursorPath string `yaml:"recursor_path"`
	AuthPath     string `yaml:"auth_path"`
}

// Metrics configures the optional Prometheus-compatible query endpoint behind
// the curated dashboard (research D13). Empty = dashboard unavailable.
type Metrics struct {
	PrometheusURL  string `yaml:"prometheus_url"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

// IPAMSync configures the IPAM address-event consumer (research D8).
type IPAMSync struct {
	Enabled bool `yaml:"enabled"`
	// Tenants whose platform:events:<tenant> streams are consumed (default:
	// the mesh-enroll tenant).
	Tenants    []string `yaml:"tenants"`
	Service    string   `yaml:"service"`
	DefaultTTL int      `yaml:"default_ttl"`
}

// ACME configures the lcm-only DNS-01 challenge surface (research D12).
type ACME struct {
	AllowedCaller string `yaml:"allowed_caller"`
	MaxAgeSeconds int    `yaml:"max_age_seconds"`
}

// Records bounds record sets (research D5/D6).
type Records struct {
	MinTTL      int `yaml:"min_ttl"`
	MaxTTL      int `yaml:"max_ttl"`
	MaxValues   int `yaml:"max_values"`
	MaxPageSize int `yaml:"max_page_size"`
}

// Secrets configures how warden references are resolved: the warden service
// name on the mesh, the file holding the module's platform token used to call
// it, and how long a resolved value is cached before it is re-read (rotation).
type Secrets struct {
	WardenService string `yaml:"warden_service"`
	TokenFile     string `yaml:"token_file"`
	RefreshSecs   int    `yaml:"refresh_seconds"`
}

// Events toggles the realtime publisher.
type Events struct {
	Enabled bool `yaml:"enabled"`
}

// Gateway names the application gateway and the platform token issuer.
type Gateway struct {
	Service string `yaml:"service"`
	Issuer  string `yaml:"issuer"`
}

// MeshEnroll configures how the DNS SERVER obtains its own mesh SVID by
// enrolling with lcm over the network (identity.provider=provided).
type MeshEnroll struct {
	Enabled       bool   `yaml:"enabled"`
	EnrollURL     string `yaml:"enroll_url"`
	LCMGRPCTarget string `yaml:"lcm_grpc"`
	TenantID      string `yaml:"tenant_id"`
	TokenFile     string `yaml:"token_file"`
	StateFile     string `yaml:"state_file"`
	Insecure      bool   `yaml:"insecure"`
}

// Limits bound the module's browser request shapes.
type Limits struct {
	MaxRequestBytes int64 `yaml:"max_request_bytes"`
	MaxBackupBytes  int64 `yaml:"max_backup_bytes"`
	MaxExportBytes  int64 `yaml:"max_export_bytes"`
	MaxPageSize     int   `yaml:"max_page_size"`
}

// ContainerNameRE is the Docker container-name grammar the restarter accepts.
var ContainerNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

var (
	serverIDRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
	uuidRE     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hostRE     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

// Default returns secure defaults on top of the Freya defaults.
func Default() Config {
	return Config{
		Config: fconfig.Default(),
		DB:     DB{MaxConns: 16},
		KEK:    KEK{Source: "file"},
		PDNS: PDNS{ServerID: "localhost", TimeoutSeconds: 10, MaxResponseBytes: 32 << 20,
			AuthForwardHost: "pdns-auth", AuthForwardPort: 53},
		Recursor: Recursor{ServerID: "localhost", TimeoutSeconds: 10, ReconcileIntervalSeconds: 300},
		Docker:   Docker{Socket: "/var/run/docker.sock", AuthContainer: "freya-pdns-auth", RecursorContainer: "freya-pdns-recursor", TimeoutSeconds: 60},
		Metrics:  Metrics{TimeoutSeconds: 10},
		IPAMSync: IPAMSync{Service: "ipam", DefaultTTL: 3600},
		ACME:     ACME{AllowedCaller: "spiffe://example.org/svc/lcm", MaxAgeSeconds: 3600},
		Records:  Records{MinTTL: 60, MaxTTL: 604800, MaxValues: 100, MaxPageSize: 500},
		Secrets:  Secrets{WardenService: "warden", RefreshSecs: 300},
		Events:   Events{Enabled: true},
		Gateway:  Gateway{Service: "gateway"},
		Limits:   Limits{MaxRequestBytes: 1 << 20, MaxBackupBytes: 64 << 20, MaxExportBytes: 32 << 20, MaxPageSize: 100},
	}
}

// Load reads YAML over Default(); unknown fields are rejected.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

func within[T int | int64](v, lo, hi T) bool { return v >= lo && v <= hi }

// Validate checks the Freya config and every module section. It refuses a
// missing db, kek, PowerDNS API URL or API-key reference outright and enforces
// the production TLS guards.
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	for _, check := range []func() error{c.validateInfra, c.validatePDNS, c.validateRecursor, c.validateDocker,
		c.validateFiles, c.validateMetrics, c.validateSync, c.validateRest} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateInfra() error {
	prod := c.IsProduction()
	if c.DB.DSN == "" {
		return errors.New("config: db.dsn is required")
	}
	if prod && !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		return errors.New("config: db.dsn must use sslmode=verify-full (or verify-ca) in production")
	}
	if len(c.Valkey.Addresses) == 0 {
		return errors.New("config: valkey.addresses is required")
	}
	if prod && c.Valkey.AllowPlaintext {
		return errors.New("config: valkey.allow_plaintext is not permitted in production")
	}
	switch c.KEK.Source {
	case "file":
		if c.KEK.Path == "" {
			return errors.New("config: kek.path is required for kek.source file")
		}
	case "env":
		if c.KEK.Env == "" {
			return errors.New("config: kek.env is required for kek.source env")
		}
	default:
		return errors.New("config: kek.source must be file or env")
	}
	return nil
}

// apiURL validates a PowerDNS-style API base URL: http(s), a host, no
// credentials, query or fragment. Plaintext needs the named opt-out.
func apiURL(field, raw string, allowPlain bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("config: %s must be an http(s) base URL without credentials, query or fragment", field)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowPlain {
			return fmt.Errorf("config: %s uses http; set allow_plaintext (internal network only) or use https", field)
		}
	default:
		return fmt.Errorf("config: %s must use http or https", field)
	}
	return nil
}

func (c Config) validatePDNS() error {
	p := c.PDNS
	if strings.TrimSpace(p.APIURL) == "" {
		return errors.New("config: pdns.api_url is required")
	}
	if err := apiURL("pdns.api_url", p.APIURL, p.AllowPlaintext); err != nil {
		return err
	}
	if strings.TrimSpace(p.APIKeyRef) == "" {
		return errors.New("config: pdns.api_key_ref is required (a secret reference for the PowerDNS API key)")
	}
	if !serverIDRE.MatchString(p.ServerID) {
		return errors.New("config: pdns.server_id must match [a-zA-Z0-9._-]{1,64}")
	}
	if !within(p.TimeoutSeconds, 1, 120) {
		return errors.New("config: pdns.timeout_seconds must be within [1, 120]")
	}
	if !within(p.MaxResponseBytes, 64<<10, 256<<20) {
		return errors.New("config: pdns.max_response_bytes must be within [64 KiB, 256 MiB]")
	}
	if !hostRE.MatchString(p.AuthForwardHost) {
		return errors.New("config: pdns.auth_forward_host must be a host name or IP literal")
	}
	if !within(p.AuthForwardPort, 1, 65535) {
		return errors.New("config: pdns.auth_forward_port must be within [1, 65535]")
	}
	return nil
}

func (c Config) validateRecursor() error {
	r := c.Recursor
	if strings.TrimSpace(r.APIURL) == "" {
		return nil // resolver forwarding disabled
	}
	if err := apiURL("recursor.api_url", r.APIURL, r.AllowPlaintext); err != nil {
		return err
	}
	if strings.TrimSpace(r.APIKeyRef) == "" {
		return errors.New("config: recursor.api_key_ref is required when recursor.api_url is set")
	}
	if !serverIDRE.MatchString(r.ServerID) {
		return errors.New("config: recursor.server_id must match [a-zA-Z0-9._-]{1,64}")
	}
	if !within(r.TimeoutSeconds, 1, 120) {
		return errors.New("config: recursor.timeout_seconds must be within [1, 120]")
	}
	if !within(r.ReconcileIntervalSeconds, 10, 86400) {
		return errors.New("config: recursor.reconcile_interval_seconds must be within [10, 86400]")
	}
	if len(r.StaticForwards) > 64 {
		return errors.New("config: recursor.static_forwards allows at most 64 entries")
	}
	for _, z := range r.StaticForwards {
		if z == "." {
			continue
		}
		if !hostRE.MatchString(strings.TrimSuffix(z, ".")) {
			return fmt.Errorf("config: recursor.static_forwards: %q is not a zone name", z)
		}
	}
	return nil
}

func (c Config) validateDocker() error {
	d := c.Docker
	if !d.Enabled {
		return nil
	}
	if d.Socket == "" || !filepath.IsAbs(d.Socket) || filepath.Clean(d.Socket) != d.Socket {
		return errors.New("config: docker.socket must be an absolute, clean unix socket path")
	}
	for field, name := range map[string]string{"docker.auth_container": d.AuthContainer, "docker.recursor_container": d.RecursorContainer} {
		if !ContainerNameRE.MatchString(name) {
			return fmt.Errorf("config: %s must match %s", field, ContainerNameRE)
		}
	}
	if d.AuthContainer == d.RecursorContainer {
		return errors.New("config: docker.auth_container and docker.recursor_container must differ")
	}
	if !within(d.TimeoutSeconds, 1, 600) {
		return errors.New("config: docker.timeout_seconds must be within [1, 600]")
	}
	return nil
}

func (c Config) validateFiles() error {
	m := c.ManagedFiles
	for field, p := range map[string]string{"managed_files.recursor_path": m.RecursorPath, "managed_files.auth_path": m.AuthPath} {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("config: %s must be an absolute, clean path", field)
		}
	}
	if m.RecursorPath != "" && m.RecursorPath == m.AuthPath {
		return errors.New("config: managed_files paths must differ")
	}
	return nil
}

func (c Config) validateMetrics() error {
	m := c.Metrics
	if m.PrometheusURL != "" {
		u, err := url.Parse(m.PrometheusURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("config: metrics.prometheus_url must be an http(s) base URL without credentials, query or fragment")
		}
	}
	if !within(m.TimeoutSeconds, 1, 60) {
		return errors.New("config: metrics.timeout_seconds must be within [1, 60]")
	}
	return nil
}

func (c Config) validateSync() error {
	s := c.IPAMSync
	for _, t := range s.Tenants {
		if !uuidRE.MatchString(t) {
			return fmt.Errorf("config: ipam_sync.tenants: %q is not a tenant id", t)
		}
	}
	if !s.Enabled {
		return nil
	}
	if s.Service == "" {
		return errors.New("config: ipam_sync.service is required when ipam_sync.enabled")
	}
	if len(s.SyncTenants(c.MeshEnroll.TenantID)) == 0 {
		return errors.New("config: ipam_sync.tenants (or mesh_enroll.tenant_id) is required when ipam_sync.enabled")
	}
	if !within(s.DefaultTTL, c.Records.MinTTL, c.Records.MaxTTL) {
		return errors.New("config: ipam_sync.default_ttl must be within [records.min_ttl, records.max_ttl]")
	}
	return nil
}

// SyncTenants returns the tenants whose event streams the IPAM sync consumes:
// the configured list, else the mesh-enroll tenant.
func (s IPAMSync) SyncTenants(enrollTenant string) []string {
	if len(s.Tenants) > 0 {
		return append([]string(nil), s.Tenants...)
	}
	if uuidRE.MatchString(enrollTenant) {
		return []string{enrollTenant}
	}
	return nil
}

func (c Config) validateRest() error {
	prod := c.IsProduction()
	if !strings.HasPrefix(c.ACME.AllowedCaller, "spiffe://") || strings.ContainsAny(c.ACME.AllowedCaller, " *") {
		return errors.New("config: acme.allowed_caller must be an exact spiffe:// ID")
	}
	if !within(c.ACME.MaxAgeSeconds, 60, 86400) {
		return errors.New("config: acme.max_age_seconds must be within [60, 86400]")
	}
	r := c.Records
	if !within(r.MinTTL, 1, r.MaxTTL) || !within(r.MaxTTL, r.MinTTL, 2147483647) {
		return errors.New("config: records.min_ttl/max_ttl must satisfy 1 <= min_ttl <= max_ttl")
	}
	if !within(r.MaxValues, 1, 1000) {
		return errors.New("config: records.max_values must be within [1, 1000]")
	}
	if !within(r.MaxPageSize, 1, 500) {
		return errors.New("config: records.max_page_size must be within [1, 500]")
	}
	if c.Secrets.WardenService == "" {
		return errors.New("config: secrets.warden_service is required")
	}
	if !within(c.Secrets.RefreshSecs, 10, 86400) {
		return errors.New("config: secrets.refresh_seconds must be within [10, 86400]")
	}
	if c.Gateway.Service == "" {
		return errors.New("config: gateway.service is required")
	}
	if iu, err := url.Parse(c.Gateway.Issuer); err != nil || iu.Scheme != "https" || iu.Host == "" {
		return errors.New("config: gateway.issuer must be an https origin")
	}
	if prod && c.MeshEnroll.Enabled && c.MeshEnroll.Insecure {
		return errors.New("config: mesh_enroll.insecure is not permitted in production")
	}
	if !within(c.Limits.MaxRequestBytes, 1<<10, 64<<20) {
		return errors.New("config: limits_dns.max_request_bytes must be within [1 KiB, 64 MiB]")
	}
	if !within(c.Limits.MaxBackupBytes, 1<<10, 256<<20) {
		return errors.New("config: limits_dns.max_backup_bytes must be within [1 KiB, 256 MiB]")
	}
	if !within(c.Limits.MaxExportBytes, 1<<10, 256<<20) {
		return errors.New("config: limits_dns.max_export_bytes must be within [1 KiB, 256 MiB]")
	}
	if !within(c.Limits.MaxPageSize, 1, 100) {
		return errors.New("config: limits_dns.max_page_size must be within [1, 100]")
	}
	return nil
}

func isPlainHTTP(raw string) bool { return strings.HasPrefix(strings.ToLower(raw), "http://") }

func isFileRef(ref string) bool { return strings.HasPrefix(strings.TrimSpace(ref), "file:") }

// Warnings lists accepted insecure opt-outs (surfaced at start).
func (c Config) Warnings() []string {
	w := c.Config.Warnings()
	if c.Valkey.AllowPlaintext {
		w = append(w, "valkey.allow_plaintext: event-bus traffic without TLS (development only)")
	}
	if c.MeshEnroll.Enabled && c.MeshEnroll.Insecure {
		w = append(w, "mesh_enroll.insecure: SVID enrollment without TLS (development only)")
	}
	if isPlainHTTP(c.PDNS.APIURL) {
		w = append(w, "pdns.api_url is plaintext http: keep the PowerDNS API on the internal network only")
	}
	if c.RecursorEnabled() && isPlainHTTP(c.Recursor.APIURL) {
		w = append(w, "recursor.api_url is plaintext http: keep the recursor API on the internal network only")
	}
	if isFileRef(c.PDNS.APIKeyRef) || isFileRef(c.Recursor.APIKeyRef) {
		w = append(w, "secret reference uses file: (development only; use a warden reference)")
	}
	if c.Docker.Enabled {
		w = append(w, "docker.enabled: the Docker Engine socket is mounted (root-equivalent on the host); restarts are limited to "+
			c.Docker.AuthContainer+" and "+c.Docker.RecursorContainer+" — use an API-filtering socket proxy in production")
	}
	if !c.RecursorEnabled() {
		w = append(w, "recursor.api_url empty: resolver forwarding for managed zones is disabled")
	}
	if c.Metrics.PrometheusURL == "" {
		w = append(w, "metrics.prometheus_url empty: the dashboard reports metrics unavailable")
	}
	return w
}

// GRPCAddr is the mesh gRPC listener (framework server section).
func (c Config) GRPCAddr() string { return c.Config.Server.GRPCAddr }

// HTTPAddr is the mesh HTTP listener (framework server section).
func (c Config) HTTPAddr() string { return c.Config.Server.HTTPAddr }

// AdminAddr is the framework admin/operations listener.
func (c Config) AdminAddr() string { return c.Config.Admin.Addr }

// RecursorEnabled reports whether resolver forwarding is configured.
func (c Config) RecursorEnabled() bool { return strings.TrimSpace(c.Recursor.APIURL) != "" }

// PDNSTimeout bounds one PowerDNS API call.
func (c Config) PDNSTimeout() time.Duration {
	return time.Duration(c.PDNS.TimeoutSeconds) * time.Second
}

// RecursorTimeout bounds one recursor API call.
func (c Config) RecursorTimeout() time.Duration {
	return time.Duration(c.Recursor.TimeoutSeconds) * time.Second
}

// ReconcileInterval is the recursor reconciler period.
func (c Config) ReconcileInterval() time.Duration {
	return time.Duration(c.Recursor.ReconcileIntervalSeconds) * time.Second
}

// SecretRefresh is how long a resolved secret is cached.
func (c Config) SecretRefresh() time.Duration {
	return time.Duration(c.Secrets.RefreshSecs) * time.Second
}

// ChallengeMaxAge is how long a presented ACME TXT value may live before the
// sweeper removes it.
func (c Config) ChallengeMaxAge() time.Duration {
	return time.Duration(c.ACME.MaxAgeSeconds) * time.Second
}

// MetricsTimeout bounds one dashboard refresh.
func (c Config) MetricsTimeout() time.Duration {
	return time.Duration(c.Metrics.TimeoutSeconds) * time.Second
}

// AuthForwardTarget is the host:port the recursor forwards managed zones to.
func (c Config) AuthForwardTarget() string {
	return net.JoinHostPort(c.PDNS.AuthForwardHost, fmt.Sprint(c.PDNS.AuthForwardPort))
}

// AuthForwardIsIP reports whether the forward host is already an IP literal.
func (c Config) AuthForwardIsIP() bool {
	_, err := netip.ParseAddr(c.PDNS.AuthForwardHost)
	return err == nil
}
