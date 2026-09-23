// Package app wires the DNS service: configuration -> Freya runtime (mesh
// identity, admin listener) -> store/KEK/audit/secrets -> the PowerDNS
// Authoritative and Recursor clients (API keys from secret references, read per
// call) -> events/stream/metrics -> the mesh HTTP surface (reached only through
// the gateway) and the dns.v1 gRPC surface (module-to-module), plus gateway
// registration and permission seeding. It refuses to start without a KEK, a
// store and a usable PowerDNS endpoint + key reference (config.Validate and the
// client constructors).
//
// Domain services and background workers are added by the user-story phases
// (US1 zones/records + recursor reconciler, US2 IPAM consumer, US3 templates/
// supermasters, US4 ACME challenges + sweeper, US5 configuration re-apply, US6
// dashboard) through Deps and AddWorker; routes of services not yet wired
// answer 501.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-freya/freya"
	"github.com/go-freya/freya/services/lcm/pkg/lcmidentity"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
	"github.com/go-freya/freya/services/ipam/pkg/ipamclient"

	"github.com/go-freya/freya/services/dns/internal/acmechallenge"
	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/backup"
	"github.com/go-freya/freya/services/dns/internal/config"
	"github.com/go-freya/freya/services/dns/internal/dashboard"
	"github.com/go-freya/freya/services/dns/internal/dnsconf"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/grpcapi"
	"github.com/go-freya/freya/services/dns/internal/httpapi"
	"github.com/go-freya/freya/services/dns/internal/ipamsync"
	"github.com/go-freya/freya/services/dns/internal/metrics"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/recursor"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/repo/repodb"
	"github.com/go-freya/freya/services/dns/internal/sealed"
	"github.com/go-freya/freya/services/dns/internal/secrets"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/stream"
	"github.com/go-freya/freya/services/dns/internal/stream/valkeykv"
	"github.com/go-freya/freya/services/dns/internal/supermasters"
	"github.com/go-freya/freya/services/dns/internal/templates"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
	"github.com/go-freya/freya/services/dns/pkg/dnsmanifest"
)

// Options override infrastructure (tests) and attach optional parts.
type Options struct {
	Logger   slog.Handler
	KEK      []byte
	Verifier httpapi.Verifier
	Checker  authz.Checker   // API-permission checker override (default: auth Authorization/Check)
	Repo     repo.Store      // store override (tests: memstore); skips the DB
	Secrets  secrets.Source  // PowerDNS/recursor API-key source override (tests: &secrets.Fake{})
	Stream   stream.Client   // event-bus client override (tests: stream.NewMemory())
	PDNS     pdns.Client     // PowerDNS Authoritative client override (tests: pdns.NewFake())
	Recursor recursor.Client // Recursor client override (tests: recursor.NewFake())
	IPAM     ipamsync.IPAM   // IPAM reader override (tests); default: ipam.v1 over SPIFFE mTLS, dialled lazily
	// Restarter overrides the Docker restarter (tests: dnsconf.NewFake).
	Restarter dnsconf.Restarter
	// ConfigFiles overrides the include-file writer (default: the disk).
	ConfigFiles dnsconf.FileWriter
	// Metrics overrides the dashboard's metrics client (default: Prometheus
	// at metrics.prometheus_url, none when empty).
	Metrics dashboard.MetricsClient
	Freya   []freya.Option
	Migrate bool
	Remote  fs.FS // built federated UI remote (nil serves no remote)
}

// Worker is a background loop started by Run and stopped by ctx cancellation.
type Worker struct {
	Name string
	Run  func(ctx context.Context)
}

// App is the wired service.
type App struct {
	Cfg      config.Config
	Log      *slog.Logger
	Freya    *freya.App
	Store    *store.Store
	Repo     repo.Store
	Env      *sealed.Envelope
	Audit    *audit.Writer
	Verifier httpapi.Verifier
	Checker  authz.Checker
	Secrets  secrets.Source
	PDNS     pdns.Client
	Recursor recursor.Client
	Events   events.Publisher
	Metrics  *metrics.Metrics
	Hub      *stream.Hub
	HTTP     *httpapi.Server
	Zones    *zones.Service
	Records  *records.Service
	Recon    *recursor.Reconciler
	Tpl      *templates.Service
	Masters  *supermasters.Service
	Bus      stream.Client
	Sync     *ipamsync.Syncer
	// US4-US6.
	Challenges *acmechallenge.Service
	Config     *dnsconf.Service
	Dashboard  *dashboard.Service
	Backup     *backup.Service

	parseBackup func([]byte) (backup.Backup, error)
	closers     []func()
	workers     []Worker
}

// Build wires the service.
func Build(ctx context.Context, cfg config.Config, o Options) (a *App, err error) {
	a = &App{Cfg: cfg}
	handler := o.Logger
	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	a.Log = slog.New(handler)
	built := a
	defer func() { // release what was opened when wiring fails half-way
		if err != nil {
			built.Close()
		}
	}()

	if err = a.buildRuntime(ctx, cfg, handler, o.Freya); err != nil {
		return nil, err
	}
	if err = a.buildStorage(ctx, cfg, o); err != nil {
		return nil, err
	}
	if err = a.buildPeers(ctx, cfg, o); err != nil {
		return nil, err
	}
	if err = a.buildDNS(cfg, o); err != nil {
		return nil, err
	}
	if err = a.buildEvents(cfg, o.Stream); err != nil {
		return nil, err
	}
	if a.Metrics, err = metrics.New(a.Freya.Metrics().Meter(metrics.Scope)); err != nil {
		return nil, fmt.Errorf("metrics: %w", err)
	}

	// Mesh HTTP surface (reached only through the gateway).
	hopts := []httpapi.Option{httpapi.WithVerifier(a.Verifier), httpapi.WithChecker(a.Checker), httpapi.WithLogger(a.Log)}
	if o.Remote != nil {
		hopts = append(hopts, httpapi.WithRemote(o.Remote))
	}
	if a.HTTP, err = httpapi.NewHandler(a.Freya, hopts...); err != nil {
		return nil, err
	}
	a.buildServices(cfg, o)
	if err = a.buildOperations(cfg, o); err != nil {
		return nil, err
	}
	a.HTTP.Register(httpapi.Deps{Health: a.health, Zones: a.Zones, Records: a.Records, Templates: a.Tpl, Supermasters: a.Masters,
		Config: a.Config, Dashboard: a.Dashboard, Backup: a.Backup, ParseBackup: a.parseBackup, Hub: a.Hub})
	a.Freya.HTTP().HandlePrefix("/", a.HTTP.Handler())

	// Service-to-service gRPC surface (dns.v1), SPIFFE mTLS, not gateway-proxied.
	grpcapi.Register(a.Freya.GRPC(), grpcapi.Deps{AllowedChallengeCaller: cfg.ACME.AllowedCaller, Zones: a.Zones, Challenges: a.Challenges})
	return a, nil
}

// buildServices wires the domain services (US1 zones and record sets, US2
// IPAM sync, US3 templates and supermasters) and their workers: the recursor reconciler (start-up + interval
// forward sync) and, when enabled, the IPAM event consumer.
func (a *App) buildServices(cfg config.Config, o Options) {
	limits := validate.Limits{MinTTL: cfg.Records.MinTTL, MaxTTL: cfg.Records.MaxTTL, MaxValues: cfg.Records.MaxValues}
	a.Tpl = templates.New(templates.Deps{Store: a.Repo, Audit: a.Audit, Limits: limits, Log: a.Log})
	a.Zones = zones.New(zones.Deps{Store: a.Repo, PDNS: a.PDNS, Recursor: a.Recursor, Events: a.Events, Audit: a.Audit,
		Metrics: a.Metrics, Templates: a.Tpl, MaxExportBytes: cfg.Limits.MaxExportBytes, Log: a.Log})
	a.Masters = supermasters.New(supermasters.Deps{Store: a.Repo, PDNS: a.PDNS, Audit: a.Audit, Metrics: a.Metrics, Log: a.Log})
	a.Records = records.New(records.Deps{Zones: a.Zones, PDNS: a.PDNS, Events: a.Events, Audit: a.Audit, Log: a.Log, Limits: limits})
	a.Backup = backup.New(backup.Deps{Store: a.Repo, PDNS: a.PDNS, Audit: a.Audit, Limits: limits, Log: a.Log})
	a.parseBackup = func(raw []byte) (backup.Backup, error) { return backup.Parse(raw, limits) }
	a.Recon = &recursor.Reconciler{Client: a.Recursor, Names: a.Repo.AllZoneNames, Static: cfg.Recursor.StaticForwards,
		Interval: cfg.ReconcileInterval(), Log: a.Log, OnResult: a.Metrics.RecursorSync,
		PDNSNames: a.PDNS.ListZoneNames, OnUnowned: a.Metrics.SetUnownedZones}
	// Runs even without a resolver: it also reports PowerDNS zones no tenant owns.
	a.AddWorker("recursor-reconciler", a.Recon.Run)
	if cfg.IPAMSync.Enabled {
		a.buildSync(cfg, o.IPAM)
	}
}

// buildOperations wires US4-US6: the lcm-only ACME challenge service and its
// sweeper, the server configuration (restart-only Docker client, disabled
// unless configured; start-up re-apply worker) and the curated dashboard
// (Prometheus client when metrics.prometheus_url is set).
func (a *App) buildOperations(cfg config.Config, o Options) error {
	a.Challenges = acmechallenge.New(acmechallenge.Deps{Zones: a.Zones, Records: a.Records, Store: a.Repo, Audit: a.Audit,
		Metrics: a.Metrics, AllowedCaller: cfg.ACME.AllowedCaller, Log: a.Log})
	sweeper := &acmechallenge.Sweeper{Service: a.Challenges, MaxAge: cfg.ChallengeMaxAge()}
	a.AddWorker("acme-sweeper", sweeper.Run)

	restarter := o.Restarter
	if restarter == nil {
		d, err := dnsconf.NewDocker(dnsconf.DockerConfig{Enabled: cfg.Docker.Enabled, Socket: cfg.Docker.Socket,
			AuthContainer: cfg.Docker.AuthContainer, RecursorContainer: cfg.Docker.RecursorContainer,
			Timeout: time.Duration(cfg.Docker.TimeoutSeconds) * time.Second})
		if err != nil {
			return fmt.Errorf("docker restarter: %w", err)
		}
		restarter = d
	}
	a.Config = dnsconf.New(dnsconf.ServiceDeps{Store: a.Repo, Files: o.ConfigFiles, Restarter: restarter, Checker: a.Checker,
		Audit: a.Audit, Metrics: a.Metrics, RecursorPath: cfg.ManagedFiles.RecursorPath, AuthPath: cfg.ManagedFiles.AuthPath,
		Reconcile: a.Recon.ReconcileNow, Log: a.Log})
	a.AddWorker("config-reapply", a.Config.Run)

	client := o.Metrics
	if client == nil && cfg.Metrics.PrometheusURL != "" {
		p, err := dashboard.NewProm(dashboard.PromConfig{BaseURL: cfg.Metrics.PrometheusURL, Timeout: cfg.MetricsTimeout()})
		if err != nil {
			return fmt.Errorf("metrics client: %w", err)
		}
		client = p
	}
	a.Dashboard = dashboard.New(dashboard.Deps{Client: client, Checker: a.Checker, Timeout: cfg.MetricsTimeout(), Log: a.Log})
	return nil
}

// buildSync wires the IPAM consumer (research D8): address events of the
// configured tenants are re-read from IPAM (ipam.v1 over SPIFFE mTLS) and
// applied through the zone/record services.
func (a *App) buildSync(cfg config.Config, reader ipamsync.IPAM) {
	if reader == nil {
		reader = ipamsync.Client{R: &lazyIPAM{app: a, service: cfg.IPAMSync.Service}}
	}
	a.Sync = ipamsync.New(ipamsync.Deps{Store: a.Repo, Zones: a.Zones, Records: a.Records, IPAM: reader, Audit: a.Audit,
		Metrics: a.Metrics, TTL: cfg.IPAMSync.DefaultTTL, Log: a.Log})
	cons := &ipamsync.Consumer{Reader: a.Bus, Tenants: cfg.IPAMSync.SyncTenants(cfg.MeshEnroll.TenantID), Handle: a.Sync.Handle, Log: a.Log,
		OnDrop: func(string) { a.Metrics.IPAMSync("decode", metrics.ResultRefused) }}
	a.AddWorker("ipam-sync", cons.Run)
}

// lazyIPAM dials ipam on first use so the module starts while it is down.
type lazyIPAM struct {
	app     *App
	service string
	mu      sync.Mutex
	c       *ipamclient.Client
}

func (l *lazyIPAM) client(ctx context.Context) (*ipamclient.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c == nil {
		conn, err := l.app.Freya.Client(ctx, l.service)
		if err != nil {
			return nil, fmt.Errorf("ipam client: %w", err)
		}
		l.c = ipamclient.New(conn)
	}
	return l.c, nil
}

func (l *lazyIPAM) GetAddress(ctx context.Context, tenantID, id string) (ipamclient.IPAddress, error) {
	c, err := l.client(ctx)
	if err != nil {
		return ipamclient.IPAddress{}, err
	}
	return c.GetAddress(ctx, tenantID, id)
}

func (l *lazyIPAM) GetSubnet(ctx context.Context, tenantID, id string) (ipamclient.Subnet, error) {
	c, err := l.client(ctx)
	if err != nil {
		return ipamclient.Subnet{}, err
	}
	return c.GetSubnet(ctx, tenantID, id)
}

func (a *App) buildRuntime(ctx context.Context, cfg config.Config, handler slog.Handler, extra []freya.Option) error {
	fopts := append([]freya.Option{freya.WithLogger(handler)}, extra...)
	if cfg.MeshEnroll.Enabled {
		raw, err := os.ReadFile(cfg.MeshEnroll.TokenFile)
		if err != nil {
			return fmt.Errorf("dns: mesh enroll token: %w", err)
		}
		prov, err := lcmidentity.NewNet(ctx, lcmidentity.NetConfig{
			EnrollURL: cfg.MeshEnroll.EnrollURL, LCMGRPCTarget: cfg.MeshEnroll.LCMGRPCTarget,
			TenantID: cfg.MeshEnroll.TenantID, TrustDomain: cfg.Config.TrustDomain, ServiceName: cfg.Config.ServiceName,
			EnrollmentToken: strings.TrimSpace(string(raw)), Insecure: cfg.MeshEnroll.Insecure, StateFile: cfg.MeshEnroll.StateFile,
		})
		if err != nil {
			return fmt.Errorf("dns: mesh enroll: %w", err)
		}
		a.closers = append(a.closers, func() { _ = prov.Close() })
		fopts = append(fopts, freya.WithIdentityProvider(prov))
	}
	f, err := freya.New(cfg.Config, fopts...)
	if err != nil {
		return err
	}
	a.Freya = f
	a.closers = append(a.closers, f.Close)
	return nil
}

func (a *App) buildStorage(ctx context.Context, cfg config.Config, o Options) (err error) {
	kek := o.KEK
	if len(kek) == 0 {
		if kek, err = sealed.LoadKEK(cfg.KEK.Source, cfg.KEK.Path, cfg.KEK.Env); err != nil {
			return fmt.Errorf("kek: %w", err)
		}
	}
	if a.Env, err = sealed.NewEnvelope(kek); err != nil {
		return err
	}
	a.Repo = o.Repo
	if a.Repo == nil {
		if o.Migrate {
			mdsn := cfg.DB.MigrateDSN
			if mdsn == "" {
				mdsn = cfg.DB.DSN
			}
			if err = store.Migrate(ctx, mdsn); err != nil {
				return err
			}
		}
		if a.Store, err = store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns); err != nil {
			return err
		}
		a.closers = append(a.closers, a.Store.Close)
		a.Repo = repodb.New(a.Store)
	}
	a.Audit = audit.NewWriter(a.Repo, func(err error) { a.Log.Error("audit write failed", "err", err) })
	a.closers = append(a.closers, a.Audit.Close)
	return nil
}

// buildPeers wires what the module asks other services: the platform-token
// verifier and the permission checker (auth), and the API-key source (warden
// references; file: in development). Mesh connections are dialled lazily
// where possible so the module starts while a peer is down.
func (a *App) buildPeers(ctx context.Context, cfg config.Config, o Options) error {
	a.Verifier, a.Checker = o.Verifier, o.Checker
	if a.Verifier == nil || a.Checker == nil {
		conn, err := a.Freya.Client(ctx, "auth")
		if err != nil {
			return fmt.Errorf("auth client: %w", err)
		}
		if a.Verifier == nil {
			a.Verifier = authclient.New(authclient.Config{Issuer: cfg.Gateway.Issuer},
				authclient.GRPCKeys{Client: authv1.NewKeysClient(conn)},
				authclient.GRPCRevocations{Client: authv1.NewSessionsClient(conn)})
		}
		if a.Checker == nil {
			a.Checker = AuthPerms{Client: authv1.NewAuthorizationClient(conn)}
		}
	}
	a.Secrets = o.Secrets
	if a.Secrets == nil {
		var tok secrets.TokenFunc
		if cfg.Secrets.TokenFile != "" {
			tok = secrets.FileToken(cfg.Secrets.TokenFile)
		}
		resolver := secrets.Resolver{Warden: &lazyWarden{app: a, token: tok}, AllowFile: !cfg.IsProduction()}
		a.Secrets = secrets.NewCached(resolver, cfg.PDNS.APIKeyRef, cfg.Recursor.APIKeyRef, cfg.SecretRefresh())
	}
	return nil
}

// buildDNS wires the PowerDNS Authoritative and Recursor clients. Both read
// their API key from the secret source on every call (rotation without
// restart); the recursor client is a disabled no-op without an API URL.
func (a *App) buildDNS(cfg config.Config, o Options) error {
	a.PDNS = o.PDNS
	if a.PDNS == nil {
		c, err := pdns.New(pdns.Config{BaseURL: cfg.PDNS.APIURL, ServerID: cfg.PDNS.ServerID, Key: a.Secrets.PDNSAPIKey,
			Timeout: cfg.PDNSTimeout(), MaxResponseBytes: cfg.PDNS.MaxResponseBytes})
		if err != nil {
			return err
		}
		a.PDNS = c
	}
	a.Recursor = o.Recursor
	if a.Recursor == nil {
		c, err := recursor.New(recursor.Config{BaseURL: cfg.Recursor.APIURL, ServerID: cfg.Recursor.ServerID, Key: a.Secrets.RecursorAPIKey,
			ForwardHost: cfg.PDNS.AuthForwardHost, ForwardPort: cfg.PDNS.AuthForwardPort, Timeout: cfg.RecursorTimeout()})
		if err != nil {
			return err
		}
		a.Recursor = c
	}
	return nil
}

func (a *App) buildEvents(cfg config.Config, client stream.Client) error {
	if client == nil {
		sc := valkeykv.Config{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			pem, err := os.ReadFile(cfg.Valkey.CAFile)
			if err != nil {
				return fmt.Errorf("valkey ca: %w", err)
			}
			sc.CAPEM = pem
		}
		c, err := valkeykv.New(sc)
		if err != nil {
			return fmt.Errorf("event bus: %w", err)
		}
		client = c
	}
	a.Bus = client
	a.Hub = stream.NewHub(client, stream.Config{}, a.Log)
	a.closers = append(a.closers, a.Hub.Close)
	a.Events = events.HubPublisher{}
	if cfg.Events.Enabled {
		a.Events = events.HubPublisher{Hub: a.Hub}
	}
	return nil
}

// AddWorker registers a background loop started by Run (the user stories add
// the recursor reconciler, the IPAM consumer, the challenge sweeper and the
// configuration re-apply). It must be called before Run.
func (a *App) AddWorker(name string, run func(ctx context.Context)) {
	a.workers = append(a.workers, Worker{Name: name, Run: run})
}

// Workers lists the registered background loops.
func (a *App) Workers() []Worker { return append([]Worker(nil), a.workers...) }

// lazyWarden dials warden on first use so the module starts while it is down.
type lazyWarden struct {
	app   *App
	token secrets.TokenFunc
	mu    sync.Mutex
	w     *secrets.Warden
}

func (l *lazyWarden) Fetch(ctx context.Context, id string) (string, error) {
	l.mu.Lock()
	if l.w == nil {
		conn, err := l.app.Freya.Client(ctx, l.app.Cfg.Secrets.WardenService)
		if err != nil {
			l.mu.Unlock()
			return "", fmt.Errorf("%w: warden client", secrets.ErrUnavailable)
		}
		l.w = secrets.NewWarden(conn, l.token)
	}
	w := l.w
	l.mu.Unlock()
	return w.Fetch(ctx, id)
}

// health reports component reachability for /health (never an error text).
func (a *App) health() map[string]string {
	out := map[string]string{"store": "ok", "pdns": "ok", "pdns_api_key": "ok"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if a.Store != nil {
		if err := a.Store.Ping(ctx); err != nil {
			out["store"] = "unreachable"
		}
	}
	if _, err := a.Secrets.PDNSAPIKey(ctx); err != nil {
		out["pdns_api_key"] = "unavailable"
	}
	if err := a.PDNS.Ping(ctx); err != nil {
		out["pdns"] = "unreachable"
	}
	if a.Recursor.Enabled() {
		out["recursor"] = "ok"
		if err := a.Recursor.Ready(ctx); err != nil {
			out["recursor"] = "unreachable"
		}
	}
	return out
}

// Run starts the verifier, gateway registration, permission seeding, the
// background workers and the Freya runtime.
func (a *App) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if v, ok := a.Verifier.(*authclient.Verifier); ok {
		go func() {
			for wctx.Err() == nil {
				if err := v.Start(wctx, func(err error) { a.Log.Warn("verifier", "err", err) }); err == nil {
					return
				}
				select {
				case <-wctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	go a.register(wctx)
	for _, w := range a.workers {
		a.Log.Info("worker starting", "worker", w.Name)
		go w.Run(wctx)
	}
	go func() {
		for wctx.Err() == nil && !a.Freya.Ready() {
			time.Sleep(100 * time.Millisecond)
		}
		a.seedLoop(wctx)
	}()
	return a.Freya.Run(ctx)
}

// Close releases resources (idempotent).
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}

// register keeps the gateway lease for the manifest.
func (a *App) register(ctx context.Context) {
	for ctx.Err() == nil && !a.Freya.Ready() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	man, err := dnsmanifest.Manifest()
	if err != nil {
		a.Log.Error("gateway manifest", "err", err)
		return
	}
	httpEP, err := a.Freya.HTTP().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: http endpoint", "err", err)
		return
	}
	grpcEP, err := a.Freya.GRPC().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: grpc endpoint", "err", err)
		return
	}
	var client *gatewayclient.Client
	for ctx.Err() == nil && client == nil {
		conn, cerr := a.Freya.Client(ctx, a.Cfg.Gateway.Service)
		if cerr != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		client, err = gatewayclient.New(conn, gatewayclient.Options{Manifest: man, HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host, Logger: a.Log,
			OnState: func(s gatewayclient.State) {
				a.Log.Info("gateway lease", "registered", s.Registered, "lease", s.LeaseID, "err", s.Err)
			}})
		if err != nil {
			a.Log.Error("gateway client", "err", err)
			return
		}
	}
	if client != nil {
		if err := client.Run(ctx); err != nil {
			a.Log.Error("gateway registration", "err", err)
		}
	}
}
