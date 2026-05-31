package service

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/encoding/protojson"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/data"
	"github.com/go-tangra/go-tangra-dns/internal/dnsconf"
	"github.com/go-tangra/go-tangra-dns/internal/recursor"
)

// ConfigService manages platform PowerDNS configuration: it persists the
// settings, renders them into each service's include-dir config file, and
// restarts the affected container to apply them.
type ConfigService struct {
	dnsV1.UnimplementedDnsConfigServiceServer

	log        *log.Helper
	repo       *data.DnsConfigRepo
	docker     *dnsconf.Docker
	reconciler *recursor.Reconciler

	recursorConfPath  string
	authConfPath      string
	recursorContainer string
	authContainer     string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewConfigService(ctx *bootstrap.Context, repo *data.DnsConfigRepo, reconciler *recursor.Reconciler) *ConfigService {
	return &ConfigService{
		log:               ctx.NewLoggerHelper("dns/service/config"),
		repo:              repo,
		reconciler:        reconciler,
		docker:            dnsconf.NewDocker(envOr("DOCKER_SOCKET", "/var/run/docker.sock")),
		recursorConfPath:  envOr("RECURSOR_CONF_PATH", "/managed/recursor/zz-tangra.yml"),
		authConfPath:      envOr("AUTH_CONF_PATH", "/managed/auth/zz-tangra.conf"),
		recursorContainer: envOr("RECURSOR_CONTAINER", "go-tangra-docker-pdns-recursor-1"),
		authContainer:     envOr("AUTH_CONTAINER", "go-tangra-docker-powerdns-1"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultRecursor() *dnsV1.RecursorConfig {
	return &dnsV1.RecursorConfig{
		LocalAddress:   []string{"0.0.0.0", "::"},
		LocalPort:      53,
		AllowFrom:      []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		DnssecDisabled: true,
	}
}

func defaultAuth() *dnsV1.AuthConfig {
	return &dnsV1.AuthConfig{
		LocalAddress: []string{"0.0.0.0"},
		LocalPort:    53,
	}
}

// load reads the stored config, falling back to defaults for missing parts.
func (s *ConfigService) load(ctx context.Context) (*dnsV1.RecursorConfig, *dnsV1.AuthConfig) {
	rc, ac := defaultRecursor(), defaultAuth()
	data, err := s.repo.Get(ctx)
	if err != nil {
		s.log.Warnf("load config: %v", err)
		return rc, ac
	}
	if data == "" {
		return rc, ac
	}
	stored := &dnsV1.GetDnsConfigResponse{}
	if err := protojson.Unmarshal([]byte(data), stored); err != nil {
		s.log.Warnf("decode stored config: %v", err)
		return rc, ac
	}
	if stored.GetRecursor() != nil {
		rc = stored.GetRecursor()
	}
	if stored.GetAuthoritative() != nil {
		ac = stored.GetAuthoritative()
	}
	return rc, ac
}

func (s *ConfigService) GetDnsConfig(ctx context.Context, _ *dnsV1.GetDnsConfigRequest) (*dnsV1.GetDnsConfigResponse, error) {
	rc, ac := s.load(ctx)
	return &dnsV1.GetDnsConfigResponse{Recursor: rc, Authoritative: ac}, nil
}

func (s *ConfigService) UpdateDnsConfig(ctx context.Context, req *dnsV1.UpdateDnsConfigRequest) (*dnsV1.UpdateDnsConfigResponse, error) {
	rc := req.GetRecursor()
	if rc == nil {
		rc = defaultRecursor()
	}
	ac := req.GetAuthoritative()
	if ac == nil {
		ac = defaultAuth()
	}

	// Persist.
	stored := &dnsV1.GetDnsConfigResponse{Recursor: rc, Authoritative: ac}
	blob, err := protojson.Marshal(stored)
	if err == nil {
		if err := s.repo.Save(ctx, string(blob)); err != nil {
			s.log.WithContext(ctx).Warnf("persist config: %v", err)
		}
	}

	restarted := s.apply(ctx, rc, ac)

	// A restart can change a container's IP, which invalidates the recursor's
	// forward-zone targets. Re-point them once the containers are back up.
	if len(restarted) > 0 && s.reconciler != nil {
		go func() {
			time.Sleep(6 * time.Second)
			s.reconciler.ReconcileNow()
		}()
	}

	return &dnsV1.UpdateDnsConfigResponse{Recursor: rc, Authoritative: ac, Restarted: restarted}, nil
}

// apply renders config files and restarts any container whose file changed.
func (s *ConfigService) apply(ctx context.Context, rc *dnsV1.RecursorConfig, ac *dnsV1.AuthConfig) []string {
	var restarted []string

	if changed, err := writeIfChanged(s.recursorConfPath, dnsconf.RenderRecursorYAML(rc)); err != nil {
		s.log.WithContext(ctx).Warnf("write recursor config %s: %v", s.recursorConfPath, err)
	} else if changed {
		if err := s.docker.RestartContainer(ctx, s.recursorContainer); err != nil {
			s.log.WithContext(ctx).Warnf("restart recursor %s: %v", s.recursorContainer, err)
		} else {
			s.log.WithContext(ctx).Infof("applied recursor config, restarted %s", s.recursorContainer)
			restarted = append(restarted, s.recursorContainer)
		}
	}

	if changed, err := writeIfChanged(s.authConfPath, dnsconf.RenderAuthConf(ac)); err != nil {
		s.log.WithContext(ctx).Warnf("write auth config %s: %v", s.authConfPath, err)
	} else if changed {
		if err := s.docker.RestartContainer(ctx, s.authContainer); err != nil {
			s.log.WithContext(ctx).Warnf("restart auth %s: %v", s.authContainer, err)
		} else {
			s.log.WithContext(ctx).Infof("applied auth config, restarted %s", s.authContainer)
			restarted = append(restarted, s.authContainer)
		}
	}
	return restarted
}

// Start re-applies the stored config shortly after boot (covers a config
// file lost to a volume reset / drift). No-op when nothing is stored.
func (s *ConfigService) Start() error {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(8 * time.Second):
		}
		data, err := s.repo.Get(s.ctx)
		if err != nil || data == "" {
			return // nothing stored — entrypoint defaults stand
		}
		rc, ac := s.load(s.ctx)
		s.apply(s.ctx, rc, ac)
	}()
	return nil
}

func (s *ConfigService) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	return nil
}

func writeIfChanged(path, content string) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, err
	}
	return true, nil
}
