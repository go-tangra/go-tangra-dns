package dnsconf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/metrics"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

// Server names (API "changed"/"errors[].server").
const (
	ServerRecursor      = "recursor"
	ServerAuthoritative = "authoritative"
)

// ServiceDeps wire the configuration service. Store is required.
type ServiceDeps struct {
	Store     repo.ServerConfig
	Files     FileWriter // default DiskWriter
	Restarter Restarter  // default: disabled (restart_required)
	// Reconcile re-synchronises the resolver's forward zones after a recursor
	// restart (recursor.Reconciler.ReconcileNow: readiness-polled).
	Reconcile func(ctx context.Context) error
	Checker   authz.Checker
	Audit     audit.Recorder
	Metrics   *metrics.Metrics
	// RecursorPath/AuthPath are the managed include files (empty = the
	// server's configuration is not managed on this deployment).
	RecursorPath string
	AuthPath     string
	Log          *slog.Logger
	Now          func() time.Time
}

// Service reads, saves and applies the server configuration.
type Service struct {
	d     ServiceDeps
	mu    sync.Mutex // one apply at a time
	retry time.Duration
}

// New builds the service.
func New(d ServiceDeps) *Service {
	if d.Files == nil {
		d.Files = DiskWriter{}
	}
	if d.Restarter == nil {
		d.Restarter = disabled{}
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{d: d, retry: 5 * time.Second}
}

// disabled is the default Restarter: never restarts.
type disabled struct{}

func (disabled) Enabled() bool { return false }
func (disabled) Containers() map[Target]string {
	return map[Target]string{TargetAuth: "", TargetRecursor: ""}
}
func (disabled) Restart(context.Context, Target) (string, error) { return "", ErrDisabled }

// RestarterView describes the restarter (the two configured names only).
type RestarterView struct {
	Enabled    bool              `json:"enabled"`
	Containers map[string]string `json:"containers"`
}

// View is the GET /config response.
type View struct {
	Recursor      Recursor      `json:"recursor"`
	Authoritative Authoritative `json:"authoritative"`
	Defaults      bool          `json:"defaults"`
	Restarter     RestarterView `json:"restarter"`
}

// ServerError reports a per-server apply problem (never file contents).
type ServerError struct {
	Server string `json:"server"`
	Reason string `json:"reason"` // write_failed | restart_failed | not_managed
}

// Result is the PUT /config response.
type Result struct {
	Recursor        Recursor      `json:"recursor"`
	Authoritative   Authoritative `json:"authoritative"`
	Changed         []string      `json:"changed"`
	Restarted       []string      `json:"restarted"`
	RestartRequired []string      `json:"restart_required"`
	Errors          []ServerError `json:"errors"`
}

// authorize requires platform-admin authority AND config:manage (when a
// checker is wired; the HTTP layer enforces the route permission too).
func (s *Service) authorize(ctx context.Context, subj authz.Subjects) error {
	if err := authz.RequirePlatformAdmin(subj); err != nil {
		return err
	}
	if s.d.Checker != nil {
		return authz.Require(ctx, s.d.Checker, subj, authz.ConfigManage)
	}
	return nil
}

func (s *Service) emit(ctx context.Context, subj authz.Subjects, t audit.EventType, kind, id, outcome, reason string, details map[string]any) {
	audit.Emit(ctx, s.d.Audit, audit.Event{TenantID: audit.NilTenant, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: kind, SubjectID: id, Outcome: outcome, Reason: reason, Details: details})
}

// stored loads the saved model; ok=false when nothing was saved.
func (s *Service) stored(ctx context.Context) (Model, bool, error) {
	row, err := s.d.Store.GetServerConfig(ctx)
	if errors.Is(err, repo.ErrNotFound) {
		return Defaults(), false, nil
	}
	if err != nil {
		return Model{}, false, err
	}
	m := Model{}
	if err := json.Unmarshal(row.Recursor, &m.Recursor); err != nil {
		return Model{}, false, fmt.Errorf("dnsconf: stored recursor section: %w", err)
	}
	if err := json.Unmarshal(row.Authoritative, &m.Authoritative); err != nil {
		return Model{}, false, fmt.Errorf("dnsconf: stored authoritative section: %w", err)
	}
	return m, true, nil
}

func (s *Service) restarterView() RestarterView {
	c := s.d.Restarter.Containers()
	return RestarterView{Enabled: s.d.Restarter.Enabled(), Containers: map[string]string{"auth": c[TargetAuth], "recursor": c[TargetRecursor]}}
}

// Get returns the stored configuration (or the defaults) and the restarter.
func (s *Service) Get(ctx context.Context, subj authz.Subjects) (View, error) {
	if err := s.authorize(ctx, subj); err != nil {
		return View{}, err
	}
	m, saved, err := s.stored(ctx)
	if err != nil {
		return View{}, err
	}
	if v, verr := m.Validate(); verr == nil {
		m = v.Model() // canonical, never null lists
	}
	return View{Recursor: m.Recursor, Authoritative: m.Authoritative, Defaults: !saved, Restarter: s.restarterView()}, nil
}

// Update validates and saves the configuration, then applies it: renders both
// files, writes only those that changed and restarts only their containers.
func (s *Service) Update(ctx context.Context, subj authz.Subjects, in Model) (Result, error) {
	if err := s.authorize(ctx, subj); err != nil {
		s.emit(ctx, subj, audit.ConfigUpdate, audit.SubjectConfig, "server", audit.OutcomeRefused, "forbidden", nil)
		return Result{}, err
	}
	v, err := in.Validate()
	if err != nil {
		s.emit(ctx, subj, audit.ConfigUpdate, audit.SubjectConfig, "server", audit.OutcomeRefused, "invalid_config", nil)
		return Result{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := v.Model()
	rec, _ := json.Marshal(m.Recursor)
	auth, _ := json.Marshal(m.Authoritative)
	if err := s.d.Store.SaveServerConfig(ctx, store.ServerConfig{Recursor: rec, Authoritative: auth, UpdatedBy: subj.ActorID(), UpdatedAt: s.d.Now()}); err != nil {
		s.emit(ctx, subj, audit.ConfigUpdate, audit.SubjectConfig, "server", audit.OutcomeError, "store", nil)
		return Result{}, err
	}
	s.emit(ctx, subj, audit.ConfigUpdate, audit.SubjectConfig, "server", audit.OutcomeOK, "", map[string]any{"open_resolver": v.OpenResolver()})
	return s.apply(ctx, subj, v, true)
}

// Reapply re-applies the stored configuration at start-up (system scope):
// drifted files are rewritten and only their containers restarted. Nothing
// happens when no configuration was ever saved.
func (s *Service) Reapply(ctx context.Context) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, saved, err := s.stored(ctx)
	if err != nil {
		return Result{}, err
	}
	if !saved {
		return Result{Changed: []string{}, Restarted: []string{}, RestartRequired: []string{}, Errors: []ServerError{}}, nil
	}
	v, err := m.Validate()
	if err != nil {
		return Result{}, err
	}
	return s.apply(ctx, authz.Internal(""), v, false)
}

// Run is the start-up re-apply worker: it retries until the store answers or
// ctx ends, then returns.
func (s *Service) Run(ctx context.Context) {
	for {
		res, err := s.Reapply(ctx)
		if err == nil {
			if len(res.Changed) > 0 {
				s.d.Log.InfoContext(ctx, "server configuration re-applied", "changed", res.Changed, "restarted", res.Restarted, "restart_required", res.RestartRequired)
			}
			return
		}
		if errors.Is(err, ErrInvalid) {
			s.d.Log.ErrorContext(ctx, "stored server configuration is invalid; not applied", "err", err)
			return
		}
		s.d.Log.WarnContext(ctx, "server configuration re-apply failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.retry):
		}
	}
}

type server struct {
	name   string
	path   string
	target Target
	render func(Validated) (string, error)
}

// apply renders and writes both files and restarts the changed containers.
func (s *Service) apply(ctx context.Context, subj authz.Subjects, v Validated, reportUnmanaged bool) (Result, error) {
	m := v.Model()
	res := Result{Recursor: m.Recursor, Authoritative: m.Authoritative, Changed: []string{}, Restarted: []string{}, RestartRequired: []string{}, Errors: []ServerError{}}
	hashes := map[string]string{}
	servers := []server{
		{ServerRecursor, s.d.RecursorPath, TargetRecursor, RenderRecursorYAML},
		{ServerAuthoritative, s.d.AuthPath, TargetAuth, RenderAuthConf},
	}
	recursorRestarted := false
	for _, sv := range servers {
		content, err := sv.render(v)
		if err != nil {
			return Result{}, err
		}
		hashes[sv.name] = Hash(content)
		if sv.path == "" {
			if reportUnmanaged {
				res.Errors = append(res.Errors, ServerError{Server: sv.name, Reason: "not_managed"})
			}
			continue
		}
		changed, err := s.d.Files.WriteIfChanged(sv.path, content)
		if err != nil {
			s.d.Log.ErrorContext(ctx, "writing the managed include file failed", "server", sv.name, "err", err)
			res.Errors = append(res.Errors, ServerError{Server: sv.name, Reason: "write_failed"})
			continue
		}
		if !changed {
			continue
		}
		res.Changed = append(res.Changed, sv.name)
		if ok := s.restart(ctx, subj, sv, &res); ok && sv.target == TargetRecursor {
			recursorRestarted = true
		}
	}
	if err := s.d.Store.SetConfigHashes(ctx, hashes[ServerRecursor], hashes[ServerAuthoritative], s.d.Now()); err != nil {
		s.d.Log.WarnContext(ctx, "recording the applied configuration hashes failed", "err", err)
	}
	if recursorRestarted && s.d.Reconcile != nil {
		if err := s.d.Reconcile(ctx); err != nil {
			s.d.Log.WarnContext(ctx, "resolver forward re-sync after restart failed (the reconciler retries)", "err", err)
		}
	}
	outcome := audit.OutcomeOK
	if len(res.Errors) > 0 {
		outcome = audit.OutcomeError
	}
	s.emit(ctx, subj, audit.ConfigApply, audit.SubjectConfig, "server", outcome, "", map[string]any{
		"changed": toAny(res.Changed), "restarted": toAny(res.Restarted), "restart_required": toAny(res.RestartRequired)})
	return res, nil
}

// restart restarts the container of a changed server (or records that a
// restart is required) and reports whether it restarted.
func (s *Service) restart(ctx context.Context, subj authz.Subjects, sv server, res *Result) bool {
	name := s.d.Restarter.Containers()[sv.target]
	if !s.d.Restarter.Enabled() {
		res.RestartRequired = append(res.RestartRequired, name)
		return false
	}
	name, err := s.d.Restarter.Restart(ctx, sv.target)
	if err != nil {
		s.d.Log.ErrorContext(ctx, "container restart failed", "container", name, "err", err)
		res.Errors = append(res.Errors, ServerError{Server: sv.name, Reason: "restart_failed"})
		res.RestartRequired = append(res.RestartRequired, name)
		s.emit(ctx, subj, audit.ConfigRestart, audit.SubjectContainer, name, audit.OutcomeError, "restart_failed", map[string]any{"server": sv.name})
		s.d.Metrics.Restart(string(sv.target), metrics.ResultError)
		return false
	}
	res.Restarted = append(res.Restarted, name)
	s.emit(ctx, subj, audit.ConfigRestart, audit.SubjectContainer, name, audit.OutcomeOK, "", map[string]any{"server": sv.name})
	s.d.Metrics.Restart(string(sv.target), metrics.ResultOK)
	return true
}

func toAny(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}
