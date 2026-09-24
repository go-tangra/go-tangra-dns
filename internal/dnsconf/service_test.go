package dnsconf

// T080: the configuration service — config:manage AND platform-admin (tenant
// owners/admins and viewers refused); a save validates, persists, writes only
// the changed include file atomically and restarts only its container; a
// no-op save restarts nothing (SC-006); a disabled restarter reports
// restart_required; a recursor restart is followed by a readiness-polled
// reconcile; start-up re-apply rewrites drifted files; everything audited.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-dns/v4/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

const (
	tenant   = "11111111-1111-7111-8111-111111111111"
	platform = "22222222-2222-7222-8222-222222222222"
	owner    = "33333333-3333-7333-8333-333333333333"
)

type auditLog struct {
	mu sync.Mutex
	ev []audit.Event
}

func (a *auditLog) Record(_ context.Context, e audit.Event) error {
	if err := audit.Validate(e); err != nil {
		return err
	}
	a.mu.Lock()
	a.ev = append(a.ev, e)
	a.mu.Unlock()
	return nil
}

func (a *auditLog) of(t audit.EventType) []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []audit.Event
	for _, e := range a.ev {
		if e.EventType == t {
			out = append(out, e)
		}
	}
	return out
}

type svcHarness struct {
	svc        *Service
	st         *memstore.Mem
	rs         *Fake
	aud        *auditLog
	rec        *recursor.Fake
	reconciled int
	dir        string
	admin      authz.Subjects
	mu         sync.Mutex
}

func newSvc(t *testing.T, restarts bool) *svcHarness {
	t.Helper()
	h := &svcHarness{st: memstore.New(), rs: NewFake(restarts), aud: &auditLog{}, rec: recursor.NewFake(), dir: t.TempDir(),
		admin: authz.User(tenant, platform, []string{authz.RolePlatformAdmin})}
	checker := authz.Static{platform: {authz.ConfigManage}, owner: {authz.ConfigManage, authz.ZonesManage}}
	h.svc = New(ServiceDeps{Store: h.st, Restarter: h.rs, Checker: checker, Audit: h.aud,
		RecursorPath: filepath.Join(h.dir, "recursor.d", "freya.yml"), AuthPath: filepath.Join(h.dir, "pdns.d", "freya.conf"),
		Reconcile: func(ctx context.Context) error {
			h.mu.Lock()
			h.reconciled++
			h.mu.Unlock()
			return h.rec.Ready(ctx)
		}})
	for _, d := range []string{"recursor.d", "pdns.d"} {
		if err := os.MkdirAll(filepath.Join(h.dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *svcHarness) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, name)) // #nosec G304 -- test temp dir
	if err != nil {
		return ""
	}
	return string(b)
}

func TestConfigAuthority(t *testing.T) {
	h := newSvc(t, true)
	ctx := context.Background()
	refused := []authz.Subjects{
		authz.User(tenant, owner, []string{"owner", "admin"}),               // tenant admin holding config:manage
		authz.User(tenant, "viewer", nil),                                   // viewer
		authz.User(tenant, "pa-no-perm", []string{authz.RolePlatformAdmin}), // platform admin without config:manage
		authz.Module(tenant, "spiffe://example.org/svc/lcm"),                // module
		authz.SystemFor(tenant),                                             // IPAM sync
	}
	for _, s := range refused {
		if _, err := h.svc.Get(ctx, s); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("get by %+v = %v", s, err)
		}
		if _, err := h.svc.Update(ctx, s, Defaults()); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("update by %+v = %v", s, err)
		}
	}
	if len(h.aud.of(audit.ConfigUpdate)) != len(refused) {
		t.Fatalf("refused updates audited = %d", len(h.aud.of(audit.ConfigUpdate)))
	}
	for _, e := range h.aud.of(audit.ConfigUpdate) {
		if e.Outcome != audit.OutcomeRefused || e.TenantID != audit.NilTenant {
			t.Fatalf("refusal audit = %+v", e)
		}
	}
	if len(h.rs.Restarts()) != 0 || h.read(t, "recursor.d/freya.yml") != "" {
		t.Fatal("a refused caller changed something")
	}
	// Without a checker a platform admin is still required.
	open := New(ServiceDeps{Store: h.st, Restarter: h.rs})
	if _, err := open.Get(ctx, authz.User(tenant, owner, []string{"owner"})); !errors.Is(err, authz.ErrForbidden) {
		t.Fatal("no checker: tenant owner allowed")
	}
	if _, err := open.Get(ctx, h.admin); err != nil {
		t.Fatal(err)
	}
}

func TestGetDefaults(t *testing.T) {
	h := newSvc(t, true)
	v, err := h.svc.Get(context.Background(), h.admin)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Defaults || v.Recursor.Port != 53 || !v.Restarter.Enabled || v.Restarter.Containers["auth"] != "freya-pdns-auth" || v.Restarter.Containers["recursor"] != "freya-pdns-recursor" {
		t.Fatalf("view = %+v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "null") {
		t.Fatalf("view has nulls: %s", b)
	}
}

func TestUpdateWritesOnlyChangedAndRestartsOnlyAffected(t *testing.T) {
	h := newSvc(t, true)
	ctx := context.Background()
	// First save: both files are new → both containers restart.
	res, err := h.svc.Update(ctx, h.admin, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Changed, ",") != "recursor,authoritative" || strings.Join(res.Restarted, ",") != "freya-pdns-recursor,freya-pdns-auth" ||
		len(res.RestartRequired) != 0 || len(res.Errors) != 0 {
		t.Fatalf("first save = %+v", res)
	}
	if !strings.Contains(h.read(t, "recursor.d/freya.yml"), `validation: "off"`) || !strings.Contains(h.read(t, "pdns.d/freya.conf"), "local-port=53") {
		t.Fatal("files not rendered")
	}
	if h.reconciled != 1 {
		t.Fatalf("reconciled = %d", h.reconciled)
	}
	// No-op save: nothing restarts (SC-006).
	res, err = h.svc.Update(ctx, h.admin, Defaults())
	if err != nil || len(res.Changed) != 0 || len(res.Restarted) != 0 || len(res.RestartRequired) != 0 {
		t.Fatalf("no-op save = %+v %v", res, err)
	}
	if len(h.rs.Restarts()) != 2 {
		t.Fatalf("restarts after no-op = %v", h.rs.Restarts())
	}
	// Change only the resolver's allowed networks: only the recursor restarts.
	m := Defaults()
	m.Recursor.AllowedNetworks = []string{"10.20.0.0/16"}
	authBefore, _ := os.Stat(filepath.Join(h.dir, "pdns.d", "freya.conf"))
	res, err = h.svc.Update(ctx, h.admin, m)
	if err != nil || strings.Join(res.Changed, ",") != "recursor" || strings.Join(res.Restarted, ",") != "freya-pdns-recursor" {
		t.Fatalf("resolver change = %+v %v", res, err)
	}
	authAfter, _ := os.Stat(filepath.Join(h.dir, "pdns.d", "freya.conf"))
	if !authAfter.ModTime().Equal(authBefore.ModTime()) {
		t.Fatal("the unchanged auth file was rewritten")
	}
	if res.Recursor.AllowedNetworks[0] != "10.20.0.0/16" {
		t.Fatalf("result model = %+v", res.Recursor)
	}
	// Stored and returned by Get.
	v, _ := h.svc.Get(ctx, h.admin)
	if v.Defaults || v.Recursor.AllowedNetworks[0] != "10.20.0.0/16" {
		t.Fatalf("stored = %+v", v)
	}
	sc, _ := h.st.GetServerConfig(ctx)
	if sc.RecursorHash != Hash(h.read(t, "recursor.d/freya.yml")) || sc.AuthHash != Hash(h.read(t, "pdns.d/freya.conf")) || sc.UpdatedBy != platform {
		t.Fatalf("hashes = %+v", sc)
	}
	// Audit: update + apply + one restart per restarted container, platform scope.
	if len(h.aud.of(audit.ConfigUpdate)) != 3 || len(h.aud.of(audit.ConfigApply)) != 3 || len(h.aud.of(audit.ConfigRestart)) != 3 {
		t.Fatalf("audit = %+v", h.aud.ev)
	}
	for _, e := range h.aud.ev {
		if e.TenantID != audit.NilTenant || e.ActorID != platform {
			t.Fatalf("audit scope = %+v", e)
		}
		for k := range e.Details {
			if strings.Contains(k, "file") || strings.Contains(k, "content") {
				t.Fatalf("audit leaks %s", k)
			}
		}
	}
}

func TestUpdateRefusesInvalid(t *testing.T) {
	h := newSvc(t, true)
	m := Defaults()
	m.Recursor.AllowedNetworks = []string{"0.0.0.0/0"}
	_, err := h.svc.Update(context.Background(), h.admin, m)
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "recursor.allowed_networks[0]" {
		t.Fatalf("invalid = %v", err)
	}
	if _, err := h.st.GetServerConfig(context.Background()); err == nil {
		t.Fatal("an invalid config was stored")
	}
	e := h.aud.of(audit.ConfigUpdate)
	if len(e) != 1 || e[0].Outcome != audit.OutcomeRefused || e[0].Reason != "invalid_config" {
		t.Fatalf("audit = %+v", e)
	}
	// With the flag the open resolver is accepted (and audited as such).
	m.Recursor.AllowOpenResolver = true
	if _, err := h.svc.Update(context.Background(), h.admin, m); err != nil {
		t.Fatal(err)
	}
	if last := h.aud.of(audit.ConfigUpdate); last[len(last)-1].Details["open_resolver"] != true {
		t.Fatalf("open resolver not audited: %+v", last[len(last)-1])
	}
}

func TestDisabledRestarterReportsRestartRequired(t *testing.T) {
	h := newSvc(t, false)
	res, err := h.svc.Update(context.Background(), h.admin, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Restarted) != 0 || strings.Join(res.RestartRequired, ",") != "freya-pdns-recursor,freya-pdns-auth" || h.reconciled != 0 {
		t.Fatalf("disabled = %+v (reconciled %d)", res, h.reconciled)
	}
	v, _ := h.svc.Get(context.Background(), h.admin)
	if v.Restarter.Enabled {
		t.Fatal("view says enabled")
	}
}

func TestRestartAndWriteFailures(t *testing.T) {
	h := newSvc(t, true)
	h.rs.FailNext(ErrRestart)
	res, err := h.svc.Update(context.Background(), h.admin, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || res.Errors[0].Server != "recursor" || res.Errors[0].Reason != "restart_failed" ||
		strings.Join(res.RestartRequired, ",") != "freya-pdns-recursor" || strings.Join(res.Restarted, ",") != "freya-pdns-auth" {
		t.Fatalf("restart failure = %+v", res)
	}
	if h.reconciled != 0 {
		t.Fatal("reconciled after a failed recursor restart")
	}
	// An unwritable path is reported per server; nothing restarts for it.
	bad := New(ServiceDeps{Store: memstore.New(), Restarter: NewFake(true), RecursorPath: filepath.Join(h.dir, "missing", "x.yml"), AuthPath: filepath.Join(h.dir, "pdns.d", "other.conf")})
	res, err = bad.Update(context.Background(), h.admin, Defaults())
	if err != nil || len(res.Errors) != 1 || res.Errors[0].Reason != "write_failed" || strings.Join(res.Changed, ",") != "authoritative" {
		t.Fatalf("write failure = %+v %v", res, err)
	}
	// Unmanaged files (no paths) are reported, never written.
	none := New(ServiceDeps{Store: memstore.New(), Restarter: NewFake(true)})
	res, err = none.Update(context.Background(), h.admin, Defaults())
	if err != nil || len(res.Changed) != 0 || len(res.Errors) != 2 || res.Errors[0].Reason != "not_managed" {
		t.Fatalf("unmanaged = %+v %v", res, err)
	}
	// Store failures surface.
	st := memstore.New()
	st.FailNext("SaveServerConfig")
	if _, err := New(ServiceDeps{Store: st}).Update(context.Background(), h.admin, Defaults()); err == nil {
		t.Fatal("store failure hidden")
	}
	st.FailNext("GetServerConfig")
	if _, err := New(ServiceDeps{Store: st}).Get(context.Background(), h.admin); err == nil {
		t.Fatal("get failure hidden")
	}
}

func TestReapplyAtStartup(t *testing.T) {
	h := newSvc(t, true)
	ctx := context.Background()
	// Nothing stored: nothing is written.
	res, err := h.svc.Reapply(ctx)
	if err != nil || len(res.Changed) != 0 || h.read(t, "recursor.d/freya.yml") != "" {
		t.Fatalf("empty reapply = %+v %v", res, err)
	}
	m := Defaults()
	m.Authoritative.TransferPeers = []string{"198.51.100.0/24"}
	if _, err := h.svc.Update(ctx, h.admin, m); err != nil {
		t.Fatal(err)
	}
	restarts := len(h.rs.Restarts())
	// Unchanged files: no restart.
	if res, err = h.svc.Reapply(ctx); err != nil || len(res.Changed) != 0 || len(h.rs.Restarts()) != restarts {
		t.Fatalf("idempotent reapply = %+v %v", res, err)
	}
	// Drift: someone edited the auth file by hand.
	if err := os.WriteFile(filepath.Join(h.dir, "pdns.d", "freya.conf"), []byte("launch=pipe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = h.svc.Reapply(ctx)
	if err != nil || strings.Join(res.Changed, ",") != "authoritative" || strings.Join(res.Restarted, ",") != "freya-pdns-auth" {
		t.Fatalf("drift reapply = %+v %v", res, err)
	}
	if !strings.Contains(h.read(t, "pdns.d/freya.conf"), "allow-axfr-ips=198.51.100.0/24") {
		t.Fatal("drift not repaired")
	}
	e := h.aud.of(audit.ConfigApply)
	if last := e[len(e)-1]; last.ActorKind != audit.ActorSystem {
		t.Fatalf("reapply audit = %+v", last)
	}
	// A stored row that no longer validates is refused, not rendered.
	_ = h.st.SaveServerConfig(ctx, store.ServerConfig{Recursor: json.RawMessage(`{"listen_addresses":["x"],"port":53,"dnssec_validation":"off"}`), Authoritative: json.RawMessage(`{"listen_addresses":["0.0.0.0"],"port":53}`)})
	if _, err := h.svc.Reapply(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid stored = %v", err)
	}
	_ = h.st.SaveServerConfig(ctx, store.ServerConfig{Recursor: json.RawMessage(`[`), Authoritative: json.RawMessage(`{}`)})
	if _, err := h.svc.Reapply(ctx); err == nil {
		t.Fatal("corrupt stored config accepted")
	}
}

func TestRunWorker(t *testing.T) {
	h := newSvc(t, true)
	ctx := context.Background()
	if _, err := h.svc.Update(ctx, h.admin, Defaults()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(h.dir, "recursor.d", "freya.yml")); err != nil {
		t.Fatal(err)
	}
	h.st.FailNext("GetServerConfig") // first attempt fails, the worker retries
	h.svc.retry = time.Millisecond
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	h.svc.Run(rctx)
	if h.read(t, "recursor.d/freya.yml") == "" {
		t.Fatal("run did not re-apply")
	}
	// A cancelled context stops the retries.
	h.st.FailNext("GetServerConfig")
	cctx, ccancel := context.WithCancel(ctx)
	ccancel()
	h.svc.Run(cctx)
}

func TestDiskWriter(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.conf")
	w := DiskWriter{}
	changed, err := w.WriteIfChanged(p, "a\n")
	if err != nil || !changed {
		t.Fatalf("first = %v %v", changed, err)
	}
	if changed, err = w.WriteIfChanged(p, "a\n"); err != nil || changed {
		t.Fatalf("same = %v %v", changed, err)
	}
	if changed, err = w.WriteIfChanged(p, "b\n"); err != nil || !changed {
		t.Fatalf("different = %v %v", changed, err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
	if _, err := w.WriteIfChanged(filepath.Join(dir, "nope", "x"), "a"); err == nil {
		t.Fatal("missing dir accepted")
	}
	if _, err := w.WriteIfChanged(dir, "a"); err == nil {
		t.Fatal("a directory path accepted")
	}
	if Hash("a") == Hash("b") || len(Hash("a")) != 64 {
		t.Fatal("hash")
	}
}
