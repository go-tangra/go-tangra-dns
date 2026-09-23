package acmechallenge

// T067: the ACME DNS-01 challenge service — name rules, longest tenant zone,
// nothing written outside the tenant's zones, CNAME refusal, value format,
// add/remove of ONE TXT value keeping the others, idempotence, per-name
// serialisation, the sweeper and the audit trail.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
	lcm     = "spiffe://example.org/svc/lcm"
)

// tok returns a distinct 43-char base64url value.
func tok(i int) string {
	s := fmt.Sprintf("tok%02d", i)
	return s + strings.Repeat("A", 43-len(s))
}

type auditLog struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *auditLog) Record(_ context.Context, e audit.Event) error {
	if err := audit.Validate(e); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}

func (a *auditLog) of(t audit.EventType) []audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []audit.Event
	for _, e := range a.events {
		if e.EventType == t {
			out = append(out, e)
		}
	}
	return out
}

type harness struct {
	svc  *Service
	zs   *zones.Service
	rs   *records.Service
	st   *memstore.Mem
	pd   *pdns.Fake
	aud  *auditLog
	subj authz.Subjects
	apex store.Zone
	sub  store.Zone
	now  time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{st: memstore.New(), pd: pdns.NewFake(), aud: &auditLog{}, subj: authz.Module(tenantA, lcm), now: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)}
	h.st.Now = func() time.Time { return h.now }
	h.zs = zones.New(zones.Deps{Store: h.st, PDNS: h.pd})
	h.rs = records.New(records.Deps{Zones: h.zs, PDNS: h.pd})
	h.svc = New(Deps{Zones: h.zs, Records: h.rs, Store: h.st, Audit: h.aud, AllowedCaller: lcm, Now: func() time.Time { return h.now }})
	ctx := context.Background()
	var err error
	if h.apex, err = h.zs.Create(ctx, authz.Internal(tenantA), zones.CreateInput{Name: "example.test", Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	if h.sub, err = h.zs.Create(ctx, authz.Internal(tenantA), zones.CreateInput{Name: "lab.example.test", Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.zs.Create(ctx, authz.Internal(tenantB), zones.CreateInput{Name: "other.test", Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.zs.Create(ctx, authz.Internal(tenantA), zones.CreateInput{Name: "sec.test", Kind: "slave", Masters: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) txt(t *testing.T, z store.Zone, name string) []string {
	t.Helper()
	rs, err := h.rs.Lookup(context.Background(), authz.Internal(z.TenantID), z, records.Key{Name: name, Type: "TXT"})
	if errors.Is(err, records.ErrNotFound) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v := range rs.Values {
		out = append(out, v.Content)
	}
	return out
}

func req(domain, fqdn, value string) Request {
	return Request{Domain: domain, FQDN: fqdn, Value: value}
}

func TestPresentLongestZoneAndCleanUp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	zone, err := h.svc.Present(ctx, h.subj, req("host.lab.example.test", "_acme-challenge.host.lab.example.test.", tok(1)))
	if err != nil {
		t.Fatal(err)
	}
	if zone != "lab.example.test." {
		t.Fatalf("zone = %q, want the longest tenant zone", zone)
	}
	if got := h.txt(t, h.sub, "_acme-challenge.host"); len(got) != 1 || got[0] != `"`+tok(1)+`"` {
		t.Fatalf("txt = %v", got)
	}
	if h.txt(t, h.apex, "_acme-challenge.host.lab") != nil {
		t.Fatal("written to the shorter zone")
	}
	olds, _ := h.st.ChallengesOlderThan(ctx, h.now.Add(time.Hour), 10)
	if len(olds) != 1 || olds[0].ZoneID != h.sub.ID || olds[0].RequestedBy != lcm || olds[0].FQDN != "_acme-challenge.host.lab.example.test." {
		t.Fatalf("bookkeeping = %+v", olds)
	}
	if zone, err = h.svc.CleanUp(ctx, h.subj, req("host.lab.example.test", "_acme-challenge.host.lab.example.test", tok(1))); err != nil || zone != "lab.example.test." {
		t.Fatalf("cleanup = %q %v", zone, err)
	}
	if got := h.txt(t, h.sub, "_acme-challenge.host"); got != nil {
		t.Fatalf("rrset not deleted when empty: %v", got)
	}
	if olds, _ = h.st.ChallengesOlderThan(ctx, h.now.Add(time.Hour), 10); len(olds) != 0 {
		t.Fatalf("bookkeeping left: %+v", olds)
	}
	if len(h.aud.of(audit.ChallengePresent)) != 1 || len(h.aud.of(audit.ChallengeCleanup)) != 1 {
		t.Fatalf("audit = %+v", h.aud.events)
	}
	e := h.aud.of(audit.ChallengePresent)[0]
	if e.ActorKind != audit.ActorModule || e.ActorID != lcm || e.TenantID != tenantA || e.Outcome != audit.OutcomeOK || e.Details["zone"] != "lab.example.test." {
		t.Fatalf("present audit = %+v", e)
	}
	for _, ev := range h.aud.events {
		for k, v := range ev.Details {
			if strings.Contains(fmt.Sprint(v), tok(1)) {
				t.Fatalf("audit detail %s carries the token", k)
			}
		}
	}
}

func TestPresentKeepsOtherValuesAndIsIdempotent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	other := validate.RecordSetInput{Name: "_acme-challenge", Type: "TXT", TTL: 300, Comment: "keep me",
		Values: []validate.RecordValue{{Content: "unrelated"}}}
	if _, err := h.rs.Apply(ctx, authz.Internal(tenantA), h.apex, other, "api"); err != nil {
		t.Fatal(err)
	}
	r := req("example.test", "_acme-challenge.example.test.", tok(2))
	for i := 0; i < 2; i++ {
		if _, err := h.svc.Present(ctx, h.subj, r); err != nil {
			t.Fatal(err)
		}
	}
	got := h.txt(t, h.apex, "_acme-challenge")
	if len(got) != 2 || got[0] != `"unrelated"` || got[1] != `"`+tok(2)+`"` {
		t.Fatalf("txt = %v", got)
	}
	rs, _ := h.rs.Lookup(ctx, authz.Internal(tenantA), h.apex, records.Key{Name: "_acme-challenge", Type: "TXT"})
	if rs.Comment != "keep me" {
		t.Fatalf("comment lost: %+v", rs)
	}
	// Wildcard + apex share the name: a second value is added, not replaced.
	if _, err := h.svc.Present(ctx, h.subj, req("*.example.test", "_acme-challenge.example.test.", tok(3))); err != nil {
		t.Fatal(err)
	}
	if got = h.txt(t, h.apex, "_acme-challenge"); len(got) != 3 {
		t.Fatalf("txt = %v", got)
	}
	// CleanUp removes only its value; unknown values and repeats are OK.
	for i := 0; i < 2; i++ {
		if _, err := h.svc.CleanUp(ctx, h.subj, r); err != nil {
			t.Fatal(err)
		}
	}
	if got = h.txt(t, h.apex, "_acme-challenge"); len(got) != 2 || got[0] != `"unrelated"` || got[1] != `"`+tok(3)+`"` {
		t.Fatalf("after cleanup txt = %v", got)
	}
	if _, err := h.svc.CleanUp(ctx, h.subj, req("nothing.example.test", "_acme-challenge.nothing.example.test", tok(9))); err != nil {
		t.Fatalf("cleanup of an absent rrset: %v", err)
	}
}

func TestRefusals(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cases := []struct {
		name string
		r    Request
		want error
	}{
		{"fqdn mismatch", req("example.test", "_acme-challenge.other.example.test", tok(1)), ErrInvalid},
		{"no prefix", req("example.test", "example.test", tok(1)), ErrInvalid},
		{"wildcard fqdn", req("*.example.test", "_acme-challenge.*.example.test", tok(1)), ErrInvalid},
		{"double wildcard", req("*.*.example.test", "_acme-challenge.*.example.test", tok(1)), ErrInvalid},
		{"bad domain", req("exa mple.test", "_acme-challenge.exa mple.test", tok(1)), ErrInvalid},
		{"empty domain", req("", "_acme-challenge.", tok(1)), ErrInvalid},
		{"short value", req("example.test", "_acme-challenge.example.test", "abc"), ErrInvalid},
		{"value charset", req("example.test", "_acme-challenge.example.test", strings.Repeat("+", 43)), ErrInvalid},
		{"quote injection", req("example.test", "_acme-challenge.example.test", `"`+strings.Repeat("a", 42)), ErrInvalid},
		{"other tenant zone", req("x.other.test", "_acme-challenge.x.other.test", tok(1)), ErrNotFound},
		{"no zone", req("nowhere.invalid", "_acme-challenge.nowhere.invalid", tok(1)), ErrNotFound},
		{"secondary zone", req("sec.test", "_acme-challenge.sec.test", tok(1)), ErrPrecondition},
	}
	for _, c := range cases {
		if _, err := h.svc.Present(ctx, h.subj, c.r); !errors.Is(err, c.want) {
			t.Errorf("%s: present = %v, want %v", c.name, err, c.want)
		}
		if _, err := h.svc.CleanUp(ctx, h.subj, c.r); !errors.Is(err, c.want) {
			t.Errorf("%s: cleanup = %v, want %v", c.name, err, c.want)
		}
	}
	if n := len(h.pd.CallLog()); n > 0 {
		for _, c := range h.pd.CallLog() {
			if strings.HasPrefix(c, "PatchRRsets") {
				t.Fatalf("a refused challenge wrote to PowerDNS: %v", h.pd.CallLog())
			}
		}
	}
	// A CNAME at the name refuses.
	cname := validate.RecordSetInput{Name: "_acme-challenge.www", Type: "CNAME", TTL: 300, Values: []validate.RecordValue{{Content: "elsewhere.example."}}}
	if _, err := h.rs.Apply(ctx, authz.Internal(tenantA), h.apex, cname, "api"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Present(ctx, h.subj, req("www.example.test", "_acme-challenge.www.example.test", tok(1))); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("cname present = %v", err)
	}
	// Only the configured caller.
	for _, s := range []authz.Subjects{authz.Module(tenantA, "spiffe://example.org/svc/deployer"), authz.User(tenantA, "u", []string{authz.RolePlatformAdmin}), authz.Internal(tenantA)} {
		if _, err := h.svc.Present(ctx, s, req("example.test", "_acme-challenge.example.test", tok(1))); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("%+v present = %v", s, err)
		}
	}
	if got := len(h.aud.of(audit.ChallengeRefused)); got < len(cases) {
		t.Fatalf("refusals audited = %d", got)
	}
	// PowerDNS down → unavailable.
	h.pd.SetDown(true)
	if _, err := h.svc.Present(ctx, h.subj, req("example.test", "_acme-challenge.example.test", tok(1))); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("down present = %v", err)
	}
}

func TestConcurrentPresentSerialisedPerName(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := "example.test"
			if i%2 == 1 {
				d = "*.example.test"
			}
			if _, err := h.svc.Present(ctx, h.subj, req(d, "_acme-challenge.example.test", tok(i))); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := h.txt(t, h.apex, "_acme-challenge"); len(got) != n {
		t.Fatalf("lost updates: %d values %v", len(got), got)
	}
}

func TestSweeper(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Present(ctx, h.subj, req("example.test", "_acme-challenge.example.test", tok(1))); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(30 * time.Minute)
	if _, err := h.svc.Present(ctx, h.subj, req("*.example.test", "_acme-challenge.example.test", tok(2))); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(40 * time.Minute) // tok(1) is 70 min old, tok(2) 40 min
	n, err := h.svc.Sweep(ctx, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("sweep = %d %v", n, err)
	}
	if got := h.txt(t, h.apex, "_acme-challenge"); len(got) != 1 || got[0] != `"`+tok(2)+`"` {
		t.Fatalf("after sweep txt = %v", got)
	}
	sw := h.aud.of(audit.ChallengeSwept)
	if len(sw) != 1 || sw[0].ActorKind != audit.ActorSystem || sw[0].TenantID != tenantA {
		t.Fatalf("swept audit = %+v", sw)
	}
	// A challenge whose zone is gone is just forgotten.
	h.now = h.now.Add(2 * time.Hour)
	if err := h.zs.Delete(ctx, authz.Internal(tenantA), h.apex.ID); err != nil {
		t.Fatal(err)
	}
	if n, err = h.svc.Sweep(ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("sweep after zone delete = %d %v", n, err)
	}
	if olds, _ := h.st.ChallengesOlderThan(ctx, h.now, 10); len(olds) != 0 {
		t.Fatalf("left: %+v", olds)
	}
	// Store failures are reported.
	h.st.FailNext("ChallengesOlderThan")
	if _, err := h.svc.Sweep(ctx, time.Hour); err == nil {
		t.Fatal("store failure hidden")
	}
}

func TestSweeperWorker(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := h.svc.Present(ctx, h.subj, req("example.test", "_acme-challenge.example.test", tok(1))); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	w := &Sweeper{Service: h.svc, MaxAge: time.Hour, Interval: 5 * time.Millisecond}
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(h.aud.of(audit.ChallengeSwept)) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if len(h.aud.of(audit.ChallengeSwept)) != 1 {
		t.Fatal("sweeper did not run")
	}
}

func TestBookkeepingFailureIsTolerated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.FailNext("InsertChallenge")
	if _, err := h.svc.Present(ctx, h.subj, req("example.test", "_acme-challenge.example.test", tok(1))); err != nil {
		t.Fatalf("present with a bookkeeping failure = %v", err)
	}
	h.st.FailNext("DeleteChallenge")
	if _, err := h.svc.CleanUp(ctx, h.subj, req("example.test", "_acme-challenge.example.test", tok(1))); err != nil {
		t.Fatalf("cleanup with a bookkeeping failure = %v", err)
	}
}

func TestRefusedHelper(t *testing.T) {
	h := newHarness(t)
	h.svc.Refused(context.Background(), "spiffe://example.org/svc/deployer", "not-a-uuid")
	h.svc.Refused(context.Background(), "", tenantA)
	ev := h.aud.of(audit.ChallengeRefused)
	if len(ev) != 2 || ev[0].TenantID != audit.NilTenant || ev[0].ActorID != "spiffe://example.org/svc/deployer" || ev[1].TenantID != tenantA {
		t.Fatalf("refused audit = %+v", ev)
	}
}
