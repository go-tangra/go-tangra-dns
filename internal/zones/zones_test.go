package zones

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/events"
	"github.com/go-tangra/go-tangra-dns/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
	userA   = "33333333-3333-7333-8333-333333333333"
	userB   = "44444444-4444-7444-8444-444444444444"
)

type auditLog struct{ events []audit.Event }

func (a *auditLog) Record(_ context.Context, e audit.Event) error {
	if err := audit.Validate(e); err != nil {
		return err
	}
	a.events = append(a.events, e)
	return nil
}

func (a *auditLog) last() audit.Event { return a.events[len(a.events)-1] }

type harness struct {
	svc  *Service
	st   *memstore.Mem
	pd   *pdns.Fake
	rec  *recursor.Fake
	pub  *events.Recorder
	aud  *auditLog
	subA authz.Subjects
	subB authz.Subjects
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{st: memstore.New(), pd: pdns.NewFake(), rec: recursor.NewFake(), pub: &events.Recorder{}, aud: &auditLog{},
		subA: authz.User(tenantA, userA, nil), subB: authz.User(tenantB, userB, nil)}
	h.svc = New(Deps{Store: h.st, PDNS: h.pd, Recursor: h.rec, Events: h.pub, Audit: h.aud,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return h
}

func (h *harness) create(t *testing.T, subj authz.Subjects, name string) store.Zone {
	t.Helper()
	z, err := h.svc.Create(context.Background(), subj, CreateInput{Name: name, Kind: store.KindNative, Nameservers: []string{"ns1." + strings.TrimSuffix(name, ".") + "."}})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return z
}

func TestCreatePowerDNSFirstThenLocal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	z, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "Example.TEST", Kind: "native", Nameservers: []string{"NS1.example.test"},
		DNSSEC: true, Description: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if z.Name != "example.test." || z.PDNSID != "example.test." || z.TenantID != tenantA || z.Origin != store.OriginManual ||
		z.CreatedBy != userA || z.ID == "" || !z.DNSSEC || z.Masters == nil || len(z.Nameservers) != 1 || z.Nameservers[0] != "ns1.example.test." {
		t.Fatalf("zone = %+v", z)
	}
	calls := h.pd.CallLog()
	pz, err := h.pd.GetZone(ctx, "example.test.")
	if err != nil || pz.Kind != "Native" || pz.Account != tenantA || !pz.DNSSEC {
		t.Fatalf("pdns zone = %+v %v", pz, err)
	}
	if len(calls) != 2 || calls[0] != "GetZone example.test." || calls[1] != "CreateZone example.test." {
		t.Fatalf("calls = %v", calls)
	}
	if _, ok := h.rec.Forwards()["example.test."]; !ok {
		t.Fatalf("recursor forward missing: %v", h.rec.Forwards())
	}
	if len(h.pub.Events) != 1 || h.pub.Events[0].Type != events.ZoneCreated || h.pub.Events[0].TenantID != tenantA {
		t.Fatalf("events = %+v", h.pub.Events)
	}
	if e := h.aud.last(); e.EventType != audit.ZoneCreate || e.Outcome != audit.OutcomeOK || e.SubjectID != z.ID {
		t.Fatalf("audit = %+v", e)
	}
	// slave zone with masters
	s, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "sec.test", Kind: "slave", Masters: []string{"192.0.2.1", "192.0.2.2:5300"},
		Nameservers: []string{"ignored.example."}})
	if err != nil || len(s.Masters) != 2 || len(s.Nameservers) != 0 || s.Kind != store.KindSlave {
		t.Fatalf("slave = %+v %v", s, err)
	}
}

func TestCreateRefusals(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.create(t, h.subA, "example.test.")
	h.create(t, h.subA, "deep.corp.test.")
	h.pd.Seed(pdns.Zone{Name: "outside.test.", Kind: "Native"})
	cases := []struct {
		name string
		subj authz.Subjects
		in   CreateInput
		want error
	}{
		{"invalid name", h.subA, CreateInput{Name: "bad..name", Kind: "native"}, validate.ErrName},
		{"public suffix", h.subA, CreateInput{Name: "co.uk", Kind: "native"}, validate.ErrName},
		{"bad kind", h.subA, CreateInput{Name: "k.test", Kind: "primary"}, ErrInvalidKind},
		{"slave without masters", h.subA, CreateInput{Name: "s.test", Kind: "slave"}, ErrInvalidKind},
		{"masters on native", h.subA, CreateInput{Name: "m.test", Kind: "native", Masters: []string{"192.0.2.1"}}, validate.ErrMasters},
		{"bad master", h.subA, CreateInput{Name: "m.test", Kind: "slave", Masters: []string{"127.0.0.1"}}, validate.ErrMasters},
		{"bad nameserver", h.subA, CreateInput{Name: "n.test", Kind: "native", Nameservers: []string{"ns_1"}}, validate.ErrName},
		{"long description", h.subA, CreateInput{Name: "d.test", Kind: "native", Description: strings.Repeat("d", 1001)}, ErrInvalid},
		{"template without templates", h.subA, CreateInput{Name: "t.test", Kind: "native", TemplateID: "x"}, ErrTemplateNotFound},
		{"same tenant duplicate", h.subA, CreateInput{Name: "EXAMPLE.test", Kind: "native"}, ErrDuplicate},
		{"other tenant duplicate", h.subB, CreateInput{Name: "example.test", Kind: "native"}, ErrDuplicate},
		{"other tenant child", h.subB, CreateInput{Name: "sub.example.test", Kind: "native"}, ErrDuplicate},
		{"other tenant parent", h.subB, CreateInput{Name: "corp.test", Kind: "native"}, ErrDuplicate},
		{"unrelated name", h.subB, CreateInput{Name: "a.b.test", Kind: "native"}, nil},
		{"present in PowerDNS only", h.subA, CreateInput{Name: "outside.test", Kind: "native"}, ErrDuplicate},
		{"no tenant", authz.Subjects{ActorKind: authz.ActorUser, UserID: userA}, CreateInput{Name: "x.test", Kind: "native"}, authz.ErrForbidden},
		{"module actor", authz.Module(tenantA, "spiffe://example.org/svc/x"), CreateInput{Name: "x.test", Kind: "native"}, authz.ErrForbidden},
	}
	for _, c := range cases {
		before := len(h.pd.CallLog())
		_, err := h.svc.Create(ctx, c.subj, c.in)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if c.want != ErrDuplicate || c.name == "present in PowerDNS only" {
			continue
		}
		// duplicates are refused before any PowerDNS call
		if after := h.pd.CallLog(); len(after) != before {
			t.Errorf("%s: PowerDNS called: %v", c.name, after[before:])
		}
	}
	// the zone present only in PowerDNS was never adopted nor touched
	if _, err := h.st.GetZoneByName(ctx, tenantA, "outside.test."); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("adopted: %v", err)
	}
	// same-tenant nesting is allowed
	h.create(t, h.subA, "lab.example.test.")
	if e := h.aud.events; len(e) == 0 {
		t.Fatal("no audit")
	}
	refused := 0
	for _, e := range h.aud.events {
		if e.EventType == audit.ZoneCreate && e.Outcome == audit.OutcomeRefused {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("refusals not audited")
	}
}

func TestCreateCompensatesWhenLocalInsertFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.st.FailNext("CreateZone")
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "comp.test", Kind: "native"}); err == nil {
		t.Fatal("expected failure")
	}
	if calls := h.pd.CallLog(); calls[len(calls)-1] != "DeleteZone comp.test." {
		t.Fatalf("calls = %v", calls)
	}
	if _, err := h.pd.GetZone(ctx, "comp.test."); !errors.Is(err, pdns.ErrNotFound) {
		t.Fatalf("PowerDNS zone not compensated: %v", err)
	}
	if len(h.pub.Events) != 0 || len(h.rec.Forwards()) != 0 {
		t.Fatal("side effects after a failed create")
	}
	if e := h.aud.last(); e.Outcome != audit.OutcomeError {
		t.Fatalf("audit = %+v", e)
	}
	// compensation failure is logged, the original error still returned
	h.st.FailNext("CreateZone")
	h.pd.FailNext("DeleteZone", pdns.ErrUnavailable)
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "comp2.test", Kind: "native"}); err == nil {
		t.Fatal("expected failure")
	}
	// a racing insert of the same name elsewhere maps to duplicate (the global unique index)
	_ = h.st.CreateZone(ctx, store.Zone{ID: "other", TenantID: tenantB, Name: "race.test.", PDNSID: "zzz"})
	h.pd2Conflict(t)
}

// pd2Conflict: a local unique-index conflict after the PowerDNS create is a
// duplicate, and the PowerDNS zone is removed again.
func (h *harness) pd2Conflict(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	// bypass the overlap check by using a store that reports no conflict
	svc := New(Deps{Store: noConflict{h.st}, PDNS: h.pd, Recursor: h.rec})
	if _, err := svc.Create(ctx, h.subA, CreateInput{Name: "race.test", Kind: "native"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("race = %v", err)
	}
	if _, err := h.pd.GetZone(ctx, "race.test."); !errors.Is(err, pdns.ErrNotFound) {
		t.Fatal("not compensated")
	}
}

type noConflict struct{ *memstore.Mem }

func (noConflict) ZoneConflict(context.Context, string, string) (bool, error) { return false, nil }

func TestCreatePowerDNSFailures(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.pd.SetDown(true)
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "down.test", Kind: "native"}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("down = %v", err)
	}
	if _, err := h.st.GetZoneByName(ctx, tenantA, "down.test."); !errors.Is(err, repo.ErrNotFound) {
		t.Fatal("local row written while PowerDNS is down")
	}
	h.pd.SetDown(false)
	h.pd.FailNext("CreateZone", fmt.Errorf("%w", pdns.ErrConflict))
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "c.test", Kind: "native"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("conflict = %v", err)
	}
	h.pd.FailNext("CreateZone", &pdns.APIError{Status: http.StatusUnprocessableEntity, Message: "bad"})
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "r.test", Kind: "native"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("rejected = %v", err)
	}
	h.pd.FailNext("GetZone", errors.New("boom"))
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "g.test", Kind: "native"}); err == nil {
		t.Fatal("existence check failure ignored")
	}
	h.st.FailNext("ZoneConflict")
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "g.test", Kind: "native"}); err == nil {
		t.Fatal("conflict check failure ignored")
	}
	h.st.FailNext("GetZoneByName")
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "g.test", Kind: "native"}); err == nil {
		t.Fatal("same-tenant check failure ignored")
	}
	// recursor failure is logged, not fatal
	h.rec.FailNext("SyncForward", recursor.ErrUnavailable)
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "rec.test", Kind: "native"}); err != nil {
		t.Fatalf("recursor failure was fatal: %v", err)
	}
}

func TestCreateWithTemplateAndIPAMOrigin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	exp := &fakeExpander{rrsets: []pdns.RRset{{Name: "www.tpl.test.", Type: "A", TTL: 300, Records: []pdns.Record{{Content: "192.0.2.1"}}}}}
	svc := New(Deps{Store: h.st, PDNS: h.pd, Templates: exp})
	z, err := svc.Create(ctx, h.subA, CreateInput{Name: "tpl.test", Kind: "native", TemplateID: "tpl-1"})
	if err != nil || z.TemplateID != "tpl-1" || exp.zone != "tpl.test." || exp.tenant != tenantA {
		t.Fatalf("template create = %+v %v (%+v)", z, err, exp)
	}
	pz, _ := h.pd.GetZone(ctx, "tpl.test.")
	found := false
	for _, r := range pz.RRsets {
		found = found || (r.Name == "www.tpl.test." && r.Type == "A")
	}
	if !found {
		t.Fatalf("template rrsets not created: %+v", pz.RRsets)
	}
	exp.err = ErrTemplateNotFound
	if _, err := svc.Create(ctx, h.subA, CreateInput{Name: "tpl2.test", Kind: "native", TemplateID: "gone"}); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("missing template = %v", err)
	}
	// IPAM sync creates origin=ipam zones as "ipam-sync"
	z, err = h.svc.Create(ctx, authz.SystemFor(tenantA), CreateInput{Name: "auto.test", Kind: "native", Origin: store.OriginIPAM})
	if err != nil || z.Origin != store.OriginIPAM || z.CreatedBy != authz.IPAMSyncActorID {
		t.Fatalf("ipam zone = %+v %v", z, err)
	}
	// a user cannot claim the ipam origin
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "fake.test", Kind: "native", Origin: store.OriginIPAM}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("user ipam origin = %v", err)
	}
}

// T061: templates apply to primaries only; a template's apex NS set is
// merged with the requested nameservers (PowerDNS refuses both at once).
func TestCreateFromTemplateRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	exp := &fakeExpander{rrsets: []pdns.RRset{
		{Name: "ns.test.", Type: "NS", TTL: 3600, ChangeType: pdns.ChangeReplace, Records: []pdns.Record{{Content: "ns1.ns.test."}, {Content: "ns2.ns.test."}}},
		{Name: "ns.test.", Type: "MX", TTL: 3600, ChangeType: pdns.ChangeReplace, Records: []pdns.Record{{Content: "10 mail.ns.test."}}},
	}}
	svc := New(Deps{Store: h.st, PDNS: h.pd, Templates: exp})
	if _, err := svc.Create(ctx, h.subA, CreateInput{Name: "sec.test", Kind: "slave", Masters: []string{"192.0.2.53"}, TemplateID: "t"}); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("template on a secondary = %v", err)
	}
	if exp.zone != "" {
		t.Fatal("expander called for a secondary")
	}
	z, err := svc.Create(ctx, h.subA, CreateInput{Name: "ns.test", Kind: "master", Nameservers: []string{"ns2.ns.test.", "ns3.ns.test."}, TemplateID: "t"})
	if err != nil || strings.Join(z.Nameservers, ",") != "ns2.ns.test.,ns3.ns.test." {
		t.Fatalf("create = %+v %v", z, err)
	}
	pz, _ := h.pd.GetZone(ctx, "ns.test.")
	var ns []string
	for _, r := range pz.RRsets {
		if r.Name == "ns.test." && r.Type == "NS" {
			for _, v := range r.Records {
				ns = append(ns, v.Content)
			}
		}
	}
	if strings.Join(ns, ",") != "ns1.ns.test.,ns2.ns.test.,ns3.ns.test." {
		t.Fatalf("apex NS = %v", ns)
	}
	// a template refused for the real zone is refused before PowerDNS
	exp.err = &validate.RecordError{Field: "records[0].name", Msg: "too long"}
	before := len(h.pd.CallLog())
	if _, err := svc.Create(ctx, h.subA, CreateInput{Name: "bad.test", Kind: "native", TemplateID: "t"}); err == nil {
		t.Fatal("invalid expansion accepted")
	}
	if len(h.pd.CallLog()) != before {
		t.Fatal("PowerDNS called for an invalid template expansion")
	}
}

// T063: export (BIND text, size-capped) and NOTIFY (master/producer only),
// both after the ownership check.
func TestExportAndNotify(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	z := h.create(t, h.subA, "exp.test.")
	ex, err := h.svc.Export(ctx, h.subA, z.ID)
	if err != nil || ex.Zone != "exp.test." || !strings.HasPrefix(ex.Text, "exp.test.\t3600\tIN\tSOA") || !strings.Contains(ex.Text, "\tNS\tns1.exp.test.") {
		t.Fatalf("export = %+v %v", ex, err)
	}
	if h.aud.last().EventType != audit.ZoneExport || h.aud.last().Outcome != audit.OutcomeOK {
		t.Fatalf("audit = %+v", h.aud.last())
	}
	if _, err := h.svc.Export(ctx, h.subB, z.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant export = %v", err)
	}
	small := New(Deps{Store: h.st, PDNS: h.pd, MaxExportBytes: 10, Audit: h.aud})
	if _, err := small.Export(ctx, h.subA, z.ID); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("size cap = %v", err)
	}
	h.pd.SetDown(true)
	if _, err := h.svc.Export(ctx, h.subA, z.ID); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("down export = %v", err)
	}
	h.pd.SetDown(false)

	// NOTIFY: native refused before PowerDNS, master accepted
	before := len(h.pd.CallLog())
	if err := h.svc.Notify(ctx, h.subA, z.ID); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("native notify = %v", err)
	}
	if len(h.pd.CallLog()) != before {
		t.Fatal("PowerDNS called for a native NOTIFY")
	}
	m, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "m.test", Kind: "master", Nameservers: []string{"ns1.m.test."}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Notify(ctx, h.subA, m.ID); err != nil {
		t.Fatalf("master notify = %v", err)
	}
	if h.aud.last().EventType != audit.ZoneNotify || h.aud.last().Outcome != audit.OutcomeOK {
		t.Fatalf("audit = %+v", h.aud.last())
	}
	if err := h.svc.Notify(ctx, h.subB, m.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant notify = %v", err)
	}
	h.pd.FailNext("NotifyZone", &pdns.APIError{Status: 422, Message: "nope"})
	if err := h.svc.Notify(ctx, h.subA, m.ID); !errors.Is(err, ErrRejected) {
		t.Fatalf("refused notify = %v", err)
	}
	// modules may not export or notify
	mod := authz.Module(tenantA, "spiffe://example.org/svc/x")
	if _, err := h.svc.Export(ctx, mod, z.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module export = %v", err)
	}
	if err := h.svc.Notify(ctx, mod, m.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module notify = %v", err)
	}
}

type fakeExpander struct {
	rrsets       []pdns.RRset
	err          error
	tenant, zone string
}

func (f *fakeExpander) Expand(_ context.Context, tenantID, _ string, zone string) ([]pdns.RRset, error) {
	f.tenant, f.zone = tenantID, zone
	return f.rrsets, f.err
}

func TestGetListAndOwnership(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.create(t, h.subA, "alpha.test.")
	h.create(t, h.subA, "beta.test.")
	if _, err := h.svc.Create(ctx, h.subA, CreateInput{Name: "gamma.test", Kind: "master"}); err != nil {
		t.Fatal(err)
	}
	h.create(t, h.subB, "other.test.")
	_ = h.pd.PatchRRsets(ctx, "alpha.test.", []pdns.RRset{{Name: "x.alpha.test.", Type: "A", TTL: 60, ChangeType: pdns.ChangeReplace, Records: []pdns.Record{{Content: "192.0.2.1"}}}})

	d, err := h.svc.Get(ctx, h.subA, a.ID)
	if err != nil || d.Serial == nil || *d.Serial != 2 || d.NotifiedSerial == nil || d.Name != "alpha.test." {
		t.Fatalf("detail = %+v %v", d, err)
	}
	if _, err := h.svc.Get(ctx, h.subB, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
	// PowerDNS down: the detail still answers, without serial
	h.pd.SetDown(true)
	d, err = h.svc.Get(ctx, h.subA, a.ID)
	if err != nil || d.Serial != nil {
		t.Fatalf("degraded detail = %+v %v", d, err)
	}
	h.pd.SetDown(false)

	items, total, err := h.svc.List(ctx, h.subA, store.ZoneFilter{})
	if err != nil || total != 3 || len(items) != 3 || items[0].Name != "alpha.test." {
		t.Fatalf("list = %+v %d %v", items, total, err)
	}
	items, total, _ = h.svc.List(ctx, h.subA, store.ZoneFilter{Query: "ET", PageSize: 1})
	if total != 1 || items[0].Name != "beta.test." {
		t.Fatalf("query = %+v %d", items, total)
	}
	items, total, _ = h.svc.List(ctx, h.subA, store.ZoneFilter{Kind: store.KindMaster})
	if total != 1 || items[0].Name != "gamma.test." {
		t.Fatalf("kind = %+v %d", items, total)
	}
	items, total, _ = h.svc.List(ctx, h.subA, store.ZoneFilter{Page: 2, PageSize: 2})
	if total != 3 || len(items) != 1 {
		t.Fatalf("paging = %+v %d", items, total)
	}
	h.st.FailNext("ListZones")
	if _, _, err := h.svc.List(ctx, h.subA, store.ZoneFilter{}); err == nil {
		t.Fatal("list error swallowed")
	}
	if _, _, err := h.svc.List(ctx, authz.Subjects{}, store.ZoneFilter{}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatal("list without tenant")
	}
	// Owned / ByName / FindForName (module callers)
	mod := authz.Module(tenantA, "spiffe://example.org/svc/ipam")
	if z, err := h.svc.Owned(ctx, mod, a.ID); err != nil || z.ID != a.ID {
		t.Fatalf("owned = %v", err)
	}
	if z, err := h.svc.ByName(ctx, mod, "ALPHA.test"); err != nil || z.ID != a.ID {
		t.Fatalf("by name = %+v %v", z, err)
	}
	if _, err := h.svc.ByName(ctx, mod, "other.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("by name cross-tenant = %v", err)
	}
	if _, err := h.svc.ByName(ctx, mod, "bad..name"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("by bad name = %v", err)
	}
	if z, err := h.svc.FindForName(ctx, mod, "Host.X.Alpha.Test"); err != nil || z.ID != a.ID {
		t.Fatalf("find = %+v %v", z, err)
	}
	if _, err := h.svc.FindForName(ctx, mod, "host.other.test."); !errors.Is(err, ErrNotFound) {
		t.Fatalf("find cross-tenant = %v", err)
	}
	h.st.FailNext("ZonesForTenant")
	if _, err := h.svc.FindForName(ctx, mod, "alpha.test"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("find store error = %v", err)
	}
	h.st.FailNext("GetZone")
	if _, err := h.svc.Owned(ctx, mod, a.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("owned store error = %v", err)
	}
	if _, err := h.svc.Owned(ctx, authz.Module(tenantA, ""), a.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module without peer = %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestUpdate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	z := h.create(t, h.subA, "up.test.")
	u, err := h.svc.Update(ctx, h.subA, z.ID, UpdateInput{Kind: ptr("slave"), Masters: &[]string{"192.0.2.9"}, DNSSEC: ptr(true), Description: ptr("secondary")})
	if err != nil || u.Kind != store.KindSlave || len(u.Masters) != 1 || !u.DNSSEC || u.Description != "secondary" {
		t.Fatalf("update = %+v %v", u, err)
	}
	pz, _ := h.pd.GetZone(ctx, "up.test.")
	if pz.Kind != "Slave" || len(pz.Masters) != 1 || !pz.DNSSEC {
		t.Fatalf("pdns = %+v", pz)
	}
	if h.pub.Events[len(h.pub.Events)-1].Type != events.ZoneUpdated || h.aud.last().EventType != audit.ZoneUpdate {
		t.Fatal("update event/audit")
	}
	// description-only change does not touch PowerDNS
	before := len(h.pd.CallLog())
	if _, err := h.svc.Update(ctx, h.subA, z.ID, UpdateInput{Description: ptr("d2")}); err != nil {
		t.Fatal(err)
	}
	if len(h.pd.CallLog()) != before {
		t.Fatalf("PowerDNS called for a description change: %v", h.pd.CallLog()[before:])
	}
	// back to native clears masters
	u, err = h.svc.Update(ctx, h.subA, z.ID, UpdateInput{Kind: ptr("native")})
	if err != nil || len(u.Masters) != 0 || u.Masters == nil {
		t.Fatalf("to native = %+v %v", u, err)
	}
	// refusals
	for name, c := range map[string]struct {
		in   UpdateInput
		want error
	}{
		"bad kind":        {UpdateInput{Kind: ptr("x")}, ErrInvalidKind},
		"slave no master": {UpdateInput{Kind: ptr("slave")}, ErrInvalidKind},
		"masters native":  {UpdateInput{Masters: &[]string{"192.0.2.1"}}, validate.ErrMasters},
		"bad master":      {UpdateInput{Kind: ptr("slave"), Masters: &[]string{"0.0.0.0"}}, validate.ErrMasters},
		"long desc":       {UpdateInput{Description: ptr(strings.Repeat("x", 1001))}, ErrInvalid},
	} {
		if _, err := h.svc.Update(ctx, h.subA, z.ID, c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := h.svc.Update(ctx, h.subB, z.ID, UpdateInput{Description: ptr("x")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant update = %v", err)
	}
	// local failure re-PUTs the previous metadata
	h.st.FailNext("UpdateZone")
	if _, err := h.svc.Update(ctx, h.subA, z.ID, UpdateInput{Kind: ptr("master"), DNSSEC: ptr(false)}); err == nil {
		t.Fatal("expected failure")
	}
	calls := h.pd.CallLog()
	if calls[len(calls)-1] != "UpdateZoneMetadata up.test." || calls[len(calls)-2] != "UpdateZoneMetadata up.test." {
		t.Fatalf("calls = %v", calls)
	}
	pz, _ = h.pd.GetZone(ctx, "up.test.")
	if pz.Kind != "Native" || !pz.DNSSEC {
		t.Fatalf("previous metadata not restored: %+v", pz)
	}
	// PowerDNS down: nothing written locally
	h.pd.SetDown(true)
	if _, err := h.svc.Update(ctx, h.subA, z.ID, UpdateInput{Kind: ptr("master")}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("down = %v", err)
	}
	h.pd.SetDown(false)
	cur, _ := h.st.GetZone(ctx, tenantA, z.ID)
	if cur.Kind != store.KindNative {
		t.Fatalf("local row changed: %+v", cur)
	}
}

func TestDelete(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	z := h.create(t, h.subA, "del.test.")
	if err := h.svc.Delete(ctx, h.subB, z.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v", err)
	}
	if calls := h.pd.CallLog(); calls[len(calls)-1] == "DeleteZone del.test." {
		t.Fatal("PowerDNS called before the ownership check")
	}
	h.pd.SetDown(true)
	if err := h.svc.Delete(ctx, h.subA, z.ID); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("down delete = %v", err)
	}
	h.pd.SetDown(false)
	if _, err := h.st.GetZone(ctx, tenantA, z.ID); err != nil {
		t.Fatal("local row removed while PowerDNS was down")
	}
	if err := h.svc.Delete(ctx, h.subA, z.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.GetZone(ctx, tenantA, z.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatal("local row kept")
	}
	if _, ok := h.rec.Forwards()["del.test."]; ok {
		t.Fatal("forward kept")
	}
	if h.pub.Events[len(h.pub.Events)-1].Type != events.ZoneDeleted || h.aud.last().EventType != audit.ZoneDelete {
		t.Fatal("delete event/audit")
	}
	// PowerDNS no longer has the zone: the local row is still removed; recursor failure is not fatal
	z2 := h.create(t, h.subA, "gone.test.")
	_ = h.pd.DeleteZone(ctx, "gone.test.")
	h.rec.FailNext("RemoveForward", recursor.ErrUnavailable)
	if err := h.svc.Delete(ctx, h.subA, z2.ID); err != nil {
		t.Fatalf("delete of a zone missing in PowerDNS = %v", err)
	}
	// local failures surface
	z3 := h.create(t, h.subA, "fail.test.")
	h.st.FailNext("ClearSyncZone")
	if err := h.svc.Delete(ctx, h.subA, z3.ID); err == nil {
		t.Fatal("sync clear failure swallowed")
	}
	h.st.FailNext("DeleteZone")
	if err := h.svc.Delete(ctx, h.subA, z3.ID); err == nil {
		t.Fatal("local delete failure swallowed")
	}
	if err := h.svc.Delete(ctx, h.subA, z3.ID); err != nil {
		t.Fatalf("retry = %v", err)
	}
}

func TestCallMetricsAndResults(t *testing.T) {
	cases := map[string]error{
		"ok":          nil,
		"not_found":   pdns.ErrNotFound,
		"conflict":    pdns.ErrConflict,
		"unavailable": pdns.ErrUnavailable,
		"error":       errors.New("x"),
	}
	for want, err := range cases {
		if got := Result(err); got != want {
			t.Errorf("Result(%v) = %s", err, got)
		}
	}
	h := newHarness(t)
	if err := h.svc.Call("Op", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(mapPDNS(&pdns.APIError{Status: 400, Message: "x"}), ErrRejected) || !errors.Is(mapPDNS(pdns.ErrConflict), pdns.ErrConflict) {
		t.Fatal("mapPDNS")
	}
	if mapPDNS(nil) != nil {
		t.Fatal("mapPDNS(nil)")
	}
	// defaults: no events/audit/recursor/logger wired
	svc := New(Deps{Store: memstore.New(), PDNS: pdns.NewFake(), Now: func() time.Time { return time.Unix(1, 0) }, NewID: func() string { return "fixed" }})
	z, err := svc.Create(context.Background(), authz.Internal(tenantA), CreateInput{Name: "bare.test", Kind: "native"})
	if err != nil || z.ID != "fixed" || z.CreatedBy != authz.ActorSystem {
		t.Fatalf("bare = %+v %v", z, err)
	}
	if err := svc.Delete(context.Background(), authz.Internal(tenantA), z.ID); err != nil {
		t.Fatal(err)
	}
	// a Checker, when wired, is consulted for users too
	chk := New(Deps{Store: memstore.New(), PDNS: pdns.NewFake(), Checker: authz.Static{userA: {authz.ZonesRead}}})
	if _, _, err := chk.List(context.Background(), h.subA, store.ZoneFilter{}); err != nil {
		t.Fatalf("checker read = %v", err)
	}
	if _, err := chk.Create(context.Background(), h.subA, CreateInput{Name: "x.test", Kind: "native"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("checker manage = %v", err)
	}
}
