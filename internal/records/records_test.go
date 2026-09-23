package records

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
	userA   = "33333333-3333-7333-8333-333333333333"
)

type auditLog struct{ events []audit.Event }

func (a *auditLog) Record(_ context.Context, e audit.Event) error {
	if err := audit.Validate(e); err != nil {
		return err
	}
	a.events = append(a.events, e)
	return nil
}

type harness struct {
	svc  *Service
	zs   *zones.Service
	st   *memstore.Mem
	pd   *pdns.Fake
	pub  *events.Recorder
	aud  *auditLog
	subA authz.Subjects
	zone store.Zone
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	h := &harness{st: memstore.New(), pd: pdns.NewFake(), pub: &events.Recorder{}, aud: &auditLog{}, subA: authz.User(tenantA, userA, nil)}
	h.zs = zones.New(zones.Deps{Store: h.st, PDNS: h.pd})
	h.svc = New(Deps{Zones: h.zs, PDNS: h.pd, Events: h.pub, Audit: h.aud})
	z, err := h.zs.Create(context.Background(), h.subA, zones.CreateInput{Name: "example.test", Kind: "native", Nameservers: []string{"ns1.example.test."}})
	if err != nil {
		t.Fatal(err)
	}
	h.zone = z
	return h
}

func in(name, typ string, ttl int, values ...string) validate.RecordSetInput {
	r := validate.RecordSetInput{Name: name, Type: typ, TTL: ttl}
	for _, v := range values {
		r.Values = append(r.Values, validate.RecordValue{Content: v})
	}
	return r
}

func (h *harness) upsert(t *testing.T, r validate.RecordSetInput) RecordSet {
	t.Helper()
	out, err := h.svc.Upsert(context.Background(), h.subA, h.zone.ID, r)
	if err != nil {
		t.Fatalf("upsert %s %s: %v", r.Name, r.Type, err)
	}
	return out
}

func TestUpsertAndList(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	www := in("www", "A", 300, "192.0.2.10", "192.0.2.11")
	www.Values[1].Disabled = true
	www.Comment = "web"
	got := h.upsert(t, www)
	if got.Name != "www.example.test." || got.Type != "A" || got.TTL != 300 || len(got.Values) != 2 || !got.Values[1].Disabled ||
		got.Comment != "web" || got.ReadOnly {
		t.Fatalf("upsert = %+v", got)
	}
	h.upsert(t, in("www", "AAAA", 300, "2001:db8::10"))
	h.upsert(t, in("@", "MX", 3600, "10 mail.example.test."))
	h.upsert(t, in("@", "TXT", 3600, "v=spf1 -all"))
	h.upsert(t, in("@", "CAA", 3600, `0 issue "letsencrypt.org"`))
	h.upsert(t, in("mail", "A", 300, "192.0.2.25"))

	pz, _ := h.pd.GetZone(ctx, h.zone.PDNSID)
	for _, r := range pz.RRsets {
		if r.Name == "www.example.test." && r.Type == "A" && (len(r.Comments) != 1 || r.Comments[0].Content != "web") {
			t.Fatalf("comment not stored: %+v", r)
		}
	}
	last := h.pub.Events[len(h.pub.Events)-1]
	if p, ok := last.Payload.(events.RecordPayload); !ok || last.Type != events.RecordChanged || p.Action != events.ActionUpserted ||
		p.Source != events.SourceAPI || p.Name != "mail.example.test." || p.Type != "A" {
		t.Fatalf("event = %+v", last)
	}
	if e := h.aud.events[len(h.aud.events)-1]; e.EventType != audit.RecordUpsert || e.SubjectKind != audit.SubjectRecord || e.Outcome != audit.OutcomeOK {
		t.Fatalf("audit = %+v", e)
	}

	items, total, err := h.svc.List(ctx, h.subA, h.zone.ID, Filter{})
	if err != nil || total != 8 || len(items) != 8 {
		t.Fatalf("list = %d %d %v", len(items), total, err)
	}
	// canonical order: apex first (SOA leading), then children
	if items[0].Type != "SOA" || !items[0].ReadOnly || items[0].Name != "example.test." || items[len(items)-1].Name != "www.example.test." {
		t.Fatalf("order = %+v", items)
	}
	for _, r := range items[1:] {
		if r.ReadOnly {
			t.Fatalf("%s %s read-only", r.Name, r.Type)
		}
	}
	items, total, _ = h.svc.List(ctx, h.subA, h.zone.ID, Filter{Type: "a"})
	if total != 2 || items[0].Name != "mail.example.test." {
		t.Fatalf("type filter = %+v", items)
	}
	items, total, _ = h.svc.List(ctx, h.subA, h.zone.ID, Filter{Type: "A", Query: "WW"})
	if total != 1 || items[0].Name != "www.example.test." {
		t.Fatalf("search = %+v", items)
	}
	items, total, _ = h.svc.List(ctx, h.subA, h.zone.ID, Filter{Page: 2, PageSize: 3})
	if total != 8 || len(items) != 3 {
		t.Fatalf("page = %d %d", len(items), total)
	}
	items, total, _ = h.svc.List(ctx, h.subA, h.zone.ID, Filter{Page: 9, PageSize: 3})
	if total != 8 || len(items) != 0 || items == nil {
		t.Fatalf("past the end = %v %d", items, total)
	}
}

func TestOwnershipBeforePowerDNS(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	other := authz.User(tenantB, "someone", nil)
	before := len(h.pd.CallLog())
	if _, _, err := h.svc.List(ctx, other, h.zone.ID, Filter{}); !errors.Is(err, zones.ErrNotFound) {
		t.Fatalf("list = %v", err)
	}
	if _, err := h.svc.Upsert(ctx, other, h.zone.ID, in("x", "A", 300, "192.0.2.1")); !errors.Is(err, zones.ErrNotFound) {
		t.Fatalf("upsert = %v", err)
	}
	if _, err := h.svc.Update(ctx, other, h.zone.ID, Key{Name: "x", Type: "A"}, in("x", "A", 300, "192.0.2.1")); !errors.Is(err, zones.ErrNotFound) {
		t.Fatalf("update = %v", err)
	}
	if err := h.svc.Delete(ctx, other, h.zone.ID, Key{Name: "x", Type: "A"}); !errors.Is(err, zones.ErrNotFound) {
		t.Fatalf("delete = %v", err)
	}
	if after := h.pd.CallLog(); len(after) != before {
		t.Fatalf("PowerDNS called for a foreign zone: %v", after[before:])
	}
	// the stored PowerDNS id is used, never a name derived from input
	st := h.st
	cur, _ := st.GetZone(ctx, tenantA, h.zone.ID)
	h.pd.Seed(pdns.Zone{ID: "pdns-id-1", Name: "example.test.", Kind: "Native"})
	_ = st.DeleteZone(ctx, tenantA, cur.ID)
	cur.PDNSID = "pdns-id-1"
	_ = st.CreateZone(ctx, cur)
	h.upsert(t, in("y", "A", 300, "192.0.2.1"))
	calls := h.pd.CallLog()
	if calls[len(calls)-1] != "PatchRRsets pdns-id-1" || calls[len(calls)-2] != "GetZone pdns-id-1" {
		t.Fatalf("calls = %v", calls[len(calls)-2:])
	}
	// module actors may not write records
	mod := authz.Module(tenantA, "spiffe://example.org/svc/x")
	if _, err := h.svc.Upsert(ctx, mod, h.zone.ID, in("z", "A", 300, "192.0.2.1")); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module upsert = %v", err)
	}
}

func TestValidationBeforePowerDNS(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.upsert(t, in("www", "A", 300, "192.0.2.1"))
	h.upsert(t, in("alias", "CNAME", 300, "www.example.test."))
	cases := []struct {
		name string
		in   validate.RecordSetInput
		want error
	}{
		{"bad A", in("x", "A", 300, "999.1.1.1"), validate.ErrRecord},
		{"mx without priority", in("@", "MX", 300, "mail.example.test."), validate.ErrRecord},
		{"apex cname", in("@", "CNAME", 300, "x.example.net."), validate.ErrRecord},
		{"cname next to a", in("www", "CNAME", 300, "x.example.net."), validate.ErrRecord},
		{"a next to cname", in("alias", "A", 300, "192.0.2.1"), validate.ErrRecord},
		{"outside zone", in("foo.other.test.", "A", 300, "192.0.2.1"), validate.ErrName},
		{"soa", in("@", "SOA", 300, "x"), validate.ErrRecord},
	}
	for _, c := range cases {
		before := h.pd.CallLog()
		if _, err := h.svc.Upsert(ctx, h.subA, h.zone.ID, c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		for _, call := range h.pd.CallLog()[len(before):] {
			if strings.HasPrefix(call, "PatchRRsets") {
				t.Errorf("%s: PowerDNS patched", c.name)
			}
		}
	}
	refused := 0
	for _, e := range h.aud.events {
		if e.EventType == audit.RecordUpsert && e.Outcome == audit.OutcomeRefused {
			refused++
		}
	}
	if refused != len(cases) {
		t.Fatalf("refusals audited = %d", refused)
	}
}

// Lookup reads one record set of an already-loaded zone (IPAM sync merges).
func TestLookup(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.upsert(t, in("www", "A", 300, "192.0.2.1", "192.0.2.2"))
	got, err := h.svc.Lookup(ctx, authz.SystemFor(tenantA), h.zone, Key{Name: "www", Type: "a"})
	if err != nil || got.Name != "www.example.test." || got.Type != "A" || len(got.Values) != 2 {
		t.Fatalf("lookup = %+v %v", got, err)
	}
	if _, err := h.svc.Lookup(ctx, h.subA, h.zone, Key{Name: "nope", Type: "A"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent = %v", err)
	}
	if _, err := h.svc.Lookup(ctx, h.subA, h.zone, Key{Name: "www.other.test.", Type: "A"}); err == nil {
		t.Fatal("out-of-zone name accepted")
	}
	if _, err := h.svc.Lookup(ctx, authz.Module(tenantA, ""), h.zone, Key{Name: "www", Type: "A"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module without identity = %v", err)
	}
	h.pd.SetDown(true)
	if _, err := h.svc.Lookup(ctx, h.subA, h.zone, Key{Name: "www", Type: "A"}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("down = %v", err)
	}
}

// US1 gap: an empty comment on update clears an existing PowerDNS comment.
func TestUpdateClearsComment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	c := in("www", "A", 300, "192.0.2.1")
	c.Comment = "web tier"
	if got := h.upsert(t, c); got.Comment != "web tier" {
		t.Fatalf("comment not stored: %+v", got)
	}
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "www", Type: "A"}, in("www", "A", 300, "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	items, _, err := h.svc.List(ctx, h.subA, h.zone.ID, Filter{Type: "A"})
	if err != nil || len(items) != 1 || items[0].Comment != "" {
		t.Fatalf("comment not cleared: %+v %v", items, err)
	}
}

func TestUpdateRenameAndDelete(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.upsert(t, in("www", "A", 300, "192.0.2.1"))
	h.upsert(t, in("api", "A", 300, "192.0.2.3"))
	// edit in place: two values, one disabled
	e := in("www", "A", 600, "192.0.2.1", "192.0.2.2")
	e.Values[0].Disabled = true
	got, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "www", Type: "A"}, e)
	if err != nil || got.TTL != 600 || len(got.Values) != 2 || !got.Values[0].Disabled {
		t.Fatalf("edit = %+v %v", got, err)
	}
	// rename = one PATCH with REPLACE new + DELETE old
	before := len(h.pd.CallLog())
	got, err = h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "www.example.test.", Type: "a"}, in("web", "A", 600, "192.0.2.1"))
	if err != nil || got.Name != "web.example.test." {
		t.Fatalf("rename = %+v %v", got, err)
	}
	patches := 0
	for _, c := range h.pd.CallLog()[before:] {
		if strings.HasPrefix(c, "PatchRRsets") {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("rename used %d patches", patches)
	}
	items, _, _ := h.svc.List(ctx, h.subA, h.zone.ID, Filter{Query: "www"})
	if len(items) != 0 {
		t.Fatalf("old name kept: %+v", items)
	}
	n := len(h.pub.Events)
	if h.pub.Events[n-1].Payload.(events.RecordPayload).Action != events.ActionDeleted ||
		h.pub.Events[n-2].Payload.(events.RecordPayload).Action != events.ActionUpserted {
		t.Fatalf("rename events = %+v", h.pub.Events[n-2:])
	}
	// type change within the same name and CNAME exclusivity ignore the original
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "web", Type: "A"}, in("web", "CNAME", 300, "api.example.test.")); err != nil {
		t.Fatalf("A -> CNAME = %v", err)
	}
	// refusals
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "nope", Type: "A"}, in("nope", "A", 300, "192.0.2.1")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing original = %v", err)
	}
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "web", Type: "CNAME"}, in("api", "A", 300, "192.0.2.9")); !errors.Is(err, ErrConflict) {
		t.Fatalf("rename onto an existing set = %v", err)
	}
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "@", Type: "SOA"}, in("@", "A", 300, "192.0.2.9")); !errors.Is(err, validate.ErrRecord) {
		t.Fatalf("SOA original = %v", err)
	}
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "x.other.", Type: "A"}, in("x", "A", 300, "192.0.2.9")); !errors.Is(err, validate.ErrName) {
		t.Fatalf("original outside = %v", err)
	}
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "api", Type: "A"}, in("api", "A", 300, "bad")); !errors.Is(err, validate.ErrRecord) {
		t.Fatalf("bad content = %v", err)
	}
	// delete
	if err := h.svc.Delete(ctx, h.subA, h.zone.ID, Key{Name: "API", Type: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Delete(ctx, h.subA, h.zone.ID, Key{Name: "api", Type: "A"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
	if err := h.svc.Delete(ctx, h.subA, h.zone.ID, Key{Name: "@", Type: "SOA"}); !errors.Is(err, validate.ErrRecord) {
		t.Fatalf("SOA delete = %v", err)
	}
	if err := h.svc.Delete(ctx, h.subA, h.zone.ID, Key{Name: "a..b", Type: "A"}); !errors.Is(err, validate.ErrName) {
		t.Fatalf("bad name delete = %v", err)
	}
	if ev := h.aud.events[len(h.aud.events)-1]; ev.EventType != audit.RecordDelete {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestPowerDNSFailuresAndKinds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.upsert(t, in("www", "A", 300, "192.0.2.1"))
	h.pd.SetDown(true)
	if _, _, err := h.svc.List(ctx, h.subA, h.zone.ID, Filter{}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("list down = %v", err)
	}
	if _, err := h.svc.Upsert(ctx, h.subA, h.zone.ID, in("x", "A", 300, "192.0.2.1")); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("upsert down = %v", err)
	}
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "www", Type: "A"}, in("www", "A", 300, "192.0.2.1")); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("update down = %v", err)
	}
	if err := h.svc.Delete(ctx, h.subA, h.zone.ID, Key{Name: "www", Type: "A"}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("delete down = %v", err)
	}
	h.pd.SetDown(false)
	h.pd.FailNext("PatchRRsets", &pdns.APIError{Status: 422, Message: "nope"})
	if _, err := h.svc.Upsert(ctx, h.subA, h.zone.ID, in("x", "A", 300, "192.0.2.1")); !errors.Is(err, zones.ErrRejected) {
		t.Fatalf("rejected = %v", err)
	}
	h.pd.FailNext("PatchRRsets", pdns.ErrUnavailable)
	if _, err := h.svc.Update(ctx, h.subA, h.zone.ID, Key{Name: "www", Type: "A"}, in("www", "A", 300, "192.0.2.2")); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("update patch = %v", err)
	}
	h.pd.FailNext("PatchRRsets", pdns.ErrUnavailable)
	if err := h.svc.Delete(ctx, h.subA, h.zone.ID, Key{Name: "www", Type: "A"}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("delete patch = %v", err)
	}
	// secondaries take their data from the primary: writes are refused
	sec, err := h.zs.Create(ctx, h.subA, zones.CreateInput{Name: "sec.test", Kind: "slave", Masters: []string{"192.0.2.53"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Upsert(ctx, h.subA, sec.ID, in("x", "A", 300, "192.0.2.1")); !errors.Is(err, zones.ErrInvalidKind) {
		t.Fatalf("slave write = %v", err)
	}
	if _, err := h.svc.Update(ctx, h.subA, sec.ID, Key{Name: "x", Type: "A"}, in("x", "A", 300, "192.0.2.1")); !errors.Is(err, zones.ErrInvalidKind) {
		t.Fatalf("slave update = %v", err)
	}
	if err := h.svc.Delete(ctx, h.subA, sec.ID, Key{Name: "x", Type: "A"}); !errors.Is(err, zones.ErrInvalidKind) {
		t.Fatalf("slave delete = %v", err)
	}
	// reads are allowed for the module view; the IPAM sync writes with source ipam
	if _, _, err := h.svc.List(ctx, authz.Module(tenantA, "spiffe://example.org/svc/x"), h.zone.ID, Filter{}); err != nil {
		t.Fatalf("module list = %v", err)
	}
	z, _ := h.zs.Owned(ctx, h.subA, h.zone.ID)
	if _, err := h.svc.Apply(ctx, authz.SystemFor(tenantA), z, in("srv1", "A", 3600, "10.20.30.40"), events.SourceIPAM); err != nil {
		t.Fatalf("apply = %v", err)
	}
	if p := h.pub.Events[len(h.pub.Events)-1].Payload.(events.RecordPayload); p.Source != events.SourceIPAM {
		t.Fatalf("source = %+v", p)
	}
	if err := h.svc.Remove(ctx, authz.SystemFor(tenantA), z, Key{Name: "srv1", Type: "A"}, events.SourceIPAM); err != nil {
		t.Fatalf("remove = %v", err)
	}
	if err := h.svc.Remove(ctx, authz.SystemFor(tenantA), z, Key{Name: "srv1", Type: "A"}, events.SourceIPAM); err != nil {
		t.Fatalf("idempotent remove = %v", err)
	}
	if _, err := h.svc.Apply(ctx, authz.Module(tenantA, "spiffe://x"), z, in("m", "A", 3600, "10.0.0.1"), events.SourceIPAM); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module apply = %v", err)
	}
	if err := h.svc.Remove(ctx, authz.Module(tenantA, "spiffe://x"), z, Key{Name: "m", Type: "A"}, events.SourceIPAM); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module remove = %v", err)
	}
	if err := h.svc.Remove(ctx, authz.SystemFor(tenantA), z, Key{Name: "m", Type: "SOA"}, events.SourceIPAM); !errors.Is(err, validate.ErrRecord) {
		t.Fatalf("remove SOA = %v", err)
	}
	h.pd.SetDown(true)
	if err := h.svc.Remove(ctx, authz.SystemFor(tenantA), z, Key{Name: "m", Type: "A"}, events.SourceIPAM); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("remove down = %v", err)
	}
}

func TestSort(t *testing.T) {
	names := []RecordSet{{Name: "b.example.test.", Type: "A"}, {Name: "example.test.", Type: "NS"}, {Name: "a.b.example.test.", Type: "A"},
		{Name: "example.test.", Type: "SOA"}, {Name: "example.test.", Type: "A"}, {Name: "a.example.test.", Type: "TXT"}, {Name: "a.example.test.", Type: "A"}}
	sortSets(names)
	got := []string{}
	for _, r := range names {
		got = append(got, r.Type+" "+r.Name)
	}
	want := "SOA example.test.,A example.test.,NS example.test.,A a.example.test.,TXT a.example.test.,A b.example.test.,A a.b.example.test."
	if strings.Join(got, ",") != want {
		t.Fatalf("order = %v", got)
	}
}

// SC-008: listing/searching a 5,000-rrset zone stays well under 3 s.
func TestListLargeZoneBudget(t *testing.T) {
	h, id := bigZone(t)
	start := time.Now()
	items, total, err := h.svc.List(context.Background(), h.subA, id, Filter{Query: "host0499", Type: "A"})
	if err != nil || total != 10 || len(items) != 10 {
		t.Fatalf("list = %d %d %v", len(items), total, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("5,000-rrset list took %v", d)
	}
}

func bigZone(t testing.TB) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	z := pdns.GenerateZone("big.test.", 5000)
	h.pd.Seed(z)
	if err := h.st.CreateZone(context.Background(), store.Zone{ID: "big", TenantID: tenantA, Name: "big.test.", PDNSID: z.ID, Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	return h, "big"
}

func BenchmarkList5000(b *testing.B) {
	h, id := bigZone(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := h.svc.List(ctx, h.subA, id, Filter{Query: "host01", PageSize: 500}); err != nil {
			b.Fatal(err)
		}
	}
}
