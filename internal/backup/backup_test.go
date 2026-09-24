package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
)

const (
	tA   = "11111111-1111-4111-8111-111111111111"
	tB   = "22222222-2222-4222-8222-222222222222"
	tC   = "33333333-3333-4333-8333-333333333333"
	zID  = "0190aaaa-0000-7000-8000-000000000001"
	z2ID = "0190aaaa-0000-7000-8000-000000000002"
	tpID = "0190aaaa-0000-7000-8000-000000000010"
	smID = "0190aaaa-0000-7000-8000-000000000020"
	key  = "SENTINEL-API-KEY-backup"
)

type auditLog struct {
	mu sync.Mutex
	ev []audit.Event
}

func (a *auditLog) Record(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ev = append(a.ev, e)
	return nil
}

func (a *auditLog) last() audit.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ev[len(a.ev)-1]
}

type fixture struct {
	st  *memstore.Mem
	pd  *pdns.Fake
	aud *auditLog
	svc *Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{st: memstore.New(), pd: pdns.NewFake(), aud: &auditLog{}}
	n := 0
	f.svc = New(Deps{Store: f.st, PDNS: f.pd, Audit: f.aud, Now: func() time.Time { return time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC) },
		NewID: func() string {
			n++
			return "0190bbbb-0000-7000-8000-" + strings.Repeat("0", 11) + string(rune('a'+n%26))
		}})
	return f
}

func admin(tenant string) authz.Subjects {
	return authz.User(tenant, "u-admin", []string{authz.RolePlatformAdmin})
}
func user(tenant string) authz.Subjects { return authz.User(tenant, "u-1", nil) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// seed: tenant A owns example.org. (in PowerDNS, account A), a template and a supermaster.
func (f *fixture) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	f.pd.Seed(pdns.Zone{Name: "example.org.", Kind: "Master", Account: tA, RRsets: []pdns.RRset{
		{Name: "example.org.", Type: "SOA", TTL: 3600, Records: []pdns.Record{{Content: "ns1.example.org. hostmaster.example.org. 1 10800 3600 604800 3600"}}},
		{Name: "www.example.org.", Type: "A", TTL: 300, Records: []pdns.Record{{Content: "192.0.2.10"}}}}})
	must(t, f.st.CreateZone(ctx, store.Zone{ID: zID, TenantID: tA, Name: "example.org.", PDNSID: "example.org.", Kind: store.KindMaster,
		Masters: []string{}, Origin: store.OriginManual, Nameservers: []string{"ns1.example.org."}, Description: "main", TemplateID: tpID}))
	must(t, f.st.CreateTemplate(ctx, store.Template{ID: tpID, TenantID: tA, Name: "web", Records: []store.TemplateRecord{
		{Name: "www", Type: "A", TTL: 300, Content: "192.0.2.1"}}}))
	must(t, f.pd.CreateSupermaster(ctx, pdns.Supermaster{IP: "192.0.2.53", Nameserver: "ns.primary.example", Account: tA}))
	must(t, f.st.CreateSupermaster(ctx, store.Supermaster{ID: smID, TenantID: tA, IP: "192.0.2.53", Nameserver: "ns.primary.example."}))
}

func TestExport(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	b, err := f.svc.Export(context.Background(), user(tA), "")
	must(t, err)
	if b.SchemaVersion != SchemaVersion || b.TenantID != tA || len(b.Zones) != 1 || len(b.Templates) != 1 || len(b.Supermasters) != 1 {
		t.Fatalf("export = %+v", b)
	}
	if !strings.Contains(b.Zones[0].Bind, "www.example.org.") {
		t.Fatalf("bind text missing: %q", b.Zones[0].Bind)
	}
	raw, _ := json.Marshal(b)
	for _, bad := range []string{"pdns_id", "api_key", key, "PDNSID"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("export carries %q", bad)
		}
	}
	if e := f.aud.last(); e.EventType != audit.BackupExport || e.Outcome != audit.OutcomeOK {
		t.Fatalf("audit = %+v", e)
	}
	// the document round-trips through Parse
	if _, err := Parse(raw, validate.Limits{}); err != nil {
		t.Fatalf("parse own export: %v", err)
	}
}

func TestExportWithoutText(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	f.pd.SetDown(true)
	b, err := f.svc.Export(context.Background(), user(tA), "")
	must(t, err)
	if b.Zones[0].Bind != "" {
		t.Fatal("bind text while PowerDNS is down")
	}
}

func TestExportAuthorization(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()
	if _, err := f.svc.Export(ctx, user(tB), tA); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("cross-tenant export by non-admin: %v", err)
	}
	if e := f.aud.last(); e.Outcome != audit.OutcomeRefused {
		t.Fatalf("refusal not audited: %+v", e)
	}
	if _, err := f.svc.Export(ctx, authz.Module(tA, "spiffe://example.org/svc/lcm"), ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module export: %v", err)
	}
	if _, err := f.svc.Export(ctx, authz.Subjects{ActorKind: authz.ActorUser}, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("tenantless export: %v", err)
	}
	if _, err := f.svc.Export(ctx, admin(tB), "not-a-uuid"); !errors.Is(err, ErrBadSchema) {
		t.Fatalf("bad tenant id: %v", err)
	}
	b, err := f.svc.Export(ctx, admin(tB), tA)
	must(t, err)
	if len(b.Zones) != 1 {
		t.Fatal("platform admin cross-tenant export empty")
	}
	// a wired checker is consulted
	chk := New(Deps{Store: f.st, PDNS: f.pd, Checker: authz.Static{"u-1": {authz.ZonesRead}}})
	if _, err := chk.Export(ctx, user(tA), ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("checker ignored: %v", err)
	}
	chk = New(Deps{Store: f.st, PDNS: f.pd, Checker: authz.Static{"u-1": {authz.BackupManage}}})
	if _, err := chk.Export(ctx, user(tA), ""); err != nil {
		t.Fatal(err)
	}
}

func TestExportStoreErrors(t *testing.T) {
	for _, m := range []string{"ZonesForTenant", "AllTemplates", "AllSupermasters"} {
		f := newFixture(t)
		f.seed(t)
		f.st.FailNext(m)
		if _, err := f.svc.Export(context.Background(), user(tA), ""); err == nil {
			t.Fatalf("%s failure swallowed", m)
		}
	}
}

func exported(t *testing.T, f *fixture) Backup {
	t.Helper()
	b, err := f.svc.Export(context.Background(), user(tA), "")
	must(t, err)
	return b
}

func TestImportSameTenantSkipAndOverwrite(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()
	b := exported(t, f)
	b.Zones[0].Description = "changed"
	b.Templates[0].Name = "web2"
	res, err := f.svc.Import(ctx, user(tA), b, Options{})
	must(t, err)
	if res.Mode != ModeSkip || res.Skipped[CZones] != 1 || res.Skipped[CTemplates] != 1 || res.Skipped[CSupermasters] != 1 {
		t.Fatalf("skip result = %+v", res)
	}
	res, err = f.svc.Import(ctx, user(tA), b, Options{Mode: ModeOverwrite})
	must(t, err)
	if res.Imported[CZones] != 1 || res.Imported[CTemplates] != 1 {
		t.Fatalf("overwrite result = %+v", res)
	}
	z, _ := f.st.GetZone(ctx, tA, zID)
	tp, _ := f.st.GetTemplate(ctx, tA, tpID)
	if z.Description != "changed" || tp.Name != "web2" {
		t.Fatalf("overwrite not applied: %q %q", z.Description, tp.Name)
	}
	if e := f.aud.last(); e.EventType != audit.BackupImport || e.Outcome != audit.OutcomeOK {
		t.Fatalf("audit = %+v", e)
	}
}

func TestImportRelinksAndReportsMissing(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()
	b := exported(t, f)
	// disaster: the local rows are gone, PowerDNS still has the zone
	must(t, f.st.DeleteZone(ctx, tA, zID))
	must(t, f.st.DeleteTemplate(ctx, tA, tpID))
	b.Zones = append(b.Zones, ZoneRow{Zone: store.Zone{ID: z2ID, Name: "gone.example.", Kind: store.KindNative}})
	res, err := f.svc.Import(ctx, user(tA), b, Options{})
	must(t, err)
	if res.Imported[CZones] != 1 || res.Imported[CTemplates] != 1 || len(res.MissingInPDNS) != 1 || res.MissingInPDNS[0] != "gone.example." {
		t.Fatalf("result = %+v", res)
	}
	z, err := f.st.GetZone(ctx, tA, zID)
	must(t, err)
	if z.PDNSID != "example.org." || z.Kind != store.KindMaster || z.TemplateID != tpID {
		t.Fatalf("relinked zone = %+v", z)
	}
	// non-admin: supermasters skipped, never written to PowerDNS
	if res.Skipped[CSupermasters] != 1 {
		t.Fatalf("supermasters for non-admin = %+v", res)
	}
}

func TestImportPinnedToCallerTenant(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()
	b := exported(t, f)
	for _, o := range []Options{{TenantID: tA}, {Full: true}} {
		if _, err := f.svc.Import(ctx, user(tB), b, o); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("non-admin %+v: %v", o, err)
		}
	}
	// a non-admin import of A's document lands in B only: A's zone is owned elsewhere
	res, err := f.svc.Import(ctx, user(tB), b, Options{})
	must(t, err)
	if res.TenantID != tB || res.Imported[CZones] != 0 || res.Skipped[CZones] != 1 || res.Imported[CTemplates] != 1 {
		t.Fatalf("result = %+v", res)
	}
	zs, _ := f.st.ZonesForTenant(ctx, tB)
	if len(zs) != 0 {
		t.Fatal("another tenant's zone was adopted")
	}
	tps, _ := f.st.AllTemplates(ctx, tB)
	if len(tps) != 1 || tps[0].ID == tpID {
		t.Fatalf("cross-tenant template ids not remapped: %+v", tps)
	}
}

func TestImportForeignAccountSkipped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// PowerDNS has a zone accounted to tenant C and no local owner
	f.pd.Seed(pdns.Zone{Name: "foreign.example.", Kind: "Native", Account: tC})
	f.pd.Seed(pdns.Zone{Name: "free.example.", Kind: "Native"})
	b := Backup{SchemaVersion: SchemaVersion, TenantID: tA, Zones: []ZoneRow{
		{Zone: store.Zone{ID: zID, Name: "foreign.example.", Kind: store.KindNative}},
		{Zone: store.Zone{ID: z2ID, Name: "free.example.", Kind: store.KindNative}}}}
	res, err := f.svc.Import(ctx, user(tA), b, Options{})
	must(t, err)
	if res.Imported[CZones] != 1 || res.Skipped[CZones] != 1 {
		t.Fatalf("result = %+v", res)
	}
	live, _ := f.pd.GetZone(ctx, "free.example.")
	if live.Account != tA {
		t.Fatalf("account not claimed: %q", live.Account)
	}
}

func TestImportFullAndCrossTenantAdmin(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()
	b := exported(t, f)
	must(t, f.st.CreateTemplate(ctx, store.Template{ID: "0190cccc-0000-7000-8000-000000000001", TenantID: tB, Name: "old", Records: []store.TemplateRecord{}}))
	// the origin's rows vanish; a platform admin restores A's document into B
	must(t, f.st.DeleteZone(ctx, tA, zID))
	must(t, f.st.DeleteSupermaster(ctx, tA, smID))
	res, err := f.svc.Import(ctx, admin(tA), b, Options{TenantID: tB, Full: true})
	must(t, err)
	if res.TenantID != tB || res.Imported[CZones] != 1 || res.Imported[CTemplates] != 1 || res.Imported[CSupermasters] != 1 {
		t.Fatalf("result = %+v", res)
	}
	tps, _ := f.st.AllTemplates(ctx, tB)
	if len(tps) != 1 || tps[0].Name != "web" {
		t.Fatalf("full restore did not wipe templates: %+v", tps)
	}
	zs, _ := f.st.ZonesForTenant(ctx, tB)
	if len(zs) != 1 || zs[0].ID == zID || zs[0].TemplateID != tps[0].ID {
		t.Fatalf("zone not remapped: %+v", zs)
	}
	live, _ := f.pd.GetZone(ctx, "example.org.")
	if live.Account != tB {
		t.Fatalf("account = %q", live.Account)
	}
}

func TestImportSupermastersAdmin(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.pd.CreateSupermaster(ctx, pdns.Supermaster{IP: "192.0.2.99", Nameserver: "ns.other.example", Account: tC}))
	b := Backup{SchemaVersion: SchemaVersion, TenantID: tA, Supermasters: []store.Supermaster{
		{ID: smID, IP: "192.0.2.53", Nameserver: "ns.primary.example."},
		{ID: "0190aaaa-0000-7000-8000-000000000021", IP: "192.0.2.99", Nameserver: "ns.other.example."}}}
	res, err := f.svc.Import(ctx, admin(tA), b, Options{})
	must(t, err)
	if res.Imported[CSupermasters] != 1 || res.Skipped[CSupermasters] != 1 {
		t.Fatalf("result = %+v", res)
	}
	live, _ := f.pd.ListSupermasters(ctx)
	if len(live) != 2 {
		t.Fatalf("PowerDNS supermasters = %+v", live)
	}
	// again: exists locally -> skipped
	res, err = f.svc.Import(ctx, admin(tA), b, Options{})
	must(t, err)
	if res.Skipped[CSupermasters] != 2 {
		t.Fatalf("second result = %+v", res)
	}
	// local failure compensates the PowerDNS create
	f2 := newFixture(t)
	f2.st.FailNext("CreateSupermaster")
	if _, err := f2.svc.Import(ctx, admin(tA), Backup{SchemaVersion: SchemaVersion, Supermasters: b.Supermasters[:1]}, Options{}); err == nil {
		t.Fatal("store failure swallowed")
	}
	if live, _ := f2.pd.ListSupermasters(ctx); len(live) != 0 {
		t.Fatalf("no compensation: %+v", live)
	}
	// PowerDNS failure
	f3 := newFixture(t)
	f3.pd.FailNext("CreateSupermaster", pdns.ErrUnavailable)
	if _, err := f3.svc.Import(ctx, admin(tA), Backup{SchemaVersion: SchemaVersion, Supermasters: b.Supermasters[:1]}, Options{}); err == nil {
		t.Fatal("PowerDNS failure swallowed")
	}
	f3.pd.FailNext("ListSupermasters", pdns.ErrUnavailable)
	if _, err := f3.svc.Import(ctx, admin(tA), Backup{SchemaVersion: SchemaVersion, Supermasters: b.Supermasters[:1]}, Options{}); err == nil {
		t.Fatal("list failure swallowed")
	}
}

func TestImportErrors(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.seed(t)
	b := exported(t, f)
	must(t, f.st.DeleteZone(ctx, tA, zID))
	f.pd.FailNext("ListZoneNames", pdns.ErrUnavailable)
	if _, err := f.svc.Import(ctx, user(tA), b, Options{}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("list zones: %v", err)
	}
	if e := f.aud.last(); e.Outcome != audit.OutcomeError {
		t.Fatalf("failed import audit = %+v", e)
	}
	f.pd.FailNext("GetZone", pdns.ErrUnavailable)
	if _, err := f.svc.Import(ctx, user(tA), b, Options{}); err == nil {
		t.Fatal("get zone failure swallowed")
	}
	for _, m := range []string{"GetZoneByName", "ZoneConflict", "CreateZone", "GetTemplate", "AllTemplates"} {
		f.st.FailNext(m)
		opts := Options{}
		if m == "AllTemplates" {
			opts.Full = true
		}
		sub := user(tA)
		if opts.Full {
			sub = admin(tA)
		}
		if _, err := f.svc.Import(ctx, sub, b, opts); err == nil && m != "GetTemplate" {
			t.Fatalf("%s failure swallowed", m)
		}
	}
	if _, err := f.svc.Import(ctx, user(tA), Backup{SchemaVersion: 9}, Options{}); !errors.Is(err, ErrBadSchema) {
		t.Fatalf("bad schema: %v", err)
	}
}

func TestValidate(t *testing.T) {
	ok := Backup{SchemaVersion: SchemaVersion, TenantID: tA,
		Zones:        []ZoneRow{{Zone: store.Zone{ID: zID, Name: "example.org.", Kind: store.KindNative}}},
		Templates:    []store.Template{{ID: tpID, Name: "t", Records: []store.TemplateRecord{{Name: "@", Type: "A", TTL: 300, Content: "192.0.2.1"}}}},
		Supermasters: []store.Supermaster{{ID: smID, IP: "192.0.2.53", Nameserver: "ns.example.org."}}}
	must(t, Validate(ok, validate.Limits{}))
	cases := map[string]func(b *Backup){
		"tenant":     func(b *Backup) { b.TenantID = "x" },
		"zone id":    func(b *Backup) { b.Zones[0].ID = "x" },
		"zone tpl":   func(b *Backup) { b.Zones[0].TemplateID = "x" },
		"zone name":  func(b *Backup) { b.Zones[0].Name = "Example.ORG" },
		"suffix":     func(b *Backup) { b.Zones[0].Name = "com." },
		"kind":       func(b *Backup) { b.Zones[0].Kind = "bogus" },
		"origin":     func(b *Backup) { b.Zones[0].Origin = "bogus" },
		"masters":    func(b *Backup) { b.Zones[0].Masters = []string{"127.0.0.1"} },
		"desc":       func(b *Backup) { b.Zones[0].Description = strings.Repeat("x", 1001) },
		"ns":         func(b *Backup) { b.Zones[0].Nameservers = []string{"bad name"} },
		"tpl id":     func(b *Backup) { b.Templates[0].ID = "" },
		"tpl name":   func(b *Backup) { b.Templates[0].Name = "a\x00b" },
		"tpl record": func(b *Backup) { b.Templates[0].Records[0].Content = "not-an-ip" },
		"sm id":      func(b *Backup) { b.Supermasters[0].ID = "x" },
		"sm ip":      func(b *Backup) { b.Supermasters[0].IP = "127.0.0.1" },
		"sm ns":      func(b *Backup) { b.Supermasters[0].Nameserver = "x" },
		"rows":       func(b *Backup) { b.Templates = make([]store.Template, MaxRows+1) },
	}
	for name, mut := range cases {
		b := ok
		b.Zones = append([]ZoneRow(nil), ok.Zones...)
		b.Templates = append([]store.Template(nil), ok.Templates...)
		b.Templates[0].Records = append([]store.TemplateRecord(nil), ok.Templates[0].Records...)
		b.Supermasters = append([]store.Supermaster(nil), ok.Supermasters...)
		mut(&b)
		err := Validate(b, validate.Limits{})
		if !errors.Is(err, ErrBadSchema) && !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParse(t *testing.T) {
	for _, raw := range []string{`{`, `{"schema_version":1,"unknown":1}`, `{"schema_version":1} {}`, `{"schema_version":2}`} {
		if _, err := Parse([]byte(raw), validate.Limits{}); !errors.Is(err, ErrBadSchema) {
			t.Errorf("%s: %v", raw, err)
		}
	}
	if _, err := Parse([]byte(`{"schema_version":1,"zones":[],"templates":[],"supermasters":[]}`), validate.Limits{}); err != nil {
		t.Fatal(err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"tenant_id":"` + tA + `","zones":[{"id":"` + zID + `","name":"example.org.","kind":"native"}]}`))
	f.Add([]byte(`{"schema_version":1,"templates":[{"id":"` + tpID + `","name":"t","records":[{"name":"@","type":"MX","ttl":300,"content":"mail.[ZONE].","priority":10}]}]}`))
	f.Add([]byte(`{"schema_version":1,"supermasters":[{"id":"` + smID + `","ip":"192.0.2.1","nameserver":"ns.example.org."}]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := Parse(raw, validate.Limits{})
		if err != nil {
			if !errors.Is(err, ErrBadSchema) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if err := Validate(b, validate.Limits{}); err != nil {
			t.Fatalf("accepted document fails re-validation: %v", err)
		}
		// an accepted document imports without panicking
		fx := &fixture{st: memstore.New(), pd: pdns.NewFake()}
		fx.svc = New(Deps{Store: fx.st, PDNS: fx.pd})
		_, _ = fx.svc.Import(context.Background(), admin(tA), b, Options{Mode: ModeOverwrite})
	})
}
