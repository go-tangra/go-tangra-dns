package memstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/repo/repotest"
	"github.com/go-freya/freya/services/dns/internal/store"
)

func TestConformance(t *testing.T) {
	repotest.Run(t, func(*testing.T) repo.Store { return New() })
}

func TestFailNextEveryMethod(t *testing.T) {
	ctx := context.Background()
	m := New()
	tn := repotest.TenantA
	calls := map[string]func() error{
		"CreateZone":          func() error { return m.CreateZone(ctx, store.Zone{}) },
		"GetZone":             func() error { _, err := m.GetZone(ctx, tn, "x"); return err },
		"GetZoneByName":       func() error { _, err := m.GetZoneByName(ctx, tn, "x."); return err },
		"ListZones":           func() error { _, _, err := m.ListZones(ctx, tn, store.ZoneFilter{}); return err },
		"UpdateZone":          func() error { _, err := m.UpdateZone(ctx, store.Zone{}); return err },
		"DeleteZone":          func() error { return m.DeleteZone(ctx, tn, "x") },
		"ZoneConflict":        func() error { _, err := m.ZoneConflict(ctx, tn, "x."); return err },
		"AllZoneNames":        func() error { _, err := m.AllZoneNames(ctx); return err },
		"ZonesForTenant":      func() error { _, err := m.ZonesForTenant(ctx, tn); return err },
		"CreateTemplate":      func() error { return m.CreateTemplate(ctx, store.Template{}) },
		"GetTemplate":         func() error { _, err := m.GetTemplate(ctx, tn, "x"); return err },
		"ListTemplates":       func() error { _, err := m.ListTemplates(ctx, tn); return err },
		"UpdateTemplate":      func() error { _, err := m.UpdateTemplate(ctx, store.Template{}); return err },
		"DeleteTemplate":      func() error { return m.DeleteTemplate(ctx, tn, "x") },
		"CreateSupermaster":   func() error { return m.CreateSupermaster(ctx, store.Supermaster{}) },
		"GetSupermaster":      func() error { _, err := m.GetSupermaster(ctx, tn, "x"); return err },
		"ListSupermasters":    func() error { _, err := m.ListSupermasters(ctx, tn); return err },
		"DeleteSupermaster":   func() error { return m.DeleteSupermaster(ctx, tn, "x") },
		"GetServerConfig":     func() error { _, err := m.GetServerConfig(ctx); return err },
		"SaveServerConfig":    func() error { return m.SaveServerConfig(ctx, store.ServerConfig{}) },
		"SetConfigHashes":     func() error { return m.SetConfigHashes(ctx, "", "", time.Time{}) },
		"GetIPAMSync":         func() error { _, err := m.GetIPAMSync(ctx, tn, "x"); return err },
		"UpsertIPAMSync":      func() error { return m.UpsertIPAMSync(ctx, store.IPAMSync{}) },
		"DeleteIPAMSync":      func() error { return m.DeleteIPAMSync(ctx, tn, "x") },
		"ClearSyncZone":       func() error { return m.ClearSyncZone(ctx, tn, "x") },
		"InsertChallenge":     func() error { return m.InsertChallenge(ctx, store.Challenge{}) },
		"DeleteChallenge":     func() error { return m.DeleteChallenge(ctx, tn, "x", "y") },
		"ChallengesOlderThan": func() error { _, err := m.ChallengesOlderThan(ctx, time.Now(), 1); return err },
		"AllTemplates":        func() error { _, err := m.AllTemplates(ctx, tn); return err },
		"AllSupermasters":     func() error { _, err := m.AllSupermasters(ctx, tn); return err },
		"TenantIDs":           func() error { _, err := m.TenantIDs(ctx); return err },
		"AppendAudit":         func() error { return m.AppendAudit(ctx, store.AuditRow{}) },
	}
	for name, call := range calls {
		m.FailNext(name)
		err := call()
		var ie injectedErr
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: injected failure not returned: %v", name, err)
		}
	}
}

func TestDefaultsAndGuards(t *testing.T) {
	ctx := context.Background()
	m := New()
	tn := repotest.TenantA
	z := store.Zone{ID: store.NewID(), TenantID: tn, Name: "example.com.", PDNSID: "example.com."}
	if err := m.CreateZone(ctx, z); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateZone(ctx, z); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("same id: %v", err)
	}
	got, _ := m.GetZone(ctx, tn, z.ID)
	if got.Kind != store.KindNative || got.Origin != store.OriginManual || got.CreatedAt.IsZero() || got.Masters == nil || got.Nameservers == nil {
		t.Fatalf("defaults = %+v", got)
	}
	tp := store.Template{ID: store.NewID(), TenantID: tn, Name: "x"}
	_ = m.CreateTemplate(ctx, tp)
	if err := m.CreateTemplate(ctx, store.Template{ID: tp.ID, TenantID: tn, Name: "y"}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("template id: %v", err)
	}
	sm := store.Supermaster{ID: store.NewID(), TenantID: tn, IP: "::ffff:192.0.2.1", Nameserver: "ns."}
	if err := m.CreateSupermaster(ctx, sm); err != nil {
		t.Fatal(err)
	}
	if s, _ := m.GetSupermaster(ctx, tn, sm.ID); s.IP != "192.0.2.1" {
		t.Fatalf("ip canonical = %q", s.IP)
	}
	if err := m.CreateSupermaster(ctx, store.Supermaster{ID: sm.ID, TenantID: tn, IP: "192.0.2.9", Nameserver: "ns."}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("supermaster id: %v", err)
	}
	if err := m.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: tn, IP: "not-an-ip", Nameserver: "ns."}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("bad ip: %v", err)
	}
	if err := m.UpsertIPAMSync(ctx, store.IPAMSync{TenantID: tn, IPAddressID: "x", Address: "nope"}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("bad address: %v", err)
	}
	if err := m.UpsertIPAMSync(ctx, store.IPAMSync{TenantID: tn, IPAddressID: "x", Address: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := m.GetIPAMSync(ctx, tn, "x"); s.LastEvent != store.SyncCreated {
		t.Fatalf("sync default event = %q", s.LastEvent)
	}
	c := store.Challenge{ID: store.NewID(), TenantID: tn, ZoneID: z.ID, FQDN: "_acme-challenge.example.com.", Value: "v"}
	if err := m.InsertChallenge(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Value = "w"
	if err := m.InsertChallenge(ctx, c); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("challenge id: %v", err)
	}
	if n := len(m.Audit()); n != 0 {
		t.Fatalf("audit = %d", n)
	}
	_ = m.AppendAudit(ctx, store.AuditRow{Action: "zone.create"})
	if n := len(m.Audit()); n != 1 {
		t.Fatalf("audit = %d", n)
	}
	m.Close()
}

func TestOverlaps(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"a.", "a.", true}, {"x.a.", "a.", true}, {"a.", "x.a.", true}, {"xa.", "a.", false}, {"b.", "a.", false}} {
		if Overlaps(c.a, c.b) != c.want {
			t.Errorf("Overlaps(%s,%s)", c.a, c.b)
		}
	}
}
