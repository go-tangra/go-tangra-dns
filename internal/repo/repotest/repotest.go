// Package repotest is the behavioural conformance suite of repo.Store. The
// in-memory store runs it in the unit suite; the TimescaleDB store runs it in
// the tagged integration suite, so both implementations provably agree on
// tenant isolation, the GLOBAL zone-name / PowerDNS-id / supermaster guards,
// the cross-tenant overlap semantics, cascades and sync-state bookkeeping.
package repotest

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

// Fixed tenants of the suite.
const (
	TenantA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	TenantB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

// Factory returns a fresh, empty store for one subtest.
type Factory func(t *testing.T) repo.Store

// Run executes every conformance case against stores built by newStore.
func Run(t *testing.T, newStore Factory) {
	cases := map[string]func(*testing.T, repo.Store){
		"zones":         testZones,
		"zone filters":  testZoneFilters,
		"list paging":   testListPaging,
		"overlap":       testOverlap,
		"templates":     testTemplates,
		"supermasters":  testSupermasters,
		"config":        testConfig,
		"config hashes": testHashesFirst,
		"ipam sync":     testIPAMSync,
		"challenges":    testChallenges,
		"backup":        testBackup,
		"audit":         testAudit,
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fn := cases[n]
		t.Run(n, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

var ctx = context.Background()

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func base() time.Time { return time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond) }

// NewZone builds a valid zone row for a canonical name.
func NewZone(tenant, name string) store.Zone {
	now := base()
	return store.Zone{ID: store.NewID(), TenantID: tenant, Name: name, PDNSID: name, Kind: store.KindNative,
		Masters: []string{}, Nameservers: []string{"ns1." + name}, Origin: store.OriginManual, CreatedBy: "u1",
		CreatedAt: now, UpdatedAt: now}
}

func testZones(t *testing.T, s repo.Store) {
	a := NewZone(TenantA, "example.com.")
	a.Description = "primary"
	a.DNSSEC = true
	a.TemplateID = store.NewID()
	must(t, s.CreateZone(ctx, a))

	// GLOBAL uniqueness: the same name in another tenant is refused, as is a
	// reused PowerDNS id.
	dup := NewZone(TenantB, "example.com.")
	wantErr(t, s.CreateZone(ctx, dup), repo.ErrConflict)
	pd := NewZone(TenantB, "other.example.")
	pd.PDNSID = a.PDNSID
	wantErr(t, s.CreateZone(ctx, pd), repo.ErrConflict)

	got, err := s.GetZone(ctx, TenantA, a.ID)
	must(t, err)
	if got.Name != a.Name || got.PDNSID != a.PDNSID || !got.DNSSEC || got.Description != "primary" ||
		got.TemplateID != a.TemplateID || got.Origin != store.OriginManual || len(got.Nameservers) != 1 || got.CreatedBy != "u1" {
		t.Fatalf("get = %+v", got)
	}
	if got.Masters == nil {
		t.Fatal("masters must be an empty list, not nil")
	}
	byName, err := s.GetZoneByName(ctx, TenantA, "example.com.")
	must(t, err)
	if byName.ID != a.ID {
		t.Fatal("get by name")
	}
	// tenant B cannot see tenant A's zone at all
	_, err = s.GetZone(ctx, TenantB, a.ID)
	wantErr(t, err, repo.ErrNotFound)
	_, err = s.GetZoneByName(ctx, TenantB, "example.com.")
	wantErr(t, err, repo.ErrNotFound)
	_, err = s.GetZone(ctx, TenantA, store.NewID())
	wantErr(t, err, repo.ErrNotFound)

	a.Kind, a.Masters, a.DNSSEC, a.Description = store.KindSlave, []string{"192.0.2.10", "192.0.2.11:5300"}, false, "secondary"
	a.UpdatedAt = base().Add(time.Minute)
	up, err := s.UpdateZone(ctx, a)
	must(t, err)
	if up.Kind != store.KindSlave || len(up.Masters) != 2 || up.Masters[1] != "192.0.2.11:5300" || up.DNSSEC || up.Description != "secondary" || up.Name != "example.com." {
		t.Fatalf("update = %+v", up)
	}
	cross := a
	cross.TenantID = TenantB
	_, err = s.UpdateZone(ctx, cross)
	wantErr(t, err, repo.ErrNotFound)

	wantErr(t, s.DeleteZone(ctx, TenantB, a.ID), repo.ErrNotFound)
	must(t, s.DeleteZone(ctx, TenantA, a.ID))
	wantErr(t, s.DeleteZone(ctx, TenantA, a.ID), repo.ErrNotFound)
	// the name is free again after delete, for any tenant
	must(t, s.CreateZone(ctx, NewZone(TenantB, "example.com.")))
}

func testZoneFilters(t *testing.T, s repo.Store) {
	for i, n := range []string{"alpha.example.", "beta.example.", "gamma.example.", "delta.test.", "10.in-addr.arpa."} {
		z := NewZone(TenantA, n)
		if i == 1 {
			z.Kind = store.KindMaster
		}
		if i == 4 {
			z.Origin = store.OriginIPAM
			z.CreatedBy = store.CreatedByIPAMSync
		}
		must(t, s.CreateZone(ctx, z))
	}
	must(t, s.CreateZone(ctx, NewZone(TenantB, "zeta.example.")))

	list := func(f store.ZoneFilter) ([]store.Zone, int) {
		t.Helper()
		items, total, _, err := s.ListZones(ctx, TenantA, f, Req(store.ZoneList, 1, 0, "", ""))
		must(t, err)
		return items, total
	}
	items, total := list(store.ZoneFilter{})
	if total != 5 || len(items) != 5 || items[0].Name != "10.in-addr.arpa." || items[4].Name != "gamma.example." {
		t.Fatalf("all: total=%d %v", total, names(items))
	}
	if items, n := list(store.ZoneFilter{Query: "EXAMPLE"}); n != 3 || items[0].Name != "alpha.example." {
		t.Fatalf("query: %d %v", n, names(items))
	}
	if _, n := list(store.ZoneFilter{Query: "%"}); n != 0 {
		t.Fatalf("like metacharacter matched %d", n)
	}
	if items, n := list(store.ZoneFilter{Kind: store.KindMaster}); n != 1 || items[0].Name != "beta.example." {
		t.Fatalf("kind: %d", n)
	}
	if items, n := list(store.ZoneFilter{Origin: store.OriginIPAM}); n != 1 || items[0].Origin != store.OriginIPAM {
		t.Fatalf("origin: %d", n)
	}
	page, n, applied, err := s.ListZones(ctx, TenantA, store.ZoneFilter{}, Req(store.ZoneList, 2, 2, "", ""))
	must(t, err)
	if n != 5 || len(page) != 2 || page[0].Name != "beta.example." || applied.Page != 2 {
		t.Fatalf("page 2: %d %v", n, names(page))
	}
	// beyond the last page: the last page is returned and reported
	beyond, n, applied, err := s.ListZones(ctx, TenantA, store.ZoneFilter{}, Req(store.ZoneList, 9, 2, "", ""))
	must(t, err)
	if n != 5 || len(beyond) != 1 || applied.Page != 3 || beyond[0].Name != "gamma.example." {
		t.Fatalf("beyond: %d %v page %d", n, names(beyond), applied.Page)
	}

	all, err := s.ZonesForTenant(ctx, TenantA)
	must(t, err)
	if len(all) != 5 {
		t.Fatalf("zones for tenant = %d", len(all))
	}
	none, err := s.ZonesForTenant(ctx, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77")
	must(t, err)
	if none == nil || len(none) != 0 {
		t.Fatalf("empty tenant = %v", none)
	}
	namesAll, err := s.AllZoneNames(ctx)
	must(t, err)
	if len(namesAll) != 6 || !sort.StringsAreSorted(namesAll) || namesAll[5] != "zeta.example." {
		t.Fatalf("all names = %v", namesAll)
	}
}

// Req builds a valid list request (zero values take the spec's defaults).
func Req(spec listquery.Spec, page, size int, sort string, order listquery.Dir) listquery.Request {
	r, err := listquery.New(page, size, sort, order, spec)
	if err != nil {
		panic(err)
	}
	return r
}

// pageAll walks every page of a list and returns the ids in order, failing on
// a total that changes between pages.
func pageAll(t *testing.T, size int, list func(page int) ([]string, int)) []string {
	t.Helper()
	var all []string
	first, total := list(1)
	all = append(all, first...)
	for p := 2; (p-1)*size < total; p++ {
		ids, n := list(p)
		if n != total {
			t.Fatalf("total changed between pages: %d then %d", total, n)
		}
		all = append(all, ids...)
	}
	if len(all) != total {
		t.Fatalf("paged %d rows, total %d", len(all), total)
	}
	return all
}

// exactlyOnce fails unless ids holds every id of want exactly once.
func exactlyOnce(t *testing.T, label string, ids []string, want map[string]bool) {
	t.Helper()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("%s: %s returned twice", label, id)
		}
		if !want[id] {
			t.Fatalf("%s: %s is not one of the tenant's rows", label, id)
		}
		seen[id] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("%s: %d of %d rows returned", label, len(seen), len(want))
	}
}

// testListPaging pages every list under every sort field and direction with a
// small page size: each of the tenant's rows comes back exactly once, the
// other tenant's never, and the order holds across page boundaries.
func testListPaging(t *testing.T, s repo.Store) {
	zoneIDs := map[string]bool{}
	kinds := []string{store.KindNative, store.KindMaster, store.KindNative, store.KindSlave, store.KindNative, store.KindMaster, store.KindNative}
	for i, n := range []string{"b.example.", "a.example.", "c.test.", "a.test.", "2.0.192.in-addr.arpa.", "x.example.", "m.example."} {
		z := NewZone(TenantA, n)
		z.Kind = kinds[i]
		if z.Kind == store.KindSlave {
			z.Masters = []string{"192.0.2.1"}
		}
		z.UpdatedAt = base().Add(time.Duration(i%3) * time.Minute) // ties on purpose
		must(t, s.CreateZone(ctx, z))
		zoneIDs[z.ID] = true
	}
	for _, n := range []string{"other.example.", "zz.example."} {
		must(t, s.CreateZone(ctx, NewZone(TenantB, n)))
	}
	byID := map[string]store.Zone{}
	for field := range store.ZoneList.Fields {
		for _, dir := range []listquery.Dir{listquery.Asc, listquery.Desc} {
			ids := pageAll(t, 2, func(p int) ([]string, int) {
				items, total, _, err := s.ListZones(ctx, TenantA, store.ZoneFilter{}, Req(store.ZoneList, p, 2, field, dir))
				must(t, err)
				out := []string{}
				for _, z := range items {
					byID[z.ID] = z
					out = append(out, z.ID)
				}
				return out, total
			})
			exactlyOnce(t, "zones "+field+" "+string(dir), ids, zoneIDs)
			for i := 1; i < len(ids); i++ {
				a, b := byID[ids[i-1]], byID[ids[i]]
				var c int
				switch field {
				case "name":
					c = strings.Compare(a.Name, b.Name)
				case "kind":
					c = strings.Compare(a.Kind, b.Kind)
				case "updated_at":
					c = a.UpdatedAt.Compare(b.UpdatedAt)
				}
				if (dir == listquery.Asc && c > 0) || (dir == listquery.Desc && c < 0) {
					t.Fatalf("zones %s %s out of order at %d: %s then %s", field, dir, i, a.Name, b.Name)
				}
			}
		}
	}
	if _, total, _, err := s.ListZones(ctx, TenantB, store.ZoneFilter{}, Req(store.ZoneList, 1, 2, "", "")); err != nil || total != 2 {
		t.Fatalf("tenant B total = %d (%v)", total, err)
	}
	// filtered totals: kind=native, sorted by updated_at desc
	items, total, _, err := s.ListZones(ctx, TenantA, store.ZoneFilter{Kind: store.KindNative}, Req(store.ZoneList, 1, 3, "updated_at", ""))
	must(t, err)
	if total != 4 || len(items) != 3 || items[0].UpdatedAt.Before(items[2].UpdatedAt) {
		t.Fatalf("native by updated_at: total %d %v", total, names(items))
	}

	tplIDs := map[string]bool{}
	for _, n := range []string{"Web", "mail", "Alpha", "beta", "web2"} {
		tpl := store.Template{ID: store.NewID(), TenantID: TenantA, Name: n, Records: []store.TemplateRecord{}}
		must(t, s.CreateTemplate(ctx, tpl))
		tplIDs[tpl.ID] = true
	}
	must(t, s.CreateTemplate(ctx, store.Template{ID: store.NewID(), TenantID: TenantB, Name: "other", Records: []store.TemplateRecord{}}))
	for _, dir := range []listquery.Dir{listquery.Asc, listquery.Desc} {
		var got []string
		ids := pageAll(t, 2, func(p int) ([]string, int) {
			items, total, _, err := s.ListTemplates(ctx, TenantA, Req(store.TemplateList, p, 2, "name", dir))
			must(t, err)
			out := []string{}
			for _, x := range items {
				out = append(out, x.ID)
				got = append(got, x.Name)
			}
			return out, total
		})
		exactlyOnce(t, "templates "+string(dir), ids, tplIDs)
		want := []string{"Alpha", "beta", "mail", "Web", "web2"}
		if dir == listquery.Desc {
			want = []string{"web2", "Web", "mail", "beta", "Alpha"}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("templates %s = %v", dir, got)
		}
	}

	smIDs := map[string]bool{}
	for _, p := range [][2]string{{"192.0.2.10", "ns2.example."}, {"2001:db8::1", "ns1.example."}, {"192.0.2.9", "ns3.example."}, {"10.0.0.1", "ns1.example."}, {"192.0.2.10", "ns1.example."}} {
		sm := store.Supermaster{ID: store.NewID(), TenantID: TenantA, IP: p[0], Nameserver: p[1]}
		must(t, s.CreateSupermaster(ctx, sm))
		smIDs[sm.ID] = true
	}
	must(t, s.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: TenantB, IP: "198.51.100.1", Nameserver: "ns.other."}))
	for field := range store.SupermasterList.Fields {
		for _, dir := range []listquery.Dir{listquery.Asc, listquery.Desc} {
			var first string
			ids := pageAll(t, 2, func(p int) ([]string, int) {
				items, total, _, err := s.ListSupermasters(ctx, TenantA, Req(store.SupermasterList, p, 2, field, dir))
				must(t, err)
				out := []string{}
				for _, x := range items {
					if first == "" {
						first = x.IP + " " + x.Nameserver
					}
					out = append(out, x.ID)
				}
				return out, total
			})
			exactlyOnce(t, "supermasters "+field+" "+string(dir), ids, smIDs)
			if field == "ip" && dir == listquery.Asc && !strings.HasPrefix(first, "10.0.0.1 ") {
				t.Fatalf("inet order: first = %s", first)
			}
			if field == "ip" && dir == listquery.Desc && !strings.HasPrefix(first, "2001:db8::1 ") {
				t.Fatalf("inet order desc: first = %s", first)
			}
		}
	}
}

func names(zs []store.Zone) []string {
	out := []string{}
	for _, z := range zs {
		out = append(out, z.Name)
	}
	return out
}

func testOverlap(t *testing.T, s repo.Store) {
	must(t, s.CreateZone(ctx, NewZone(TenantA, "example.com.")))
	must(t, s.CreateZone(ctx, NewZone(TenantA, "lab.corp.example.")))
	cases := []struct {
		tenant, name string
		want         bool
	}{
		{TenantB, "example.com.", true},          // equal
		{TenantB, "www.example.com.", true},      // descendant of A's zone
		{TenantB, "a.b.example.com.", true},      // deeper descendant
		{TenantB, "com.", true},                  // ancestor of A's zone
		{TenantB, "corp.example.", true},         // ancestor of lab.corp.example.
		{TenantB, "xexample.com.", false},        // suffix without a label boundary
		{TenantB, "example.org.", false},         // unrelated
		{TenantB, "other.corp.example.", false},  // sibling
		{TenantA, "www.example.com.", false},     // same-tenant nesting is allowed
		{TenantA, "example.com.", false},         // own zone: equality is the unique index's job
		{TenantB, "EXAMPLE.COM.", true},          // case-insensitive
		{TenantB, "x_y.lab.corp.example.", true}, // underscore is not a wildcard
		{TenantB, "lab_corp.example.", false},    // ... in either direction
	}
	for _, c := range cases {
		got, err := s.ZoneConflict(ctx, c.tenant, c.name)
		must(t, err)
		if got != c.want {
			t.Errorf("conflict(%s, %s) = %v, want %v", c.tenant[len(c.tenant)-2:], c.name, got, c.want)
		}
	}
}

func testTemplates(t *testing.T, s repo.Store) {
	now := base()
	recs := []store.TemplateRecord{
		{Name: "@", Type: "NS", TTL: 3600, Content: "ns1.[ZONE]."},
		{Name: "@", Type: "MX", TTL: 3600, Content: "mail.[ZONE].", Priority: 10},
	}
	a := store.Template{ID: store.NewID(), TenantID: TenantA, Name: "Default", Description: "base", Records: recs, CreatedAt: now, UpdatedAt: now}
	must(t, s.CreateTemplate(ctx, a))
	dup := store.Template{ID: store.NewID(), TenantID: TenantA, Name: "DEFAULT", Records: nil}
	wantErr(t, s.CreateTemplate(ctx, dup), repo.ErrConflict)
	// the same name in another tenant is fine
	must(t, s.CreateTemplate(ctx, store.Template{ID: store.NewID(), TenantID: TenantB, Name: "default"}))
	b := store.Template{ID: store.NewID(), TenantID: TenantA, Name: "another"}
	must(t, s.CreateTemplate(ctx, b))

	got, err := s.GetTemplate(ctx, TenantA, a.ID)
	must(t, err)
	if got.Name != "Default" || got.Description != "base" || len(got.Records) != 2 || got.Records[1].Priority != 10 || got.Records[0].Content != "ns1.[ZONE]." {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetTemplate(ctx, TenantB, a.ID)
	wantErr(t, err, repo.ErrNotFound)
	gb, err := s.GetTemplate(ctx, TenantA, b.ID)
	must(t, err)
	if gb.Records == nil {
		t.Fatal("records must be an empty list")
	}

	list, _, _, err := s.ListTemplates(ctx, TenantA, Req(store.TemplateList, 1, 0, "", ""))
	must(t, err)
	if len(list) != 2 || list[0].Name != "another" || list[1].Name != "Default" {
		t.Fatalf("list = %+v", list)
	}

	a.Name, a.Description, a.Records = "Renamed", "", recs[:1]
	up, err := s.UpdateTemplate(ctx, a)
	must(t, err)
	if up.Name != "Renamed" || up.Description != "" || len(up.Records) != 1 {
		t.Fatalf("update = %+v", up)
	}
	b.Name = "renamed" // collides case-insensitively
	_, err = s.UpdateTemplate(ctx, b)
	wantErr(t, err, repo.ErrConflict)
	cross := a
	cross.TenantID = TenantB
	_, err = s.UpdateTemplate(ctx, cross)
	wantErr(t, err, repo.ErrNotFound)

	wantErr(t, s.DeleteTemplate(ctx, TenantB, a.ID), repo.ErrNotFound)
	must(t, s.DeleteTemplate(ctx, TenantA, a.ID))
	wantErr(t, s.DeleteTemplate(ctx, TenantA, a.ID), repo.ErrNotFound)
}

func testSupermasters(t *testing.T, s repo.Store) {
	a := store.Supermaster{ID: store.NewID(), TenantID: TenantA, IP: "192.0.2.53", Nameserver: "ns1.example.com.", CreatedBy: "admin"}
	must(t, s.CreateSupermaster(ctx, a))
	// GLOBAL (ip, nameserver): refused for any tenant
	wantErr(t, s.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: TenantB, IP: "192.0.2.53", Nameserver: "ns1.example.com."}), repo.ErrConflict)
	must(t, s.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: TenantA, IP: "192.0.2.53", Nameserver: "ns2.example.com."}))
	must(t, s.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: TenantB, IP: "2001:db8::53", Nameserver: "ns1.example.net."}))

	got, err := s.GetSupermaster(ctx, TenantA, a.ID)
	must(t, err)
	if got.IP != "192.0.2.53" || got.Nameserver != "ns1.example.com." || got.CreatedBy != "admin" || got.CreatedAt.IsZero() {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetSupermaster(ctx, TenantB, a.ID)
	wantErr(t, err, repo.ErrNotFound)
	la, _, _, err := s.ListSupermasters(ctx, TenantA, Req(store.SupermasterList, 1, 0, "", ""))
	must(t, err)
	if len(la) != 2 || la[0].Nameserver != "ns1.example.com." {
		t.Fatalf("list A = %+v", la)
	}
	lb, _, _, err := s.ListSupermasters(ctx, TenantB, Req(store.SupermasterList, 1, 0, "", ""))
	must(t, err)
	if len(lb) != 1 || lb[0].IP != "2001:db8::53" {
		t.Fatalf("list B = %+v", lb)
	}
	wantErr(t, s.DeleteSupermaster(ctx, TenantB, a.ID), repo.ErrNotFound)
	must(t, s.DeleteSupermaster(ctx, TenantA, a.ID))
	wantErr(t, s.DeleteSupermaster(ctx, TenantA, a.ID), repo.ErrNotFound)
	// the pair is free again
	must(t, s.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: TenantB, IP: "192.0.2.53", Nameserver: "ns1.example.com."}))
}

func testConfig(t *testing.T, s repo.Store) {
	_, err := s.GetServerConfig(ctx)
	wantErr(t, err, repo.ErrNotFound)
	rec := json.RawMessage(`{"port":53,"allowed_networks":["10.0.0.0/8"]}`)
	must(t, s.SaveServerConfig(ctx, store.ServerConfig{Recursor: rec, UpdatedBy: "admin", UpdatedAt: base()}))
	got, err := s.GetServerConfig(ctx)
	must(t, err)
	if !jsonEq(got.Recursor, rec) || !jsonEq(got.Authoritative, json.RawMessage(`{}`)) || got.UpdatedBy != "admin" || got.RecursorHash != "" {
		t.Fatalf("get = %+v (%s)", got, got.Authoritative)
	}
	must(t, s.SetConfigHashes(ctx, "h-rec", "h-auth", base()))
	auth := json.RawMessage(`{"port":5300}`)
	must(t, s.SaveServerConfig(ctx, store.ServerConfig{Recursor: rec, Authoritative: auth, UpdatedBy: "admin2"}))
	got, err = s.GetServerConfig(ctx)
	must(t, err)
	if got.RecursorHash != "h-rec" || got.AuthHash != "h-auth" || !jsonEq(got.Authoritative, auth) || got.UpdatedBy != "admin2" {
		t.Fatalf("hashes not kept across save: %+v", got)
	}
}

// SetConfigHashes before any save creates the row with default sections.
func testHashesFirst(t *testing.T, s repo.Store) {
	must(t, s.SetConfigHashes(ctx, "a", "b", base()))
	got, err := s.GetServerConfig(ctx)
	must(t, err)
	if got.RecursorHash != "a" || got.AuthHash != "b" || !jsonEq(got.Recursor, json.RawMessage(`{}`)) {
		t.Fatalf("hashes first = %+v", got)
	}
}

func jsonEq(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return string(ja) == string(jb)
}

func testIPAMSync(t *testing.T, s repo.Store) {
	fz := NewZone(TenantA, "example.com.")
	rz := NewZone(TenantA, "2.0.192.in-addr.arpa.")
	must(t, s.CreateZone(ctx, fz))
	must(t, s.CreateZone(ctx, rz))
	row := store.IPAMSync{TenantID: TenantA, IPAddressID: "ip-1", Address: "192.0.2.10", Hostname: "web.example.com.",
		ForwardZoneID: fz.ID, ForwardName: "web.example.com.", ForwardType: "A", ReverseZoneID: rz.ID,
		ReverseName: "10.2.0.192.in-addr.arpa.", LastEvent: store.SyncCreated}
	must(t, s.UpsertIPAMSync(ctx, row))
	got, err := s.GetIPAMSync(ctx, TenantA, "ip-1")
	must(t, err)
	if got.Address != "192.0.2.10" || got.ForwardZoneID != fz.ID || got.ReverseName != row.ReverseName || got.LastEvent != store.SyncCreated || got.UpdatedAt.IsZero() {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetIPAMSync(ctx, TenantB, "ip-1")
	wantErr(t, err, repo.ErrNotFound)

	row.Hostname, row.ForwardName, row.LastEvent = "api.example.com.", "api.example.com.", store.SyncUpdated
	must(t, s.UpsertIPAMSync(ctx, row))
	v6 := store.IPAMSync{TenantID: TenantA, IPAddressID: "ip-2", Address: "2001:db8::1", Hostname: "v6.example.com.",
		ForwardZoneID: fz.ID, ForwardName: "v6.example.com.", ForwardType: "AAAA", LastEvent: store.SyncScanned}
	must(t, s.UpsertIPAMSync(ctx, v6))
	got, err = s.GetIPAMSync(ctx, TenantA, "ip-1")
	must(t, err)
	if got.Hostname != "api.example.com." || got.LastEvent != store.SyncUpdated {
		t.Fatalf("upsert replace = %+v", got)
	}

	// deleting a zone nulls the references, never the rows
	must(t, s.ClearSyncZone(ctx, TenantA, rz.ID))
	got, err = s.GetIPAMSync(ctx, TenantA, "ip-1")
	must(t, err)
	if got.ReverseZoneID != "" || got.ReverseName != "" || got.ForwardZoneID != fz.ID {
		t.Fatalf("clear reverse = %+v", got)
	}
	must(t, s.ClearSyncZone(ctx, TenantA, fz.ID))
	g2, err := s.GetIPAMSync(ctx, TenantA, "ip-2")
	must(t, err)
	if g2.ForwardZoneID != "" || g2.ForwardName != "" || g2.ForwardType != "" || g2.Address != "2001:db8::1" {
		t.Fatalf("clear forward = %+v", g2)
	}
	must(t, s.ClearSyncZone(ctx, TenantB, fz.ID)) // no rows: fine

	wantErr(t, s.DeleteIPAMSync(ctx, TenantB, "ip-1"), repo.ErrNotFound)
	must(t, s.DeleteIPAMSync(ctx, TenantA, "ip-1"))
	wantErr(t, s.DeleteIPAMSync(ctx, TenantA, "ip-1"), repo.ErrNotFound)
}

func testChallenges(t *testing.T, s repo.Store) {
	za := NewZone(TenantA, "example.com.")
	zb := NewZone(TenantB, "example.net.")
	must(t, s.CreateZone(ctx, za))
	must(t, s.CreateZone(ctx, zb))
	old := base().Add(-2 * time.Hour)
	val := strings.Repeat("a", 43)
	c1 := store.Challenge{ID: store.NewID(), TenantID: TenantA, ZoneID: za.ID, FQDN: "_acme-challenge.example.com.", Value: val, RequestedBy: "spiffe://example.org/svc/lcm", CreatedAt: old}
	must(t, s.InsertChallenge(ctx, c1))
	dup := c1
	dup.ID = store.NewID()
	wantErr(t, s.InsertChallenge(ctx, dup), repo.ErrConflict)
	// a zone of another tenant cannot be referenced
	cross := store.Challenge{ID: store.NewID(), TenantID: TenantA, ZoneID: zb.ID, FQDN: "_acme-challenge.example.net.", Value: val}
	wantErr(t, s.InsertChallenge(ctx, cross), repo.ErrNotFound)
	c2 := store.Challenge{ID: store.NewID(), TenantID: TenantB, ZoneID: zb.ID, FQDN: "_acme-challenge.example.net.", Value: val, CreatedAt: old.Add(time.Minute)}
	must(t, s.InsertChallenge(ctx, c2))
	fresh := store.Challenge{ID: store.NewID(), TenantID: TenantA, ZoneID: za.ID, FQDN: "_acme-challenge.www.example.com.", Value: strings.Repeat("b", 43), CreatedAt: base().Add(time.Hour)}
	must(t, s.InsertChallenge(ctx, fresh))

	stale, err := s.ChallengesOlderThan(ctx, base(), 10)
	must(t, err)
	if len(stale) != 2 || stale[0].ID != c1.ID || stale[1].ID != c2.ID || stale[0].RequestedBy != c1.RequestedBy {
		t.Fatalf("older than = %+v", stale)
	}
	one, err := s.ChallengesOlderThan(ctx, base(), 1)
	must(t, err)
	if len(one) != 1 {
		t.Fatalf("limit = %d", len(one))
	}

	wantErr(t, s.DeleteChallenge(ctx, TenantB, c1.FQDN, c1.Value), repo.ErrNotFound)
	must(t, s.DeleteChallenge(ctx, TenantA, c1.FQDN, c1.Value))
	wantErr(t, s.DeleteChallenge(ctx, TenantA, c1.FQDN, c1.Value), repo.ErrNotFound)

	// deleting the zone cascades its challenges
	must(t, s.DeleteZone(ctx, TenantA, za.ID))
	wantErr(t, s.DeleteChallenge(ctx, TenantA, fresh.FQDN, fresh.Value), repo.ErrNotFound)
}

func testBackup(t *testing.T, s repo.Store) {
	must(t, s.CreateZone(ctx, NewZone(TenantA, "example.com.")))
	must(t, s.CreateTemplate(ctx, store.Template{ID: store.NewID(), TenantID: TenantA, Name: "t1"}))
	must(t, s.CreateSupermaster(ctx, store.Supermaster{ID: store.NewID(), TenantID: TenantB, IP: "192.0.2.1", Nameserver: "ns.example.net."}))
	ids, err := s.TenantIDs(ctx)
	must(t, err)
	if strings.Join(ids, ",") != TenantA+","+TenantB {
		t.Fatalf("tenant ids = %v", ids)
	}
	tpls, err := s.AllTemplates(ctx, TenantA)
	must(t, err)
	if len(tpls) != 1 || tpls[0].Name != "t1" {
		t.Fatalf("templates = %+v", tpls)
	}
	sms, err := s.AllSupermasters(ctx, TenantB)
	must(t, err)
	if len(sms) != 1 {
		t.Fatalf("supermasters = %+v", sms)
	}
	none, err := s.AllSupermasters(ctx, TenantA)
	must(t, err)
	if none == nil || len(none) != 0 {
		t.Fatalf("no supermasters = %v", none)
	}
}

func testAudit(t *testing.T, s repo.Store) {
	must(t, s.AppendAudit(ctx, store.AuditRow{ID: store.NewID(), TenantID: TenantA, At: base(), ActorKind: "user", ActorID: "u1",
		Action: "zone.create", SubjectKind: "zone", SubjectID: store.NewID(), Outcome: "ok", Detail: map[string]any{"name": "example.com."}}))
	must(t, s.AppendAudit(ctx, store.AuditRow{ID: store.NewID(), TenantID: store.NilTenant, ActorKind: "system", Action: "config.apply", SubjectKind: "config", Outcome: "ok"}))
}
