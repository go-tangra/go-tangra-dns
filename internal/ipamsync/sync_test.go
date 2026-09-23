package ipamsync

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

const (
	userA = "44444444-4444-7444-8444-444444444444"
	addr1 = "0190f7c2-0000-7000-8000-00000000a001"
	addr2 = "0190f7c2-0000-7000-8000-00000000a002"
	addr3 = "0190f7c2-0000-7000-8000-00000000a003"
	sub4  = "0190f7c2-0000-7000-8000-00000000b001"
	sub6  = "0190f7c2-0000-7000-8000-00000000b002"
)

// fakeIPAM is IPAM's view per tenant.
type fakeIPAM struct {
	mu         sync.Mutex
	addrs      map[string]map[string]Address // tenant -> id -> address
	subnets    map[string]Subnet
	failGet    error
	failSubnet bool
}

func newFakeIPAM() *fakeIPAM {
	return &fakeIPAM{addrs: map[string]map[string]Address{}, subnets: map[string]Subnet{
		sub4: {ID: sub4, CIDR: "192.0.2.0/24"}, sub6: {ID: sub6, CIDR: "2001:db8::/64"},
	}}
}

func (f *fakeIPAM) set(tenant string, a Address) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addrs[tenant] == nil {
		f.addrs[tenant] = map[string]Address{}
	}
	f.addrs[tenant][a.ID] = a
}

func (f *fakeIPAM) del(tenant, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.addrs[tenant], id)
}

func (f *fakeIPAM) GetAddress(_ context.Context, tenant, id string) (Address, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failGet != nil {
		return Address{}, f.failGet
	}
	a, ok := f.addrs[tenant][id]
	if !ok {
		return Address{}, ErrNotFound
	}
	return a, nil
}

func (f *fakeIPAM) GetSubnet(_ context.Context, _, id string) (Subnet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subnets[id]
	if f.failSubnet || !ok {
		return Subnet{}, errors.New("ipam unavailable")
	}
	return s, nil
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
	a.events = append(a.events, e)
	a.mu.Unlock()
	return nil
}

func (a *auditLog) count(t audit.EventType, outcome string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.EventType == t && (outcome == "" || e.Outcome == outcome) {
			n++
		}
	}
	return n
}

// reverseFailing fails every PATCH of a reverse zone.
type reverseFailing struct{ *pdns.Fake }

func (r reverseFailing) PatchRRsets(ctx context.Context, id string, sets []pdns.RRset) error {
	if strings.HasSuffix(id, ".arpa.") {
		return pdns.ErrUnavailable
	}
	return r.Fake.PatchRRsets(ctx, id, sets)
}

type harness struct {
	t    *testing.T
	st   *memstore.Mem
	pd   *pdns.Fake
	ipam *fakeIPAM
	zs   *zones.Service
	aud  *auditLog
	pub  *events.Recorder
	s    *Syncer
}

func newHarness(t *testing.T, wrap func(*pdns.Fake) pdns.Client) *harness {
	t.Helper()
	h := &harness{t: t, st: memstore.New(), pd: pdns.NewFake(), ipam: newFakeIPAM(), aud: &auditLog{}, pub: &events.Recorder{}}
	var client pdns.Client = h.pd
	if wrap != nil {
		client = wrap(h.pd)
	}
	h.zs = zones.New(zones.Deps{Store: h.st, PDNS: client, Events: h.pub, Audit: h.aud})
	rs := records.New(records.Deps{Zones: h.zs, PDNS: client, Events: h.pub, Audit: h.aud})
	h.s = New(Deps{Store: h.st, Zones: h.zs, Records: rs, IPAM: h.ipam, Audit: h.aud, TTL: 3600})
	return h
}

func (h *harness) zone(tenant, name string) store.Zone {
	h.t.Helper()
	z, err := h.zs.Create(context.Background(), authz.User(tenant, userA, nil), zones.CreateInput{Name: name, Kind: "native"})
	if err != nil {
		h.t.Fatal(err)
	}
	return z
}

func (h *harness) handle(tenant, id, typ string) error {
	return h.s.Handle(context.Background(), tenant, Event{Type: typ, ID: id})
}

func (h *harness) mustHandle(tenant, id, typ string) {
	h.t.Helper()
	if err := h.handle(tenant, id, typ); err != nil {
		h.t.Fatalf("handle %s %s: %v", id, typ, err)
	}
}

// values returns the rrset values in PowerDNS (nil when absent).
func (h *harness) values(zone, name, typ string) []string {
	h.t.Helper()
	z, err := h.pd.GetZone(context.Background(), zone)
	if err != nil {
		return nil
	}
	for _, r := range z.RRsets {
		if r.Name == name && r.Type == typ {
			out := []string{}
			for _, v := range r.Records {
				out = append(out, v.Content)
			}
			return out
		}
	}
	return nil
}

func (h *harness) state(tenant, id string) (store.IPAMSync, bool) {
	s, err := h.st.GetIPAMSync(context.Background(), tenant, id)
	return s, err == nil
}

func (h *harness) patches() int {
	n := 0
	for _, c := range h.pd.CallLog() {
		if strings.HasPrefix(c, "PatchRRsets") || strings.HasPrefix(c, "CreateZone") {
			n++
		}
	}
	return n
}

func eq(a []string, b ...string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

const (
	rev4 = "2.0.192.in-addr.arpa."
	ptr4 = "10.2.0.192.in-addr.arpa."
	rev6 = "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	ptr6 = "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0." + rev6
)

func TestCreatedScannedV4AndV6(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	h.mustHandle(tenantA, addr1, TypeCreated)

	if v := h.values("example.com.", "web.example.com.", "A"); !eq(v, "192.0.2.10") {
		t.Fatalf("A = %v", v)
	}
	if v := h.values(rev4, ptr4, "PTR"); !eq(v, "web.example.com.") {
		t.Fatalf("PTR = %v", v)
	}
	rz, err := h.st.GetZoneByName(context.Background(), tenantA, rev4)
	if err != nil || rz.Origin != store.OriginIPAM || rz.CreatedBy != store.CreatedByIPAMSync || rz.Kind != store.KindNative {
		t.Fatalf("reverse zone = %+v %v", rz, err)
	}
	s, ok := h.state(tenantA, addr1)
	if !ok || s.Hostname != "web.example.com." || s.ForwardName != "web.example.com." || s.ForwardType != "A" || s.ForwardZoneID == "" ||
		s.ReverseName != ptr4 || s.ReverseZoneID != rz.ID || s.LastEvent != store.SyncCreated || s.Address != "192.0.2.10" {
		t.Fatalf("state = %+v", s)
	}
	// events carry source ipam
	found := false
	for _, e := range h.pub.Events {
		if p, ok := e.Payload.(events.RecordPayload); ok && p.Source == events.SourceIPAM && p.Type == "PTR" {
			found = true
		}
	}
	if !found || h.aud.count(audit.SyncUpsert, audit.OutcomeOK) != 1 {
		t.Fatalf("events/audit: %+v %d", h.pub.Events, h.aud.count(audit.SyncUpsert, audit.OutcomeOK))
	}

	// a scan of the unchanged address is a no-op in PowerDNS (idempotent)
	before := h.patches()
	h.mustHandle(tenantA, addr1, TypeScanned)
	if h.patches() != before {
		t.Fatalf("duplicate event wrote to PowerDNS: %v", h.pd.CallLog()[before:])
	}
	if s, _ := h.state(tenantA, addr1); s.LastEvent != store.SyncScanned {
		t.Fatalf("last event = %q", s.LastEvent)
	}

	// IPv6: AAAA + PTR in a /64 nibble zone
	h.ipam.set(tenantA, Address{ID: addr2, Address: "2001:db8::10", SubnetID: sub6, Hostname: "v6.example.com."})
	h.mustHandle(tenantA, addr2, TypeCreated)
	if v := h.values("example.com.", "v6.example.com.", "AAAA"); !eq(v, "2001:db8::10") {
		t.Fatalf("AAAA = %v", v)
	}
	if v := h.values(rev6, ptr6, "PTR"); !eq(v, "v6.example.com.") {
		t.Fatalf("PTR6 = %v", v)
	}
}

func TestForgedEventsUseIPAMState(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	// the payload claims evil.example.com; IPAM says web.example.com
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	if err := h.s.Handle(context.Background(), tenantA, Event{Type: TypeCreated, ID: addr1, Address: "198.51.100.1", Hostname: "evil.example.com"}); err != nil {
		t.Fatal(err)
	}
	if h.values("example.com.", "evil.example.com.", "A") != nil || !eq(h.values("example.com.", "web.example.com.", "A"), "192.0.2.10") {
		t.Fatal("payload data was used")
	}
	// unknown id: IPAM has nothing -> nothing written, no zone created
	before := h.patches()
	if err := h.s.Handle(context.Background(), tenantA, Event{Type: TypeCreated, ID: addr3, Address: "203.0.113.5", Hostname: "x.attacker.org"}); err != nil {
		t.Fatal(err)
	}
	if h.patches() != before {
		t.Fatalf("unknown id wrote: %v", h.pd.CallLog()[before:])
	}
	if _, ok := h.state(tenantA, addr3); ok {
		t.Fatal("state for unknown id")
	}
}

func TestRenameClearDelete(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	h.mustHandle(tenantA, addr1, TypeCreated)

	// rename
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "api.example.com"})
	h.mustHandle(tenantA, addr1, TypeUpdated)
	if h.values("example.com.", "web.example.com.", "A") != nil || !eq(h.values("example.com.", "api.example.com.", "A"), "192.0.2.10") {
		t.Fatal("rename did not move the forward record")
	}
	if v := h.values(rev4, ptr4, "PTR"); !eq(v, "api.example.com.") {
		t.Fatalf("PTR not repointed: %v", v)
	}
	if s, _ := h.state(tenantA, addr1); s.ForwardName != "api.example.com." || s.LastEvent != store.SyncUpdated {
		t.Fatalf("state = %+v", s)
	}

	// address change: old PTR removed, new written
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.11", SubnetID: sub4, Hostname: "api.example.com"})
	h.mustHandle(tenantA, addr1, TypeUpdated)
	if h.values(rev4, ptr4, "PTR") != nil || !eq(h.values(rev4, "11.2.0.192.in-addr.arpa.", "PTR"), "api.example.com.") ||
		!eq(h.values("example.com.", "api.example.com.", "A"), "192.0.2.11") {
		t.Fatal("address change not followed")
	}

	// cleared host name: forward + PTR removed, row kept with nulls
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.11", SubnetID: sub4})
	h.mustHandle(tenantA, addr1, TypeUpdated)
	if h.values("example.com.", "api.example.com.", "A") != nil || h.values(rev4, "11.2.0.192.in-addr.arpa.", "PTR") != nil {
		t.Fatal("cleared host name kept records")
	}
	s, ok := h.state(tenantA, addr1)
	if !ok || s.Hostname != "" || s.ForwardName != "" || s.ForwardZoneID != "" || s.ReverseName != "" || s.ReverseZoneID != "" {
		t.Fatalf("cleared state = %+v %v", s, ok)
	}

	// host back, then deleted in IPAM: both removed, row removed, zones kept
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.11", SubnetID: sub4, Hostname: "db.example.com"})
	h.mustHandle(tenantA, addr1, TypeUpdated)
	h.ipam.del(tenantA, addr1)
	h.mustHandle(tenantA, addr1, TypeDeleted)
	if h.values("example.com.", "db.example.com.", "A") != nil || h.values(rev4, "11.2.0.192.in-addr.arpa.", "PTR") != nil {
		t.Fatal("delete kept records")
	}
	if _, ok := h.state(tenantA, addr1); ok {
		t.Fatal("state row kept after delete")
	}
	for _, z := range []string{"example.com.", rev4} {
		if _, err := h.st.GetZoneByName(context.Background(), tenantA, z); err != nil {
			t.Fatalf("zone %s deleted by sync: %v", z, err)
		}
	}
	if h.aud.count(audit.SyncDelete, audit.OutcomeOK) < 2 {
		t.Fatalf("sync.delete audit = %d", h.aud.count(audit.SyncDelete, ""))
	}
	// a second delete (duplicate) is a no-op
	before := h.patches()
	h.mustHandle(tenantA, addr1, TypeDeleted)
	if h.patches() != before {
		t.Fatal("duplicate delete wrote")
	}
}

func TestOutOfOrderConverges(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	// a stale "deleted" arrives while IPAM still has the address: IPAM wins
	h.mustHandle(tenantA, addr1, TypeDeleted)
	if !eq(h.values("example.com.", "web.example.com.", "A"), "192.0.2.10") {
		t.Fatal("stale delete not converged to IPAM state")
	}
	// a stale "created" after the address is gone removes it
	h.ipam.del(tenantA, addr1)
	h.mustHandle(tenantA, addr1, TypeCreated)
	if h.values("example.com.", "web.example.com.", "A") != nil {
		t.Fatal("stale create kept a released address")
	}
}

func TestSharedHostName(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "rr.example.com"})
	h.ipam.set(tenantA, Address{ID: addr2, Address: "192.0.2.20", SubnetID: sub4, Hostname: "rr.example.com"})
	h.mustHandle(tenantA, addr1, TypeCreated)
	h.mustHandle(tenantA, addr2, TypeCreated)
	if v := h.values("example.com.", "rr.example.com.", "A"); !eq(v, "192.0.2.10", "192.0.2.20") {
		t.Fatalf("merged A = %v", v)
	}
	h.ipam.del(tenantA, addr1)
	h.mustHandle(tenantA, addr1, TypeDeleted)
	if v := h.values("example.com.", "rr.example.com.", "A"); !eq(v, "192.0.2.20") {
		t.Fatalf("after delete A = %v", v)
	}
}

func TestTenantConfinementAndOverlap(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	h.zone(tenantB, rev4) // tenant B manages the reverse range
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})

	// an event naming tenant B for tenant A's address id: IPAM (tenant B) has nothing
	before := h.patches()
	h.mustHandle(tenantB, addr1, TypeCreated)
	if h.patches() != before {
		t.Fatal("event of tenant B touched PowerDNS")
	}

	// tenant A: forward written, PTR skipped (B's reverse zone never written)
	h.mustHandle(tenantA, addr1, TypeCreated)
	if !eq(h.values("example.com.", "web.example.com.", "A"), "192.0.2.10") {
		t.Fatal("forward missing")
	}
	if h.values(rev4, ptr4, "PTR") != nil {
		t.Fatal("PTR written into another tenant's reverse zone")
	}
	if h.aud.count(audit.SyncSkip, "") != 1 {
		t.Fatalf("sync.skip audit = %d", h.aud.count(audit.SyncSkip, ""))
	}
	if s, _ := h.state(tenantA, addr1); s.ReverseName != "" || s.ForwardName == "" {
		t.Fatalf("state = %+v", s)
	}

	// a host under another tenant's zone: forward skipped too
	h.zone(tenantB, "other.org.")
	h.ipam.set(tenantA, Address{ID: addr2, Address: "198.51.100.7", Hostname: "x.other.org"})
	h.mustHandle(tenantA, addr2, TypeCreated)
	if h.values("other.org.", "x.other.org.", "A") != nil {
		t.Fatal("wrote into another tenant's forward zone")
	}
	if _, err := h.st.GetZoneByName(context.Background(), tenantA, "other.org."); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("zone created over another tenant's: %v", err)
	}
}

func TestReverseFailureKeepsForward(t *testing.T) {
	h := newHarness(t, func(f *pdns.Fake) pdns.Client { return reverseFailing{f} })
	h.zone(tenantA, "example.com.")
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	if err := h.handle(tenantA, addr1, TypeCreated); err != nil {
		t.Fatalf("reverse failure must not fail the event: %v", err)
	}
	if !eq(h.values("example.com.", "web.example.com.", "A"), "192.0.2.10") {
		t.Fatal("forward undone by the reverse failure")
	}
	s, ok := h.state(tenantA, addr1)
	if !ok || s.ForwardName == "" || s.ReverseName != "" {
		t.Fatalf("state = %+v", s)
	}
	if h.aud.count(audit.SyncUpsert, audit.OutcomeError) != 1 {
		t.Fatalf("error audit = %d", h.aud.count(audit.SyncUpsert, audit.OutcomeError))
	}
}

func TestSubnetFallbackAndAutoZones(t *testing.T) {
	h := newHarness(t, nil)
	h.ipam.failSubnet = true
	// no tenant zone: registrable domain created (public-suffix aware)
	h.ipam.set(tenantA, Address{ID: addr1, Address: "10.1.2.3", SubnetID: sub4, Hostname: "web.newcorp.co.uk"})
	h.mustHandle(tenantA, addr1, TypeCreated)
	z, err := h.st.GetZoneByName(context.Background(), tenantA, "newcorp.co.uk.")
	if err != nil || z.Origin != store.OriginIPAM {
		t.Fatalf("auto zone = %+v %v", z, err)
	}
	if !eq(h.values("newcorp.co.uk.", "web.newcorp.co.uk.", "A"), "10.1.2.3") || !eq(h.values("2.1.10.in-addr.arpa.", "3.2.1.10.in-addr.arpa.", "PTR"), "web.newcorp.co.uk.") {
		t.Fatal("fallback /24 reverse missing")
	}
	h.ipam.set(tenantA, Address{ID: addr2, Address: "2001:db8:1:2::5", SubnetID: sub6, Hostname: "h6.newcorp.co.uk"})
	h.mustHandle(tenantA, addr2, TypeCreated)
	if _, err := h.st.GetZoneByName(context.Background(), tenantA, "2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."); err != nil {
		t.Fatalf("fallback /64 reverse zone: %v", err)
	}
	// a subnet prefix drives the size when IPAM answers
	h.ipam.failSubnet = false
	h.ipam.subnets["s16"] = Subnet{ID: "s16", CIDR: "172.16.0.0/16"}
	h.ipam.set(tenantA, Address{ID: addr3, Address: "172.16.5.9", SubnetID: "s16", Hostname: "b.newcorp.co.uk"})
	h.mustHandle(tenantA, addr3, TypeCreated)
	if !eq(h.values("16.172.in-addr.arpa.", "9.5.16.172.in-addr.arpa.", "PTR"), "b.newcorp.co.uk.") {
		t.Fatal("/16 reverse zone not used")
	}
}

func TestIgnoredAndFailures(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	before := h.patches()
	// no host name and no prior state: ignored
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4})
	h.mustHandle(tenantA, addr1, TypeCreated)
	// a bare host: skipped
	h.ipam.set(tenantA, Address{ID: addr2, Address: "192.0.2.11", SubnetID: sub4, Hostname: "printer"})
	h.mustHandle(tenantA, addr2, TypeCreated)
	if h.patches() != before {
		t.Fatalf("ignored addresses wrote: %v", h.pd.CallLog()[before:])
	}
	if _, ok := h.state(tenantA, addr1); ok {
		t.Fatal("state for an address without host name")
	}
	// IPAM unreachable: the event fails, nothing written
	h.ipam.failGet = errors.New("unavailable")
	if err := h.handle(tenantA, addr2, TypeCreated); err == nil {
		t.Fatal("IPAM failure swallowed")
	}
	h.ipam.failGet = nil
	// IPAM answers garbage
	h.ipam.set(tenantA, Address{ID: addr3, Address: "not-an-ip", Hostname: "web.example.com"})
	if err := h.handle(tenantA, addr3, TypeCreated); err == nil {
		t.Fatal("invalid IPAM address accepted")
	}
	// a store failure reading sync state fails the event
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	h.st.FailNext("GetIPAMSync")
	if err := h.handle(tenantA, addr1, TypeCreated); err == nil {
		t.Fatal("store failure swallowed")
	}
	if h.handle("", addr1, TypeCreated) == nil {
		t.Fatal("empty tenant accepted")
	}
}

func TestForwardZoneKindAndDeletedZone(t *testing.T) {
	h := newHarness(t, nil)
	sec, err := h.zs.Create(context.Background(), authz.User(tenantA, userA, nil), zones.CreateInput{Name: "sec.example.", Kind: "slave", Masters: []string{"192.0.2.53"}})
	if err != nil {
		t.Fatal(err)
	}
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.sec.example"})
	h.mustHandle(tenantA, addr1, TypeCreated)
	if s, _ := h.state(tenantA, addr1); s.ForwardName != "" || s.ReverseName == "" {
		t.Fatalf("secondary zone written: %+v", s)
	}
	_ = sec
	// the reverse zone is deleted by a user: the next event recreates it
	rz, _ := h.st.GetZoneByName(context.Background(), tenantA, rev4)
	if err := h.zs.Delete(context.Background(), authz.User(tenantA, userA, nil), rz.ID); err != nil {
		t.Fatal(err)
	}
	h.mustHandle(tenantA, addr1, TypeUpdated)
	if !eq(h.values(rev4, ptr4, "PTR"), "web.sec.example.") {
		t.Fatal("PTR not rewritten after zone deletion")
	}
}

// PowerDNS down during a rename or delete: the previous records stay in the
// state (nothing orphaned) and the next event converges.
func TestTransientFailuresKeepState(t *testing.T) {
	h := newHarness(t, nil)
	h.zone(tenantA, "example.com.")
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	h.mustHandle(tenantA, addr1, TypeCreated)

	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "api.example.com"})
	h.pd.SetDown(true)
	if err := h.handle(tenantA, addr1, TypeUpdated); err == nil {
		t.Fatal("failed removal not reported")
	}
	if s, _ := h.state(tenantA, addr1); s.ForwardName != "web.example.com." || s.ReverseName != ptr4 {
		t.Fatalf("state lost the previous records: %+v", s)
	}
	h.pd.SetDown(false)
	h.mustHandle(tenantA, addr1, TypeUpdated)
	if h.values("example.com.", "web.example.com.", "A") != nil || !eq(h.values("example.com.", "api.example.com.", "A"), "192.0.2.10") {
		t.Fatal("did not converge after recovery")
	}

	// delete while PowerDNS is down: the row stays for the retry
	h.ipam.del(tenantA, addr1)
	h.pd.SetDown(true)
	if err := h.handle(tenantA, addr1, TypeDeleted); err == nil {
		t.Fatal("failed delete not reported")
	}
	if _, ok := h.state(tenantA, addr1); !ok {
		t.Fatal("row removed although the records remain")
	}
	// cleared host name while down keeps the references too
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4})
	if err := h.handle(tenantA, addr1, TypeUpdated); err == nil {
		t.Fatal("failed clear not reported")
	}
	if s, _ := h.state(tenantA, addr1); s.ForwardName == "" {
		t.Fatalf("clear lost references: %+v", s)
	}
	h.pd.SetDown(false)
	h.mustHandle(tenantA, addr1, TypeUpdated)
	if s, _ := h.state(tenantA, addr1); s.ForwardName != "" || h.values("example.com.", "api.example.com.", "A") != nil {
		t.Fatalf("clear did not converge: %+v", s)
	}
	// a state write failure is reported
	h.ipam.set(tenantA, Address{ID: addr1, Address: "192.0.2.10", SubnetID: sub4, Hostname: "web.example.com"})
	h.st.FailNext("UpsertIPAMSync")
	if err := h.handle(tenantA, addr1, TypeUpdated); err == nil {
		t.Fatal("state failure swallowed")
	}
}
