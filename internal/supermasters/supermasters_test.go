package supermasters

import (
	"context"
	"errors"
	"testing"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
	adminA  = "33333333-3333-7333-8333-333333333333"
	ownerA  = "44444444-4444-7444-8444-444444444444"
	adminB  = "55555555-5555-7555-8555-555555555555"
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
	svc *Service
	st  *memstore.Mem
	pd  *pdns.Fake
	aud *auditLog
}

var (
	platformA = authz.User(tenantA, adminA, []string{authz.RolePlatformAdmin})
	tenantAdm = authz.User(tenantA, ownerA, []string{"owner", "admin"})
	platformB = authz.User(tenantB, adminB, []string{authz.RolePlatformAdmin})
)

func newHarness() *harness {
	h := &harness{st: memstore.New(), pd: pdns.NewFake(), aud: &auditLog{}}
	perms := []string{authz.SupermastersManage, authz.ZonesRead}
	h.svc = New(Deps{Store: h.st, PDNS: h.pd, Audit: h.aud, Checker: authz.Static{adminA: perms, ownerA: perms, adminB: perms}})
	return h
}

func (h *harness) pdnsRows() []pdns.Supermaster {
	l, _ := h.pd.ListSupermasters(context.Background())
	return l
}

func TestCreateListGetDelete(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	sm, err := h.svc.Create(ctx, platformA, Input{IP: " 192.0.2.53 ", Nameserver: "NS1.Primary.Example"})
	if err != nil || sm.ID == "" || sm.TenantID != tenantA || sm.IP != "192.0.2.53" || sm.Nameserver != "ns1.primary.example." || sm.CreatedBy != adminA {
		t.Fatalf("create = %+v %v", sm, err)
	}
	rows := h.pdnsRows()
	if len(rows) != 1 || rows[0].IP != "192.0.2.53" || rows[0].Nameserver != "ns1.primary.example" || rows[0].Account != tenantA {
		t.Fatalf("PowerDNS rows = %+v (account forced to the tenant)", rows)
	}
	list, err := h.svc.List(ctx, tenantAdm)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if list, _ := h.svc.List(ctx, platformB); len(list) != 0 {
		t.Fatalf("other tenant sees rows: %+v", list)
	}
	if got, err := h.svc.Get(ctx, tenantAdm, sm.ID); err != nil || got.ID != sm.ID {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := h.svc.Get(ctx, platformB, sm.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
	// (ip, nameserver) is globally unique — also across tenants
	if _, err := h.svc.Create(ctx, platformB, Input{IP: "192.0.2.53", Nameserver: "ns1.primary.example."}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	if len(h.pdnsRows()) != 1 {
		t.Fatal("duplicate reached PowerDNS")
	}
	if _, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.53", Nameserver: "ns2.primary.example."}); err != nil {
		t.Fatalf("same ip other nameserver: %v", err)
	}
	if err := h.svc.Delete(ctx, platformB, sm.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v", err)
	}
	if err := h.svc.Delete(ctx, platformA, sm.ID); err != nil {
		t.Fatal(err)
	}
	if len(h.pdnsRows()) != 1 {
		t.Fatalf("PowerDNS rows after delete = %+v", h.pdnsRows())
	}
	if _, err := h.svc.Get(ctx, platformA, sm.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted get = %v", err)
	}
	ok := 0
	for _, e := range h.aud.events {
		if (e.EventType == audit.SupermasterCreate || e.EventType == audit.SupermasterDelete) && e.Outcome == audit.OutcomeOK {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("audit = %+v", h.aud.events)
	}
}

func TestPlatformAdminRequired(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	if _, err := h.svc.Create(ctx, tenantAdm, Input{IP: "192.0.2.53", Nameserver: "ns1.example.com"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("tenant admin create = %v", err)
	}
	sm, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.53", Nameserver: "ns1.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Delete(ctx, tenantAdm, sm.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("tenant admin delete = %v", err)
	}
	// platform-admin without the API permission
	noPerm := authz.User(tenantA, "66666666-6666-7666-8666-666666666666", []string{authz.RolePlatformAdmin})
	if _, err := h.svc.Create(ctx, noPerm, Input{IP: "192.0.2.54", Nameserver: "ns1.example.com"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no permission create = %v", err)
	}
	if _, err := h.svc.List(ctx, noPerm); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no permission list = %v", err)
	}
	for _, subj := range []authz.Subjects{authz.Module(tenantA, "spiffe://example.org/svc/x"), authz.SystemFor(tenantA)} {
		if _, err := h.svc.Create(ctx, subj, Input{IP: "192.0.2.55", Nameserver: "ns1.example.com"}); !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("%s create = %v", subj.ActorKind, err)
		}
	}
	if _, err := h.svc.List(ctx, authz.Subjects{}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no tenant = %v", err)
	}
	// the system scope may (backup restore)
	if _, err := h.svc.Create(ctx, authz.Internal(tenantA), Input{IP: "192.0.2.56", Nameserver: "ns1.example.com"}); err != nil {
		t.Fatalf("system create = %v", err)
	}
}

func TestIPGuardAndNameserver(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	for _, in := range []Input{
		{IP: "127.0.0.1", Nameserver: "ns1.example.com"},
		{IP: "169.254.1.1", Nameserver: "ns1.example.com"},
		{IP: "::1", Nameserver: "ns1.example.com"},
		{IP: "0.0.0.0", Nameserver: "ns1.example.com"},
		{IP: "224.0.0.1", Nameserver: "ns1.example.com"},
		{IP: "fe80::1", Nameserver: "ns1.example.com"},
		{IP: "192.0.2.1:53", Nameserver: "ns1.example.com"},
		{IP: "ns.example.com", Nameserver: "ns1.example.com"},
		{IP: "192.0.2.1", Nameserver: "ns1"},
		{IP: "192.0.2.1", Nameserver: "_x.example.com"},
		{IP: "192.0.2.1", Nameserver: "10.0.0.1"},
		{IP: "192.0.2.1", Nameserver: ""},
	} {
		_, err := h.svc.Create(ctx, platformA, in)
		if !errors.Is(err, validate.ErrMasters) && !errors.Is(err, validate.ErrName) {
			t.Errorf("%+v = %v", in, err)
		}
	}
	if len(h.pdnsRows()) != 0 {
		t.Fatal("invalid input reached PowerDNS")
	}
	// IPv6 and v4-mapped are canonicalised
	sm, err := h.svc.Create(ctx, platformA, Input{IP: "2001:DB8::53", Nameserver: "ns1.example.com"})
	if err != nil || sm.IP != "2001:db8::53" {
		t.Fatalf("v6 = %+v %v", sm, err)
	}
	sm, err = h.svc.Create(ctx, platformA, Input{IP: "::ffff:198.51.100.1", Nameserver: "ns1.example.com"})
	if err != nil || sm.IP != "198.51.100.1" {
		t.Fatalf("mapped = %+v %v", sm, err)
	}
}

func TestCompensation(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	// PowerDNS first: a PowerDNS failure leaves no local row
	h.pd.FailNext("CreateSupermaster", pdns.ErrUnavailable)
	if _, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.53", Nameserver: "ns1.example.com"}); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("pdns failure = %v", err)
	}
	if l, _ := h.svc.List(ctx, platformA); len(l) != 0 {
		t.Fatal("local row without PowerDNS entry")
	}
	h.pd.FailNext("CreateSupermaster", &pdns.APIError{Status: 422, Message: "bad"})
	if _, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.53", Nameserver: "ns1.example.com"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("pdns refusal = %v", err)
	}
	// a local failure removes the PowerDNS entry again
	h.st.FailNext("CreateSupermaster")
	if _, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.53", Nameserver: "ns1.example.com"}); err == nil {
		t.Fatal("local failure ignored")
	}
	if len(h.pdnsRows()) != 0 {
		t.Fatalf("PowerDNS orphan: %+v", h.pdnsRows())
	}
	// exists in PowerDNS only (created outside the platform): duplicate, not adopted
	_ = h.pd.CreateSupermaster(ctx, pdns.Supermaster{IP: "192.0.2.99", Nameserver: "ns9.example.com", Account: "x"})
	if _, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.99", Nameserver: "ns9.example.com"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("outside entry = %v", err)
	}
	if len(h.pdnsRows()) != 1 {
		t.Fatal("outside entry removed by compensation")
	}

	sm, err := h.svc.Create(ctx, platformA, Input{IP: "192.0.2.53", Nameserver: "ns1.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// delete: PowerDNS failure keeps the local row
	h.pd.FailNext("DeleteSupermaster", pdns.ErrUnavailable)
	if err := h.svc.Delete(ctx, platformA, sm.ID); !errors.Is(err, pdns.ErrUnavailable) {
		t.Fatalf("pdns delete failure = %v", err)
	}
	if _, err := h.svc.Get(ctx, platformA, sm.ID); err != nil {
		t.Fatal("local row removed although PowerDNS kept the entry")
	}
	// a local failure re-creates the PowerDNS entry
	h.st.FailNext("DeleteSupermaster")
	if err := h.svc.Delete(ctx, platformA, sm.ID); err == nil {
		t.Fatal("local delete failure ignored")
	}
	if len(h.pdnsRows()) != 2 {
		t.Fatalf("PowerDNS entry not restored: %+v", h.pdnsRows())
	}
	// PowerDNS no longer has it: the local row is still removed
	_ = h.pd.DeleteSupermaster(ctx, "192.0.2.53", "ns1.example.com")
	if err := h.svc.Delete(ctx, platformA, sm.ID); err != nil {
		t.Fatalf("delete with PowerDNS entry gone = %v", err)
	}
	// store read failures
	h.st.FailNext("ListSupermasters")
	if _, err := h.svc.List(ctx, platformA); err == nil {
		t.Fatal("list failure swallowed")
	}
	h.st.FailNext("GetSupermaster")
	if err := h.svc.Delete(ctx, platformA, "x"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("get failure = %v", err)
	}
}
