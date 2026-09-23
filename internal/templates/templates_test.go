package templates

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
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

func rec(name, typ string, ttl int, content string, prio int) store.TemplateRecord {
	return store.TemplateRecord{Name: name, Type: typ, TTL: ttl, Content: content, Priority: prio}
}

func standard() Input {
	return Input{Name: "Standard", Description: "NS, MX and SPF", Records: []store.TemplateRecord{
		rec("@", "NS", 3600, "ns1.[ZONE].", 0),
		rec("", "NS", 3600, "ns2.[ZONE].", 0),
		rec("@", "MX", 3600, "mail.[ZONE].", 10),
		rec("@", "MX", 3600, "20 backup.example.net.", 0),
		rec("_sip._tcp", "SRV", 3600, "5 5060 sip.[ZONE].", 30),
		rec("@", "TXT", 3600, "v=spf1 mx include:[ZONE] -all", 0),
		rec("www.[ZONE].", "CNAME", 300, "[ZONE].", 0),
		rec("mail", "A", 300, "192.0.2.25", 0),
	}}
}

func newSvc() (*Service, *memstore.Mem, *auditLog) {
	st, aud := memstore.New(), &auditLog{}
	return New(Deps{Store: st, Audit: aud}), st, aud
}

var userSubj = authz.User(tenantA, userA, nil)

func TestCRUD(t *testing.T) {
	svc, _, aud := newSvc()
	ctx := context.Background()
	tpl, err := svc.Create(ctx, userSubj, standard())
	if err != nil || tpl.ID == "" || tpl.TenantID != tenantA || tpl.Name != "Standard" || len(tpl.Records) != 8 {
		t.Fatalf("create = %+v %v", tpl, err)
	}
	// records are stored as submitted (types upper-cased, names trimmed)
	if tpl.Records[2].Priority != 10 || tpl.Records[0].Name != "@" {
		t.Fatalf("records = %+v", tpl.Records)
	}
	// per-tenant, case-insensitive unique name
	if _, err := svc.Create(ctx, userSubj, Input{Name: "  standard ", Records: nil}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	if _, err := svc.Create(ctx, authz.User(tenantB, userA, nil), Input{Name: "Standard"}); err != nil {
		t.Fatalf("other tenant same name: %v", err)
	}
	list, err := svc.List(ctx, userSubj)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	got, err := svc.Get(ctx, userSubj, tpl.ID)
	if err != nil || got.ID != tpl.ID {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := svc.Get(ctx, authz.User(tenantB, userA, nil), tpl.ID); !errors.Is(err, ErrNotFound) || !errors.Is(err, zones.ErrTemplateNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
	// update replaces the record list
	up, err := svc.Update(ctx, userSubj, tpl.ID, Input{Name: "Minimal", Records: []store.TemplateRecord{rec("@", "TXT", 3600, "hello", 0)}})
	if err != nil || up.Name != "Minimal" || len(up.Records) != 1 || up.Description != "" {
		t.Fatalf("update = %+v %v", up, err)
	}
	other, _ := svc.Create(ctx, userSubj, Input{Name: "Other"})
	if _, err := svc.Update(ctx, userSubj, other.ID, Input{Name: "MINIMAL"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("rename onto existing = %v", err)
	}
	if _, err := svc.Update(ctx, userSubj, "nope", Input{Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing = %v", err)
	}
	if err := svc.Delete(ctx, userSubj, tpl.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, userSubj, tpl.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice = %v", err)
	}
	var kinds []string
	for _, e := range aud.events {
		kinds = append(kinds, string(e.EventType)+":"+e.Outcome)
	}
	if !strings.Contains(strings.Join(kinds, ","), "template.create:ok") || !strings.Contains(strings.Join(kinds, ","), "template.update:refused") ||
		!strings.Contains(strings.Join(kinds, ","), "template.delete:ok") {
		t.Fatalf("audit = %v", kinds)
	}
}

func TestValidationAtSave(t *testing.T) {
	svc, _, _ := newSvc()
	ctx := context.Background()
	many := make([]store.TemplateRecord, store.MaxTemplateRecords+1)
	for i := range many {
		many[i] = rec("@", "TXT", 3600, "x", 0)
	}
	for name, in := range map[string]Input{
		"empty name":   {Name: "  "},
		"long name":    {Name: strings.Repeat("n", 101)},
		"control name": {Name: "a\nb"},
		"long desc":    {Name: "x", Description: strings.Repeat("d", 1001)},
		"too many":     {Name: "x", Records: many},
		"bad type":     {Name: "x", Records: []store.TemplateRecord{rec("@", "SOA", 3600, "x", 0)}},
		"bad content":  {Name: "x", Records: []store.TemplateRecord{rec("@", "A", 3600, "not-an-ip", 0)}},
		"bad ttl":      {Name: "x", Records: []store.TemplateRecord{rec("@", "A", 1, "192.0.2.1", 0)}},
		"out of zone":  {Name: "x", Records: []store.TemplateRecord{rec("www.elsewhere.org.", "A", 3600, "192.0.2.1", 0)}},
		"apex cname":   {Name: "x", Records: []store.TemplateRecord{rec("@", "CNAME", 3600, "other.org.", 0)}},
		"cname + a":    {Name: "x", Records: []store.TemplateRecord{rec("w", "CNAME", 3600, "other.org.", 0), rec("w", "A", 3600, "192.0.2.1", 0)}},
		"prio twice":   {Name: "x", Records: []store.TemplateRecord{rec("@", "MX", 3600, "10 mail.[ZONE].", 20)}},
		"prio range":   {Name: "x", Records: []store.TemplateRecord{rec("@", "MX", 3600, "mail.[ZONE].", 70000)}},
		"prio on A":    {Name: "x", Records: []store.TemplateRecord{rec("@", "A", 3600, "192.0.2.1", 5)}},
		"dup value":    {Name: "x", Records: []store.TemplateRecord{rec("@", "A", 3600, "192.0.2.1", 0), rec("@", "A", 3600, "192.0.2.1", 0)}},
		"directive":    {Name: "x", Records: []store.TemplateRecord{rec("@", "TXT", 3600, "$INCLUDE /etc/passwd", 0)}},
	} {
		_, err := svc.Create(ctx, userSubj, in)
		var re *validate.RecordError
		if err == nil || !(errors.Is(err, ErrInvalid) || errors.As(err, &re)) {
			t.Errorf("%s: %v", name, err)
		}
		if errors.As(err, &re) && !strings.HasPrefix(re.Field, "records[") {
			t.Errorf("%s: field %q not indexed", name, re.Field)
		}
	}
}

func TestExpand(t *testing.T) {
	svc, _, _ := newSvc()
	ctx := context.Background()
	tpl, err := svc.Create(ctx, userSubj, standard())
	if err != nil {
		t.Fatal(err)
	}
	sets, err := svc.Expand(ctx, tenantA, tpl.ID, "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]pdns.RRset{}
	for _, s := range sets {
		if s.ChangeType != pdns.ChangeReplace {
			t.Fatalf("changetype = %+v", s)
		}
		byKey[s.Name+" "+s.Type] = s
	}
	check := func(key string, want ...string) {
		t.Helper()
		s, ok := byKey[key]
		if !ok {
			t.Fatalf("missing %s in %+v", key, sets)
		}
		var got []string
		for _, r := range s.Records {
			got = append(got, r.Content)
		}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("%s = %v, want %v", key, got, want)
		}
	}
	check("example.com. NS", "ns1.example.com.", "ns2.example.com.") // "@" and "" merged into one rrset
	check("example.com. MX", "10 mail.example.com.", "20 backup.example.net.")
	check("_sip._tcp.example.com. SRV", "30 5 5060 sip.example.com.")
	check("example.com. TXT", `"v=spf1 mx include:example.com -all"`)
	check("www.example.com. CNAME", "example.com.")
	check("mail.example.com. A", "192.0.2.25")
	if len(sets) != 6 {
		t.Fatalf("sets = %d", len(sets))
	}
	// deterministic order
	again, _ := svc.Expand(ctx, tenantA, tpl.ID, "example.com.")
	for i := range again {
		if again[i].Name != sets[i].Name || again[i].Type != sets[i].Type {
			t.Fatal("expansion order not deterministic")
		}
	}
	// other tenant / unknown: template_not_found
	if _, err := svc.Expand(ctx, tenantB, tpl.ID, "example.com."); !errors.Is(err, zones.ErrTemplateNotFound) {
		t.Fatalf("cross tenant = %v", err)
	}
	// re-validated against the real zone: a name that becomes too long is refused
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".ex."
	if _, err := svc.Expand(ctx, tenantA, tpl.ID, long); err == nil {
		t.Fatal("over-long expansion accepted")
	}
	if _, err := svc.Expand(ctx, tenantA, tpl.ID, "not a zone"); err == nil {
		t.Fatal("invalid zone accepted")
	}
}

func TestExpandRecordsPure(t *testing.T) {
	sets, err := ExpandRecords(validate.DefaultLimits, "Example.ORG", []store.TemplateRecord{
		rec("[ZONE].", "A", 300, "192.0.2.1", 0),
		rec("host", "AAAA", 300, "2001:db8::1", 0),
		rec("host", "AAAA", 600, "2001:db8::2", 0), // merged; the first TTL wins
	})
	if err != nil || len(sets) != 2 || sets[0].Name != "example.org." || sets[1].TTL != 300 || len(sets[1].Records) != 2 {
		t.Fatalf("pure = %+v %v", sets, err)
	}
	if sets, err := ExpandRecords(validate.DefaultLimits, "example.org.", nil); err != nil || len(sets) != 0 {
		t.Fatalf("empty = %+v %v", sets, err)
	}
}

func TestStoreFailuresAndPermissions(t *testing.T) {
	st, aud := memstore.New(), &auditLog{}
	checker := authz.Static{userA: {authz.ZonesRead}}
	svc := New(Deps{Store: st, Audit: aud, Checker: checker})
	ctx := context.Background()
	if _, err := svc.Create(ctx, userSubj, Input{Name: "x"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer create = %v", err)
	}
	if _, err := svc.List(ctx, userSubj); err != nil {
		t.Fatalf("viewer list = %v", err)
	}
	if _, err := svc.List(ctx, authz.Subjects{}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no tenant = %v", err)
	}
	if _, err := svc.Create(ctx, authz.Module(tenantA, "spiffe://example.org/svc/x"), Input{Name: "x"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("module create = %v", err)
	}
	svc = New(Deps{Store: st})
	for _, m := range []string{"CreateTemplate", "ListTemplates", "GetTemplate", "UpdateTemplate", "DeleteTemplate"} {
		st.FailNext(m)
		var err error
		switch m {
		case "CreateTemplate":
			_, err = svc.Create(ctx, userSubj, Input{Name: "x"})
		case "ListTemplates":
			_, err = svc.List(ctx, userSubj)
		case "GetTemplate":
			_, err = svc.Get(ctx, userSubj, "x")
		case "UpdateTemplate":
			tpl, _ := svc.Create(ctx, userSubj, Input{Name: "u-" + m})
			st.FailNext(m)
			_, err = svc.Update(ctx, userSubj, tpl.ID, Input{Name: "u2"})
		case "DeleteTemplate":
			err = svc.Delete(ctx, userSubj, "x")
		}
		if err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("%s failure = %v", m, err)
		}
	}
	st.FailNext("GetTemplate")
	if _, err := svc.Expand(ctx, tenantA, "x", "example.com."); err == nil || errors.Is(err, zones.ErrTemplateNotFound) {
		t.Fatalf("expand store failure = %v", err)
	}
}
