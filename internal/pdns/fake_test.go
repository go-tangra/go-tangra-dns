package pdns

import (
	"errors"
	"strings"
	"testing"
)

func TestFakeZoneLifecycle(t *testing.T) {
	f := NewFake()
	z, err := f.CreateZone(ctx, Zone{Name: "example.com.", Kind: "Master", Nameservers: []string{"ns1.example.com.", "ns2.example.com."}, Account: "t1",
		RRsets: []RRset{{Name: "www.example.com.", Type: "A", TTL: 300, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.1"}}}}})
	if err != nil || z.ID != "example.com." || len(z.RRsets) != 3 || z.RRsets[0].Type != "SOA" || len(z.RRsets[1].Records) != 2 || z.RRsets[2].ChangeType != "" {
		t.Fatalf("create = %+v %v", z, err)
	}
	if _, err := f.CreateZone(ctx, Zone{Name: "example.com."}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := f.CreateZone(ctx, Zone{Name: "no-dot"}); err == nil {
		t.Fatal("non-canonical name")
	}
	if _, err := f.CreateZone(ctx, Zone{Name: "x.example.", RRsets: []RRset{{Name: "www.other.", Type: "A"}}}); err == nil {
		t.Fatal("out-of-zone rrset")
	}
	if _, err := f.CreateZone(ctx, Zone{Name: "mix.example.", Nameservers: []string{"ns1.mix.example."},
		RRsets: []RRset{{Name: "mix.example.", Type: "NS", Records: []Record{{Content: "ns2.mix.example."}}}}}); err == nil {
		t.Fatal("nameservers mixed with apex NS rrset")
	}
	bare, _ := f.CreateZone(ctx, Zone{Name: "bare.example."})
	if bare.Kind != "Native" || len(bare.RRsets) != 1 || !strings.HasPrefix(bare.RRsets[0].Records[0].Content, "a.misconfigured") {
		t.Fatalf("bare zone = %+v", bare)
	}
	names, _ := f.ListZoneNames(ctx)
	if strings.Join(names, ",") != "bare.example.,example.com." {
		t.Fatalf("names = %v", names)
	}

	// REPLACE, DELETE and serial bump
	err = f.PatchRRsets(ctx, "example.com.", []RRset{
		{Name: "www.example.com.", Type: "A", TTL: 60, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.2"}, {Content: "192.0.2.3", Disabled: true}}},
		{Name: "mail.example.com.", Type: "MX", TTL: 60, ChangeType: ChangeReplace, Records: []Record{{Content: "10 mx.example.com."}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := f.GetZone(ctx, "example.com.")
	if got.Serial != 2 || len(got.RRsets) != 4 {
		t.Fatalf("after replace = %+v", got)
	}
	if err := f.PatchRRsets(ctx, "example.com.", []RRset{{Name: "mail.example.com.", Type: "MX", ChangeType: ChangeDelete},
		{Name: "www.example.com.", Type: "A", ChangeType: ChangeReplace}}); err != nil {
		t.Fatal(err)
	}
	got, _ = f.GetZone(ctx, "example.com.")
	if got.Serial != 3 || len(got.RRsets) != 2 {
		t.Fatalf("after delete = %+v", got.RRsets)
	}
	for _, bad := range [][]RRset{
		{{Name: "www.other.", Type: "A", ChangeType: ChangeReplace}},
		{{Name: "www.example.com.", Type: "A", ChangeType: "UPSERT"}},
		{{Name: "example.com.", Type: "SOA", ChangeType: ChangeDelete}},
	} {
		if err := f.PatchRRsets(ctx, "example.com.", bad); err == nil {
			t.Fatalf("patch %+v accepted", bad)
		}
	}
	if got2, _ := f.GetZone(ctx, "example.com."); got2.Serial != 3 {
		t.Fatal("refused patch applied")
	}

	// returned zones are copies
	got.RRsets[0].Records[0].Content = "mutated"
	if again, _ := f.GetZone(ctx, "example.com."); again.RRsets[0].Records[0].Content == "mutated" {
		t.Fatal("aliasing")
	}

	if err := f.UpdateZoneMetadata(ctx, "example.com.", Zone{Kind: "Slave", Masters: []string{"192.0.2.53"}, DNSSEC: true, Account: "t2"}); err != nil {
		t.Fatal(err)
	}
	got, _ = f.GetZone(ctx, "example.com.")
	if got.Kind != "Slave" || !got.DNSSEC || got.Account != "t2" || len(got.Masters) != 1 {
		t.Fatalf("metadata = %+v", got)
	}
	_ = f.UpdateZoneMetadata(ctx, "example.com.", Zone{})
	if got, _ = f.GetZone(ctx, "example.com."); got.Kind != "Slave" || got.Account != "t2" || len(got.Masters) != 0 {
		t.Fatalf("empty metadata = %+v", got)
	}
	if err := f.NotifyZone(ctx, "example.com."); err == nil {
		t.Fatal("notify of a slave zone")
	}
	_ = f.UpdateZoneMetadata(ctx, "example.com.", Zone{Kind: "Master"})
	if err := f.NotifyZone(ctx, "example.com."); err != nil {
		t.Fatal(err)
	}
	if got, _ = f.GetZone(ctx, "example.com."); got.NotifiedSerial != got.Serial {
		t.Fatal("notified serial")
	}

	_ = f.PatchRRsets(ctx, "example.com.", []RRset{{Name: "b.example.com.", Type: "TXT", TTL: 60, ChangeType: ChangeReplace,
		Records: []Record{{Content: `"x"`}, {Content: `"hidden"`, Disabled: true}}},
		{Name: "a.example.com.", Type: "A", TTL: 60, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.9"}}}})
	text, err := f.ExportZone(ctx, "example.com.")
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if err != nil || !strings.Contains(lines[0], "\tSOA\t") || !strings.HasPrefix(lines[1], "a.example.com.\t60\tIN\tA\t192.0.2.9") || strings.Contains(text, "hidden") {
		t.Fatalf("export = %q %v", text, err)
	}

	for name, call := range map[string]func() error{
		"get":    func() error { _, err := f.GetZone(ctx, "nope."); return err },
		"update": func() error { return f.UpdateZoneMetadata(ctx, "nope.", Zone{}) },
		"delete": func() error { return f.DeleteZone(ctx, "nope.") },
		"patch":  func() error { return f.PatchRRsets(ctx, "nope.", nil) },
		"notify": func() error { return f.NotifyZone(ctx, "nope.") },
		"export": func() error { _, err := f.ExportZone(ctx, "nope."); return err },
	} {
		if err := call(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := f.DeleteZone(ctx, "example.com."); err != nil {
		t.Fatal(err)
	}
	if log := f.CallLog(); log[0] != "CreateZone example.com." || log[len(log)-1] != "DeleteZone example.com." {
		t.Fatalf("call log = %v", log)
	}
}

func TestFakeSupermastersAndFailures(t *testing.T) {
	f := NewFake()
	sm := Supermaster{IP: "192.0.2.53", Nameserver: "ns1.example.net.", Account: "t1"}
	if err := f.CreateSupermaster(ctx, sm); err != nil {
		t.Fatal(err)
	}
	if err := f.CreateSupermaster(ctx, sm); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup: %v", err)
	}
	list, _ := f.ListSupermasters(ctx)
	if len(list) != 1 || list[0].Account != "t1" {
		t.Fatalf("list = %+v", list)
	}
	if err := f.DeleteSupermaster(ctx, "192.0.2.53", "ns1.example.net."); err != nil {
		t.Fatal(err)
	}
	if err := f.DeleteSupermaster(ctx, "192.0.2.53", "ns1.example.net."); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}

	boom := errors.New("boom")
	f.FailNext("CreateZone", boom)
	if _, err := f.CreateZone(ctx, Zone{Name: "a."}); !errors.Is(err, boom) {
		t.Fatal("injected failure")
	}
	if _, err := f.CreateZone(ctx, Zone{Name: "a."}); err != nil {
		t.Fatal("failure not disarmed")
	}
	f.SetDown(true)
	for name, call := range map[string]func() error{
		"ping":   func() error { return f.Ping(ctx) },
		"list":   func() error { _, err := f.ListZoneNames(ctx); return err },
		"get":    func() error { _, err := f.GetZone(ctx, "a."); return err },
		"create": func() error { _, err := f.CreateZone(ctx, Zone{Name: "b."}); return err },
		"update": func() error { return f.UpdateZoneMetadata(ctx, "a.", Zone{}) },
		"delete": func() error { return f.DeleteZone(ctx, "a.") },
		"patch":  func() error { return f.PatchRRsets(ctx, "a.", nil) },
		"notify": func() error { return f.NotifyZone(ctx, "a.") },
		"export": func() error { _, err := f.ExportZone(ctx, "a."); return err },
		"sm ls":  func() error { _, err := f.ListSupermasters(ctx); return err },
		"sm add": func() error { return f.CreateSupermaster(ctx, sm) },
		"sm del": func() error { return f.DeleteSupermaster(ctx, "x", "y") },
	} {
		if err := call(); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s while down: %v", name, err)
		}
	}
	f.SetDown(false)
	if err := f.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateAndSeed(t *testing.T) {
	z := GenerateZone("big.example.", 5000)
	if len(z.RRsets) != 5002 || z.RRsets[2].Name != "host00000.big.example." || z.RRsets[5001].Records[0].Content != "10.0.19.135" {
		t.Fatalf("generated = %d %+v", len(z.RRsets), z.RRsets[5001])
	}
	f := NewFake()
	f.Seed(z)
	f.Seed(Zone{Name: "outside.example."})
	got, err := f.GetZone(ctx, "big.example.")
	if err != nil || len(got.RRsets) != 5002 {
		t.Fatalf("seeded = %d %v", len(got.RRsets), err)
	}
	if _, err := f.GetZone(ctx, "outside.example."); err != nil {
		t.Fatal("seed id default")
	}
	var ae *APIError
	if err := notFound("x"); !errors.As(err, &ae) || ae.Error() != "pdns: status 404: Could not find x" {
		t.Fatalf("api error text = %v", err)
	}
	if (&APIError{Status: 502}).Error() != "pdns: status 502" {
		t.Fatal("bare api error text")
	}
}

// REPLACE without a comment list keeps the rrset's comments (PowerDNS
// semantics); an explicit empty list clears them.
func TestFakeReplaceComments(t *testing.T) {
	f := NewFake()
	if _, err := f.CreateZone(ctx, Zone{Name: "example.com."}); err != nil {
		t.Fatal(err)
	}
	get := func() RRset {
		z, _ := f.GetZone(ctx, "example.com.")
		for _, r := range z.RRsets {
			if r.Name == "www.example.com." && r.Type == "A" {
				return r
			}
		}
		t.Fatal("rrset missing")
		return RRset{}
	}
	rr := RRset{Name: "www.example.com.", Type: "A", TTL: 60, ChangeType: ChangeReplace, Records: []Record{{Content: "192.0.2.2"}}}
	withComment := rr
	withComment.Comments = []Comment{{Content: "web"}}
	if err := f.PatchRRsets(ctx, "example.com.", []RRset{withComment}); err != nil || len(get().Comments) != 1 {
		t.Fatalf("set comment: %v %+v", err, get())
	}
	if err := f.PatchRRsets(ctx, "example.com.", []RRset{rr}); err != nil || len(get().Comments) != 1 {
		t.Fatalf("nil comments must keep: %v %+v", err, get())
	}
	cleared := rr
	cleared.Comments = []Comment{}
	if err := f.PatchRRsets(ctx, "example.com.", []RRset{cleared}); err != nil || len(get().Comments) != 0 {
		t.Fatalf("empty comments must clear: %v %+v", err, get())
	}
}
