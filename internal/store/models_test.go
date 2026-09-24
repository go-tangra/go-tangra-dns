package store

import "testing"

func TestKinds(t *testing.T) {
	for _, k := range Kinds {
		if !ValidKind(k) || KindFromPDNS(PDNSKind(k)) != k {
			t.Fatalf("kind %s round trip", k)
		}
	}
	if PDNSKind("master") != "Master" || PDNSKind("bogus") != "" || KindFromPDNS("NATIVE") != "native" || KindFromPDNS("Bogus") != "" {
		t.Fatal("pdns kind mapping")
	}
	if !NeedsMasters(KindSlave) || !NeedsMasters(KindConsumer) || NeedsMasters(KindMaster) {
		t.Fatal("needs masters")
	}
	if !ValidOrigin(OriginIPAM) || ValidOrigin("x") {
		t.Fatal("origin")
	}
	if !ValidSyncEvent(SyncReconciled) || ValidSyncEvent("moved") {
		t.Fatal("sync event")
	}
}

func TestZoneFilter(t *testing.T) {
	f := ZoneFilter{PageSize: 500}.Normalized(100)
	if f.Page != 1 || f.PageSize != 100 || f.Offset() != 0 {
		t.Fatalf("normalized = %+v", f)
	}
	f = ZoneFilter{Page: 3}.Normalized(0)
	if f.PageSize != 25 || f.Offset() != 50 {
		t.Fatalf("defaults = %+v", f)
	}
	z := Zone{Name: "lab.example.com.", Kind: KindMaster, Origin: OriginIPAM}
	if !(ZoneFilter{Query: " LAB "}).Matches(z) || (ZoneFilter{Query: "corp"}).Matches(z) {
		t.Fatal("query")
	}
	if (ZoneFilter{Kind: KindNative}).Matches(z) || !(ZoneFilter{Kind: KindMaster, Origin: OriginIPAM}).Matches(z) || (ZoneFilter{Origin: OriginManual}).Matches(z) {
		t.Fatal("kind/origin")
	}
}

func TestLongestZone(t *testing.T) {
	zs := []Zone{{Name: "example.com."}, {Name: "lab.example.com."}, {Name: "other.org."}}
	if z, ok := LongestZone(zs, "web.lab.example.com."); !ok || z.Name != "lab.example.com." {
		t.Fatalf("longest = %+v", z)
	}
	if z, ok := LongestZone(zs, "example.com."); !ok || z.Name != "example.com." {
		t.Fatal("apex")
	}
	if _, ok := LongestZone(zs, "xexample.com."); ok {
		t.Fatal("label boundary")
	}
	if !InZone("a.b.", "b.") || InZone("ab.", "b.") {
		t.Fatal("in zone")
	}
}
