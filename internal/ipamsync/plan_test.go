package ipamsync

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

func zonesOf(names ...string) []store.Zone {
	out := make([]store.Zone, 0, len(names))
	for i, n := range names {
		out = append(out, store.Zone{ID: "z" + string(rune('a'+i)), Name: n, Kind: store.KindNative})
	}
	return out
}

func TestCanonicalHost(t *testing.T) {
	for in, want := range map[string]string{
		"web.example.com":   "web.example.com.",
		" Web.Example.COM.": "web.example.com.",
		"a.b.c.example.org": "a.b.c.example.org.",
	} {
		if got, ok := CanonicalHost(in); !ok || got != want {
			t.Errorf("CanonicalHost(%q) = %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "web", "web.", "1.2.3.4", "_sip.example.com", "a..b.com", "*.example.com", "x.in-addr.arpa", "1.0.ip6.arpa", "exa mple.com"} {
		if got, ok := CanonicalHost(bad); ok {
			t.Errorf("CanonicalHost(%q) = %q, want refusal", bad, got)
		}
	}
}

func TestPlanForward(t *testing.T) {
	v4, v6 := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")
	tz := zonesOf("example.com.", "lab.example.com.", "2.0.192.in-addr.arpa.")

	f, err := PlanForward(tz, "web.lab.example.com.", v4)
	if err != nil || f.Zone != "lab.example.com." || f.ZoneID != "zb" || !f.Existing || f.Name != "web.lab.example.com." || f.Type != "A" {
		t.Fatalf("longest suffix = %+v %v", f, err)
	}
	f, err = PlanForward(tz, "example.com.", v6)
	if err != nil || f.Zone != "example.com." || f.Type != "AAAA" || f.Name != "example.com." {
		t.Fatalf("apex AAAA = %+v %v", f, err)
	}
	// suffix match is label-wise, not a string suffix
	f, err = PlanForward(tz, "web.notexample.com.", v4)
	if err != nil || f.Existing || f.Zone != "notexample.com." {
		t.Fatalf("label-wise = %+v %v", f, err)
	}
	// registrable domain (public-suffix aware)
	f, err = PlanForward(nil, "web.newcorp.co.uk.", v4)
	if err != nil || f.Existing || f.Zone != "newcorp.co.uk." || f.ZoneID != "" || f.Name != "web.newcorp.co.uk." {
		t.Fatalf("registrable = %+v %v", f, err)
	}
	f, err = PlanForward(nil, "a.b.example.github.io.", v6)
	if err != nil || f.Zone != "example.github.io." {
		t.Fatalf("private suffix = %+v %v", f, err)
	}
	// a public suffix itself, or a bare/invalid host, is skipped
	for _, h := range []string{"co.uk.", "com.", "github.io.", "web", ""} {
		if _, err := PlanForward(nil, h, v4); !errors.Is(err, ErrSkip) {
			t.Errorf("PlanForward(%q) = %v, want ErrSkip", h, err)
		}
	}
	if _, err := PlanForward(tz, "web.example.com.", netip.Addr{}); !errors.Is(err, ErrSkip) {
		t.Fatalf("invalid address = %v", err)
	}
	// v4-mapped v6 is written as A
	if f, _ := PlanForward(tz, "m.example.com.", netip.MustParseAddr("::ffff:192.0.2.1")); f.Type != "A" {
		t.Fatalf("mapped = %+v", f)
	}
}

func TestPTROwner(t *testing.T) {
	if got := PTROwner(netip.MustParseAddr("192.0.2.10")); got != "10.2.0.192.in-addr.arpa." {
		t.Fatalf("v4 = %q", got)
	}
	want := "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	if got := PTROwner(netip.MustParseAddr("2001:db8::10")); got != want {
		t.Fatalf("v6 = %q", got)
	}
	if got := PTROwner(netip.MustParseAddr("::ffff:10.1.2.3")); got != "3.2.1.10.in-addr.arpa." {
		t.Fatalf("mapped = %q", got)
	}
}

func TestReverseZoneSizing(t *testing.T) {
	a4 := netip.MustParseAddr("10.20.30.40")
	for prefix, want := range map[int]string{
		0: "10.in-addr.arpa.", 4: "10.in-addr.arpa.", 8: "10.in-addr.arpa.", 12: "10.in-addr.arpa.",
		16: "20.10.in-addr.arpa.", 22: "20.10.in-addr.arpa.", 24: "30.20.10.in-addr.arpa.",
		26: "30.20.10.in-addr.arpa.", 32: "30.20.10.in-addr.arpa.",
		-1: "30.20.10.in-addr.arpa.", 33: "30.20.10.in-addr.arpa.", // invalid → /24 fallback
	} {
		if got := ReverseZone(a4, prefix); got != want {
			t.Errorf("v4 /%d = %q, want %q", prefix, got, want)
		}
	}
	a6 := netip.MustParseAddr("2001:db8:abcd:12::1")
	for prefix, want := range map[int]string{
		0:   "2.ip6.arpa.",
		4:   "2.ip6.arpa.",
		7:   "2.ip6.arpa.",
		32:  "8.b.d.0.1.0.0.2.ip6.arpa.",
		48:  "d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa.",
		50:  "d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa.",
		64:  "2.1.0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa.",
		128: "2.1.0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa.",
		-5:  "2.1.0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa.", // invalid → /64 fallback
		129: "2.1.0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa.",
	} {
		if got := ReverseZone(a6, prefix); got != want {
			t.Errorf("v6 /%d = %q, want %q", prefix, got, want)
		}
	}
	if got := ReverseZone(netip.Addr{}, 24); got != "" {
		t.Fatalf("invalid addr = %q", got)
	}
}

func TestPlanReverse(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.10")
	// new zone sized from the prefix
	r, err := PlanReverse(zonesOf("example.com."), a, 24)
	if err != nil || r.Existing || r.Zone != "2.0.192.in-addr.arpa." || r.Owner != "10.2.0.192.in-addr.arpa." {
		t.Fatalf("new = %+v %v", r, err)
	}
	// an existing longer (more specific) reverse zone of the tenant wins
	tz := zonesOf("0.192.in-addr.arpa.", "10.2.0.192.in-addr.arpa.")
	r, err = PlanReverse(tz, a, 16)
	if err != nil || !r.Existing || r.Zone != "10.2.0.192.in-addr.arpa." || r.ZoneID != "zb" {
		t.Fatalf("longer existing = %+v %v", r, err)
	}
	// an existing containing zone is reused rather than nesting a new one
	r, err = PlanReverse(zonesOf("192.in-addr.arpa."), a, 24)
	if err != nil || !r.Existing || r.Zone != "192.in-addr.arpa." {
		t.Fatalf("containing existing = %+v %v", r, err)
	}
	// forward zones never match
	r, _ = PlanReverse(zonesOf("in-addr.arpa.example.com."), a, 24)
	if r.Existing {
		t.Fatalf("forward matched = %+v", r)
	}
	if _, err := PlanReverse(nil, netip.Addr{}, 24); !errors.Is(err, ErrSkip) {
		t.Fatalf("invalid = %v", err)
	}
	// v6
	r, err = PlanReverse(nil, netip.MustParseAddr("2001:db8::10"), 64)
	if err != nil || r.Zone != "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." || len(r.Owner) != 73 {
		t.Fatalf("v6 = %+v %v", r, err)
	}
}

func TestPrefixOf(t *testing.T) {
	for cidr, want := range map[string]int{"10.0.0.0/22": 22, "2001:db8::/48": 48, " 192.0.2.0/24 ": 24, "garbage": -1, "": -1, "10.0.0.1": -1} {
		if got := PrefixOf(cidr); got != want {
			t.Errorf("PrefixOf(%q) = %d, want %d", cidr, got, want)
		}
	}
}
