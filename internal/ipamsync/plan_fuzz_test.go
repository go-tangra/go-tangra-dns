package ipamsync

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
)

// T046 fuzz: any IP and any prefix yield a reverse zone that is a valid zone
// name containing the PTR owner; any host either plans inside its zone or is
// skipped.
func FuzzReversePlan(f *testing.F) {
	f.Add([]byte{192, 0, 2, 10}, 24)
	f.Add([]byte{10, 0, 0, 1}, 3)
	f.Add(netip.MustParseAddr("2001:db8::1").AsSlice(), 64)
	f.Add(netip.MustParseAddr("::ffff:10.0.0.1").AsSlice(), 100)
	f.Add([]byte{0, 0, 0, 0}, -7)
	f.Fuzz(func(t *testing.T, raw []byte, prefix int) {
		a, ok := netip.AddrFromSlice(raw)
		if !ok {
			return
		}
		owner := PTROwner(a)
		zone := ReverseZone(a, prefix)
		if !store.InZone(owner, zone) {
			t.Fatalf("owner %q not in zone %q (addr %s /%d)", owner, zone, a, prefix)
		}
		if z, err := validate.ZoneName(zone); err != nil || z != zone {
			t.Fatalf("zone %q invalid: %v", zone, err)
		}
		if _, err := validate.RecordName(zone, owner); err != nil {
			t.Fatalf("owner %q invalid in %q: %v", owner, zone, err)
		}
		r, err := PlanReverse([]store.Zone{{ID: "x", Name: zone}}, a, prefix)
		if err != nil || !r.Existing || r.Zone != zone {
			t.Fatalf("existing zone not reused: %+v %v", r, err)
		}
	})
}

func FuzzForwardPlan(f *testing.F) {
	for _, s := range []string{"web.example.com", "web.newcorp.co.uk.", "co.uk", "web", "a.b.github.io", "x..y", "UPPER.Example.ORG"} {
		f.Add(s, "example.com.")
	}
	f.Fuzz(func(t *testing.T, host, zone string) {
		if len(host) > 300 || len(zone) > 300 {
			return
		}
		var tz []store.Zone
		if z, err := validate.ZoneName(zone); err == nil {
			tz = append(tz, store.Zone{ID: "z", Name: z})
		}
		fw, err := PlanForward(tz, host, netip.MustParseAddr("192.0.2.1"))
		if err != nil {
			return
		}
		if !store.InZone(fw.Name, fw.Zone) || fw.Type != "A" {
			t.Fatalf("plan outside zone: %+v", fw)
		}
		if !fw.Existing {
			if _, err := validate.ZoneName(fw.Zone); err != nil {
				t.Fatalf("new zone %q invalid: %v", fw.Zone, err)
			}
		}
		if _, err := validate.RecordName(fw.Zone, fw.Name); err != nil || strings.Contains(fw.Name, "..") {
			t.Fatalf("name %q invalid in %q: %v", fw.Name, fw.Zone, err)
		}
	})
}
