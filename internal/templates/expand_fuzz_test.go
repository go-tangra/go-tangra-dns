package templates

import (
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
)

// T057: arbitrary template records and zone names never panic; every
// produced rrset is valid for its type and inside the zone, or the whole
// expansion is refused.
func FuzzExpand(f *testing.F) {
	f.Add("example.com.", "@", "MX", 3600, "mail.[ZONE].", 10, "www", "CNAME", "[ZONE].")
	f.Add("example.org", "_sip._tcp", "SRV", 300, "5 5060 sip.[ZONE].", 1, "[ZONE].", "A", "192.0.2.1")
	f.Add("x.example.", "", "TXT", 60, "v=spf1 include:[ZONE] -all", 0, "a.[ZONE]", "AAAA", "2001:db8::1")
	f.Add("10.in-addr.arpa.", "1.2.3", "PTR", 3600, "host.[ZONE]", 0, "*", "A", "$ORIGIN evil")
	f.Fuzz(func(t *testing.T, zone, n1, t1 string, ttl int, c1 string, prio int, n2, t2, c2 string) {
		recs := []store.TemplateRecord{
			{Name: n1, Type: t1, TTL: ttl, Content: c1, Priority: prio},
			{Name: n2, Type: t2, TTL: 3600, Content: c2},
		}
		sets, err := ExpandRecords(validate.DefaultLimits, zone, recs)
		if err != nil {
			var re *validate.RecordError
			if !errors.As(err, &re) && !errors.Is(err, validate.ErrName) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		z, err := validate.ZoneName(zone)
		if err != nil {
			t.Fatalf("expanded for an invalid zone %q", zone)
		}
		for _, s := range sets {
			if !store.InZone(s.Name, z) || len(s.Records) == 0 {
				t.Fatalf("rrset outside zone or empty: %+v", s)
			}
			for _, r := range s.Records {
				if _, err := validate.Content(s.Type, z, r.Content); err != nil {
					t.Fatalf("invalid content %q for %s: %v", r.Content, s.Type, err)
				}
			}
		}
	})
}
