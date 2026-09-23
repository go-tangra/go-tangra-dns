package ipamsync

import (
	"errors"
	"net/netip"
	"testing"
)

// T047: arbitrary type/data never panics; anything accepted is one of the
// four address types with a bounded id and an IP literal; oversized payloads
// are always dropped.
func FuzzDecode(f *testing.F) {
	f.Add(TypeCreated, `{"action":"created","id":"a-1","address":"192.0.2.10","hostname":"web.example.com"}`)
	f.Add(TypeDeleted, `{"id":"a-1","address":"2001:db8::1"}`)
	f.Add("ipam.scan.completed", `{"job_id":"j"}`)
	f.Add(TypeUpdated, `{not json`)
	f.Add("dns.zone.created", `{}`)
	f.Fuzz(func(t *testing.T, typ, data string) {
		ev, err := Decode(map[string]string{"type": typ, "data": data})
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrIgnored) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if len(data) > MaxPayload {
			t.Fatalf("oversized payload accepted (%d bytes)", len(data))
		}
		switch ev.Type {
		case TypeCreated, TypeUpdated, TypeDeleted, TypeScanned:
		default:
			t.Fatalf("accepted type %q", ev.Type)
		}
		if ev.ID == "" || len(ev.ID) > MaxID {
			t.Fatalf("bad id %q", ev.ID)
		}
		if a, err := netip.ParseAddr(ev.Address); err != nil || a.Zone() != "" {
			t.Fatalf("bad address %q", ev.Address)
		}
	})
}
