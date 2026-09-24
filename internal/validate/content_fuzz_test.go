package validate

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
)

// assertContent checks the invariants of an accepted value: exactly one RR of
// the requested type re-parses from it, it is its own canonical form, and it
// carries no line break, control character or zone-file directive.
func assertContent(t *testing.T, typ, out string) {
	t.Helper()
	for i := 0; i < len(out); i++ {
		if out[i] < 0x20 || out[i] == 0x7f {
			t.Fatalf("control character in accepted %s %q", typ, out)
		}
	}
	if hasDirective(out) {
		t.Fatalf("directive in accepted %s %q", typ, out)
	}
	zp := dns.NewZoneParser(strings.NewReader(zone+" 300 IN "+strings.ToUpper(typ)+" "+out+"\n"), "", "")
	n := 0
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		n++
		if rr.Header().Rrtype != dns.StringToType[strings.ToUpper(typ)] {
			t.Fatalf("%q re-parses as %s", out, dns.TypeToString[rr.Header().Rrtype])
		}
	}
	if zp.Err() != nil || n != 1 {
		t.Fatalf("%s %q re-parses to %d RRs (%v)", typ, out, n, zp.Err())
	}
	again, err := Content(typ, zone, out)
	if err != nil || again != out {
		t.Fatalf("%s %q not canonical: %q %v", typ, out, again, err)
	}
}

func FuzzContent(f *testing.F) {
	for _, c := range corpus(f, "valid.txt") {
		f.Add(c[0], c[1])
	}
	for _, c := range corpus(f, "invalid.txt") {
		f.Add(c[0], c[1])
	}
	for _, s := range []string{"\"a\"\n$INCLUDE /x", "\"\\010\"", "a\\", "\"\\\"", "@ IN A 1.2.3.4", "1.2.3.4\r\nevil 300 IN A 1.1.1.1"} {
		f.Add("TXT", s)
		f.Add("A", s)
	}
	f.Fuzz(func(t *testing.T, typ, value string) {
		out, err := Content(typ, zone, value)
		if err != nil {
			return
		}
		assertContent(t, typ, out)
	})
}

func FuzzRecordSet(f *testing.F) {
	f.Add("example.com.", "www", "A", "192.0.2.1", "CNAME", "alias")
	f.Add("example.com.", "@", "MX", "10 mail.example.com.", "A", "@")
	f.Add("example.com.", "foo.other.test.", "TXT", "hello", "TXT", "x")
	f.Add("10.in-addr.arpa.", "4.3.2", "PTR", "host.example.com.", "NS", "4.3.2")
	f.Add("example.com.", "*.dev", "CNAME", "x.example.net.", "A", "*.dev")
	f.Fuzz(func(t *testing.T, z, name, typ, value, otherType, otherName string) {
		existing := []pdns.RRset{{Name: otherName, Type: otherType}}
		out, err := RecordSet(z, RecordSetInput{Name: name, Type: typ, TTL: 300, Values: []RecordValue{{Content: value}}}, existing)
		if err != nil {
			return
		}
		cz, zerr := canonicalZone(z)
		if zerr != nil {
			t.Fatalf("accepted a record set in invalid zone %q", z)
		}
		canonical(t, out.Name)
		if out.Name != cz && !strings.HasSuffix(out.Name, "."+cz) {
			t.Fatalf("%q escapes zone %q", out.Name, cz)
		}
		if !Editable(out.Type) || out.Type != strings.ToUpper(out.Type) || len(out.Records) != 1 {
			t.Fatalf("rrset = %+v", out)
		}
		if out.Type == "CNAME" && out.Name == cz {
			t.Fatalf("apex CNAME accepted")
		}
		assertContent(t, out.Type, out.Records[0].Content)
	})
}
