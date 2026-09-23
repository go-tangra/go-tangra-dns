package validate

import (
	"strings"
	"testing"
)

// canonical reports whether s is in the module's canonical form: lower-case
// ASCII, one trailing dot, no empty labels, bounded lengths.
func canonical(t *testing.T, s string) {
	t.Helper()
	if !strings.HasSuffix(s, ".") || strings.HasSuffix(s, "..") || strings.HasPrefix(s, ".") || s == "." {
		t.Fatalf("not canonical: %q", s)
	}
	if s != strings.ToLower(s) || len(s) > 254 {
		t.Fatalf("not canonical: %q", s)
	}
	for _, l := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if l == "" || len(l) > 63 {
			t.Fatalf("bad label in %q", s)
		}
	}
	for _, r := range s {
		if r > 0x7e || r <= 0x20 {
			t.Fatalf("non-printable/non-ASCII in %q", s)
		}
	}
}

func FuzzZoneName(f *testing.F) {
	for _, s := range []string{"example.com", "EXAMPLE.com.", "co.uk", "10.in-addr.arpa", "8.b.d.0.1.0.0.2.ip6.arpa", "_x.example.com",
		"bücher.example", "a..b", "\x00", strings.Repeat("a.", 140)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := ZoneName(in)
		if err != nil {
			return
		}
		canonical(t, out)
		again, err := ZoneName(out)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", in, out, again, err)
		}
	})
}

func FuzzRecordName(f *testing.F) {
	for _, s := range [][2]string{{"example.com.", "@"}, {"example.com.", "www"}, {"example.com.", "*.dev"}, {"example.com.", "a.*"},
		{"example.com.", "www.example.org."}, {"10.in-addr.arpa.", "4.3.2"}, {"example.com.", "$ORIGIN"}, {"x", "y"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, zone, name string) {
		out, err := RecordName(zone, name)
		if err != nil {
			return
		}
		z, zerr := canonicalZone(zone)
		if zerr != nil {
			t.Fatalf("accepted a name in an invalid zone %q", zone)
		}
		canonical(t, out)
		if out != z && !strings.HasSuffix(out, "."+z) {
			t.Fatalf("%q escapes zone %q", out, z)
		}
		if i := strings.Index(out, "*"); i >= 0 && (i != 0 || !strings.HasPrefix(out, "*.")) {
			t.Fatalf("wildcard not left-most: %q", out)
		}
	})
}

func FuzzMasters(f *testing.F) {
	for _, s := range []string{"192.0.2.1", "192.0.2.1:53", "[2001:db8::1]:53", "127.0.0.1", "fe80::1%eth0", "x:y:z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := Masters([]string{in})
		if err != nil {
			return
		}
		if len(out) != 1 {
			t.Fatalf("masters = %v", out)
		}
		again, err := Masters(out)
		if err != nil || again[0] != out[0] {
			t.Fatalf("not idempotent: %q -> %q (%v)", in, out[0], err)
		}
	})
}
