package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestZoneName(t *testing.T) {
	ok := map[string]string{
		"example.com":                    "example.com.",
		"Example.COM.":                   "example.com.",
		"  lab.example.com  ":            "lab.example.com.",
		"xn--bcher-kva.example":          "xn--bcher-kva.example.",
		"a-b.example.org":                "a-b.example.org.",
		"sub._tcp.example.com":           "sub._tcp.example.com.",
		"newcorp.co.uk":                  "newcorp.co.uk.",
		"corp.internal":                  "corp.internal.",
		"10.in-addr.arpa":                "10.in-addr.arpa.",
		"2.0.192.in-addr.arpa.":          "2.0.192.in-addr.arpa.",
		"0.0.0.10.in-addr.arpa":          "0.0.0.10.in-addr.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa":       "8.b.d.0.1.0.0.2.ip6.arpa.",
		"B.8.ip6.ARPA":                   "b.8.ip6.arpa.",
		strings.Repeat("a", 63) + ".com": strings.Repeat("a", 63) + ".com.",
	}
	for in, want := range ok {
		got, err := ZoneName(in)
		if err != nil || got != want {
			t.Errorf("ZoneName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	long := strings.Repeat(strings.Repeat("a", 60)+".", 4) + "com" // 247 octets; + ".x" + a 5th label > 253
	bad := []string{
		"", " ", ".", "..", "example..com", ".example.com", "example.com..",
		"com", "co.uk", "uk.", "github.io", // public suffixes (ICANN + private)
		"test", "localhost", // single label: its own suffix
		"-a.example.com", "a-.example.com", "a b.example.com", "a*.example.com", "*.example.com",
		"_dmarc.example.com", "lab_1.example.com", // underscore only in non-first labels of a zone
		"bücher.example", // IDNA U-labels refused
		"exa\x00mple.com", "exa\nmple.com", "example.com/24", "a;b.example.com", `a\.b.example.com`,
		strings.Repeat("a", 64) + ".com", strings.Repeat("a", 10) + "." + long,
		"arpa", "in-addr.arpa", "ip6.arpa", // the reverse roots themselves
		"256.in-addr.arpa", "01.in-addr.arpa", "a.in-addr.arpa", "1.2.3.4.5.in-addr.arpa", "x.10.in-addr.arpa",
		"ab.ip6.arpa", "g.ip6.arpa", strings.Repeat("0.", 33) + "ip6.arpa",
	}
	for _, in := range bad {
		if got, err := ZoneName(in); err == nil {
			t.Errorf("ZoneName(%q) accepted as %q", in, got)
		} else if !errors.Is(err, ErrName) {
			t.Errorf("ZoneName(%q) error %v is not ErrName", in, err)
		}
	}
	if _, err := ZoneName("co.uk"); !errors.Is(err, ErrPublicSuffix) {
		t.Fatalf("public suffix reason: %v", err)
	}
}

func TestIsReverse(t *testing.T) {
	if !IsReverse("10.in-addr.arpa.") || !IsReverse("8.ip6.arpa.") || IsReverse("in-addr.arpa.example.") || IsReverse("example.com.") {
		t.Fatal("IsReverse")
	}
}

func TestRecordName(t *testing.T) {
	const zone = "example.com."
	ok := map[string]string{
		"@":                     "example.com.",
		"":                      "example.com.",
		"www":                   "www.example.com.",
		"WWW":                   "www.example.com.",
		"_sip._tcp":             "_sip._tcp.example.com.",
		"*":                     "*.example.com.",
		"*.dev":                 "*.dev.example.com.",
		"www.example.com.":      "www.example.com.",
		"EXAMPLE.COM.":          "example.com.",
		"a.b.c":                 "a.b.c.example.com.",
		"_acme-challenge":       "_acme-challenge.example.com.",
		"_acme-challenge.www":   "_acme-challenge.www.example.com.",
		" host ":                "host.example.com.",
		"xn--bcher-kva":         "xn--bcher-kva.example.com.",
		strings.Repeat("a", 63): strings.Repeat("a", 63) + ".example.com.",
	}
	for in, want := range ok {
		got, err := RecordName(zone, in)
		if err != nil || got != want {
			t.Errorf("RecordName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"www.example.org.", // outside the zone
		"xexample.com.",    // not a label boundary
		"com.",             // parent of the zone
		"a.*.example.com.", // wildcard not left-most
		"w*w", "*w", "a.*", // wildcard only as a whole left-most label
		"a..b", ".www", "www..", "a b", "bücher", "a\nb", "a\x00b", "$ORIGIN", "a;b", `a\046b`, "a/b", "-a", "a-",
		strings.Repeat("a", 64),
		strings.Repeat(strings.Repeat("a", 63)+".", 4), // too long once qualified
	}
	for _, in := range bad {
		if got, err := RecordName(zone, in); err == nil {
			t.Errorf("RecordName(%q) accepted as %q", in, got)
		} else if !errors.Is(err, ErrName) {
			t.Errorf("RecordName(%q) error %v is not ErrName", in, err)
		}
	}
	if _, err := RecordName("not a zone", "www"); !errors.Is(err, ErrName) {
		t.Fatal("bad zone accepted")
	}
	if got, err := RecordName("10.in-addr.arpa.", "4.3.2"); err != nil || got != "4.3.2.10.in-addr.arpa." {
		t.Fatalf("reverse owner = %q %v", got, err)
	}
}

func TestHostname(t *testing.T) {
	for in, want := range map[string]string{"ns1.example.com": "ns1.example.com.", "NS1.Example.COM.": "ns1.example.com.", "a.b": "a.b."} {
		if got, err := Hostname(in); err != nil || got != want {
			t.Errorf("Hostname(%q) = %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "ns1", "ns1.", "*.example.com", "_ns.example.com", "ns 1.example.com", "ns1..example.com", "bücher.de", "192.0.2.1"} {
		if got, err := Hostname(in); err == nil {
			t.Errorf("Hostname(%q) accepted as %q", in, got)
		}
	}
}

func TestMastersAndIPGuard(t *testing.T) {
	got, err := Masters([]string{"192.0.2.10", " 192.0.2.11:5300 ", "2001:db8::1", "[2001:db8::2]:53", "::ffff:198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10", "192.0.2.11:5300", "2001:db8::1", "[2001:db8::2]:53", "198.51.100.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("masters = %v", got)
	}
	if got, err := Masters(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty = %v %v", got, err)
	}
	bad := [][]string{
		{"127.0.0.1"}, {"::1"}, {"169.254.1.1"}, {"fe80::1"}, {"0.0.0.0"}, {"::"}, {"224.0.0.1"}, {"ff02::1"},
		{"255.255.255.255"}, {"192.0.2.1:0"}, {"192.0.2.1:65536"}, {"192.0.2.1:x"}, {"192.0.2.1:"}, {"ns1.example.com"},
		{"ns1.example.com:53"}, {""}, {"[2001:db8::1]"}, {"2001:db8::1:53:"}, {"192.0.2.1", "192.0.2.1"}, {"http://192.0.2.1"},
		{"[fe80::1%eth0]:53"}, {"fe80::1%eth0"}, {"127.0.0.1:53"}, {"[::1]:53"},
		make([]string, MaxMasters+1),
	}
	for _, in := range bad {
		if got, err := Masters(in); err == nil {
			t.Errorf("Masters(%q) accepted as %v", in, got)
		} else if !errors.Is(err, ErrMasters) {
			t.Errorf("Masters(%q) error %v is not ErrMasters", in, err)
		}
	}
	for in, want := range map[string]string{"192.0.2.1": "192.0.2.1", " 2001:DB8::1 ": "2001:db8::1", "::ffff:192.0.2.9": "192.0.2.9"} {
		if got, err := IPGuard(in); err != nil || got.String() != want {
			t.Errorf("IPGuard(%q) = %v %v", in, got, err)
		}
	}
	for _, in := range []string{"127.0.0.2", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "::", "239.1.1.1", "ff05::2", "255.255.255.255", "192.0.2.1:53", "x", "fe80::1%eth0"} {
		if _, err := IPGuard(in); !errors.Is(err, ErrMasters) {
			t.Errorf("IPGuard(%q) = %v", in, err)
		}
	}
}
