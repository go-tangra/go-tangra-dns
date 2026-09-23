package validate

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/dns/internal/pdns"
)

const zone = "example.com."

// corpus reads testdata/records/<file>: one "TYPE<TAB>CONTENT" case per line.
func corpus(t testing.TB, file string) [][2]string {
	t.Helper()
	f, err := os.Open("../../testdata/records/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out [][2]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		typ, content, _ := strings.Cut(line, "\t")
		out = append(out, [2]string{typ, content})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestContentCorpusValid(t *testing.T) {
	cases := corpus(t, "valid.txt")
	if len(cases) < 25 {
		t.Fatalf("valid corpus too small: %d", len(cases))
	}
	seen := map[string]bool{}
	for _, c := range cases {
		out, err := Content(c[0], zone, c[1])
		if err != nil {
			t.Errorf("Content(%s, %q) refused: %v", c[0], c[1], err)
			continue
		}
		seen[c[0]] = true
		// canonical output is stable and itself valid
		again, err := Content(c[0], zone, out)
		if err != nil || again != out {
			t.Errorf("Content(%s, %q) = %q not idempotent: %q %v", c[0], c[1], out, again, err)
		}
	}
	for _, typ := range EditableTypes {
		if !seen[typ] {
			t.Errorf("valid corpus lacks type %s", typ)
		}
	}
}

func TestContentCorpusInvalid(t *testing.T) {
	cases := corpus(t, "invalid.txt")
	if len(cases) < 30 {
		t.Fatalf("invalid corpus too small: %d", len(cases))
	}
	for _, c := range cases {
		if out, err := Content(c[0], zone, c[1]); err == nil {
			t.Errorf("Content(%s, %q) accepted as %q", c[0], c[1], out)
		} else if !errors.Is(err, ErrRecord) {
			t.Errorf("Content(%s, %q) error %v does not wrap ErrRecord", c[0], c[1], err)
		}
	}
}

func TestContentCanonical(t *testing.T) {
	long := strings.Repeat("a", 300)
	cases := []struct{ typ, in, want string }{
		{"A", " 192.0.2.10 ", "192.0.2.10"},
		{"AAAA", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"CNAME", "Target.Example.COM", "target.example.com."},
		{"NS", "ns1.example.net", "ns1.example.net."},
		{"MX", "10 Mail.Example.com.", "10 mail.example.com."},
		{"SRV", "10 60 5060 SIP.example.com", "10 60 5060 sip.example.com."},
		{"TXT", "hello world", `"hello world"`},
		{"TXT", `say "hi" \ there`, `"say \"hi\" \\ there"`},
		{"TXT", `"part one" "part two"`, `"part one" "part two"`},
		{"TXT", long, `"` + long[:255] + `" "` + long[255:] + `"`},
		{"SPF", "v=spf1 -all", `"v=spf1 -all"`},
		{"TXT", "héllo", `"h\195\169llo"`},
		{"CAA", `0 ISSUE "letsencrypt.org"`, `0 issue "letsencrypt.org"`},
		{"DS", "60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118", "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"},
		{"TLSA", "3 1 1 0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6", "3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6"},
		{"TLSA", "3 1 0 0c72", "3 1 0 0C72"},
		{"SSHFP", "1 1 123456789abcdef67890123456789abcdef67890", "1 1 123456789ABCDEF67890123456789ABCDEF67890"},
		{"DNSKEY", "256 3 13 AwEA AagA", "256 3 13 AwEAAagA"},
		{"DNSKEY", "0 3 13 AwEAAagA", "0 3 13 AwEAAagA"},
		{"a", "192.0.2.1", "192.0.2.1"},
	}
	for _, c := range cases {
		got, err := Content(c.typ, zone, c.in)
		if err != nil || got != c.want {
			t.Errorf("Content(%s, %q) = %q, %v; want %q", c.typ, c.in, got, err, c.want)
		}
	}
}

func TestContentRefusals(t *testing.T) {
	cases := []struct{ typ, in, msg string }{
		{"A", "", "empty"},
		{"A", "   ", "empty"},
		{"A", strings.Repeat("1", MaxContent+1), "too long"},
		{"TXT", "line\nbreak", "control"},
		{"TXT", "carriage\rreturn", "control"},
		{"TXT", "tab\there", "control"},
		{"TXT", "nul\x00", "control"},
		{"TXT", "del\x7f", "control"},
		{"TXT", `"quoted\` + "\n" + `"`, "control"},
		{"TXT", "$ORIGIN evil.example.", "directive"},
		{"TXT", `"x" $include /etc/passwd`, "directive"},
		{"TXT", `"x" $TTL 1`, "directive"},
		{"TXT", `"$GENERATE 1-10 a"`, "directive"},
		{"TXT", `"\036INCLUDE /etc/passwd"`, "directive"},
		{"TXT", `"a" ; comment`, "not allowed"},
		{"TXT", `"a" ("b")`, "not allowed"},
		{"TXT", `"a" \# 1 00`, "not allowed"},
		{"TXT", `"a" @`, "not allowed"},
		{"TXT", `"a" $x`, "not allowed"},
		{"TXT", `"a" é`, "non-ASCII"},
		{"TXT", `"unterminated`, "unterminated"},
		{"TXT", `"escape at end\`, "unterminated"},
		{"A", `"192.0.2.1"`, "not allowed"},
		{"A", "192.0.2.1 ; x", "not allowed"},
		{"A", "(192.0.2.1)", "not allowed"},
		{"CNAME", `a\.b.example.com.`, "not allowed"},
		{"CNAME", "@", "not allowed"},
		{"CNAME", "bücher.example.", "non-ASCII"},
		{"A", `\# 4 c0000201`, "not allowed"},
		{"SOA", "ns1.example.com. hostmaster.example.com. 1 2 3 4 5", "read-only"},
		{"soa", "x", "read-only"},
		{"HINFO", `"cpu" "os"`, "not editable"},
		{"TYPE65534", `\# 0`, "not editable"},
		{"AAAA", "::ffff:192.0.2.1", "IPv4-mapped"},
		{"CNAME", ".", "root"},
		{"NS", ".", "root"},
		{"PTR", ".", "root"},
		{"CNAME", "under_score!.example.com.", "label"},
		{"CNAME", "*.example.com.", "label"},
		{"MX", "10 .", "null MX"},
		{"MX", "10 bad!.example.", "label"},
		{"SRV", "0 0 1 x!y.example.", "label"},
		{"CAA", `0 foo "bar"`, "tag"},
		{"CAA", `1 issue "x"`, "flags"},
		{"CAA", `0 iodef "ftp://x"`, "iodef"},
		{"DS", "1 5 3 2BB183AF5F22588179A53B0A98631FAD1A292118", "digest type"},
		{"DS", "1 5 2 2BB183AF5F22588179A53B0A98631FAD1A292118", "digest"},
		{"DS", "1 5 1 ZZB183AF5F22588179A53B0A98631FAD1A292118", "hex"},
		{"DNSKEY", "257 3 8 !!!!", "base64"},
		{"DNSKEY", "257 4 8 AwEAAag=", "protocol"},
		{"DNSKEY", "1 3 8 AwEAAag=", "flags"},
		{"TLSA", "4 1 1 00", "usage"},
		{"TLSA", "3 2 1 00", "selector"},
		{"TLSA", "3 1 3 00", "matching"},
		{"TLSA", "3 1 2 0C72", "length"},
		{"TLSA", "3 1 0 0C7", "hex"},
		{"SSHFP", "5 1 123456789ABCDEF67890123456789ABCDEF67890", "algorithm"},
		{"SSHFP", "1 3 123456789ABCDEF67890123456789ABCDEF67890", "fingerprint type"},
		{"SSHFP", "1 2 123456789ABCDEF67890123456789ABCDEF67890", "length"},
		{"NAPTR", `100 10 "U!" "E2U+sip" "" x.example.`, "flags"},
		{"NAPTR", `100 10 "U" "E2U+sip" "" x!.example.`, "label"},
		{"A", "999.1.1.1", "not a valid A"},
	}
	for _, c := range cases {
		out, err := Content(c.typ, zone, c.in)
		if err == nil {
			t.Errorf("Content(%s, %q) accepted as %q", c.typ, c.in, out)
			continue
		}
		var re *RecordError
		if !errors.As(err, &re) || !errors.Is(err, ErrRecord) {
			t.Errorf("Content(%s, %q): %v is not a RecordError", c.typ, c.in, err)
			continue
		}
		if !strings.Contains(err.Error(), c.msg) {
			t.Errorf("Content(%s, %q) = %q, want mention of %q", c.typ, c.in, err, c.msg)
		}
	}
	if _, err := Content("A", "bad..zone", "192.0.2.1"); !errors.Is(err, ErrName) {
		t.Errorf("bad zone: %v", err)
	}
}

func TestEditable(t *testing.T) {
	if len(EditableTypes) != 15 {
		t.Fatalf("editable types = %v", EditableTypes)
	}
	for _, typ := range EditableTypes {
		if !Editable(typ) || !Editable(strings.ToLower(typ)) {
			t.Errorf("%s not editable", typ)
		}
	}
	for _, typ := range []string{"SOA", "HINFO", "RRSIG", "", "ALIAS"} {
		if Editable(typ) {
			t.Errorf("%s editable", typ)
		}
	}
}

func rs(name, typ string, ttl int, values ...string) RecordSetInput {
	in := RecordSetInput{Name: name, Type: typ, TTL: ttl}
	for _, v := range values {
		in.Values = append(in.Values, RecordValue{Content: v})
	}
	return in
}

func TestRecordSet(t *testing.T) {
	in := rs("www", "a", 300, "192.0.2.1", "192.0.2.2")
	in.Values[1].Disabled = true
	in.Comment = "web servers"
	out, err := RecordSet(zone, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "www.example.com." || out.Type != "A" || out.TTL != 300 || out.ChangeType != pdns.ChangeReplace ||
		len(out.Records) != 2 || !out.Records[1].Disabled || out.Records[0].Disabled ||
		len(out.Comments) != 1 || out.Comments[0].Content != "web servers" {
		t.Fatalf("rrset = %+v", out)
	}
	// no comment -> an explicit empty comment list (PowerDNS clears existing comments)
	if out, err := RecordSet(zone, rs("@", "MX", 3600, "10 mail.example.com."), nil); err != nil || out.Comments == nil || len(out.Comments) != 0 || out.Name != zone {
		t.Fatalf("mx = %+v %v", out, err)
	}
	// replacing the same (name, type) is not an exclusivity conflict
	existing := []pdns.RRset{{Name: "alias.example.com.", Type: "CNAME"}, {Name: "www.example.com.", Type: "A"}, {Name: zone, Type: "SOA"}}
	if _, err := RecordSet(zone, rs("alias", "CNAME", 300, "www.example.com."), existing); err != nil {
		t.Fatalf("replace cname: %v", err)
	}
	if _, err := RecordSet(zone, rs("www", "AAAA", 300, "2001:db8::1"), existing); err != nil {
		t.Fatalf("aaaa next to a: %v", err)
	}
	// custom limits
	l := Limits{MinTTL: 1, MaxTTL: 10, MaxValues: 1}
	if _, err := l.RecordSet(zone, rs("x", "A", 5, "192.0.2.1"), nil); err != nil {
		t.Fatalf("limits: %v", err)
	}
	if _, err := l.RecordSet(zone, rs("x", "A", 5, "192.0.2.1", "192.0.2.2"), nil); err == nil {
		t.Fatal("limits: max values")
	}
}

func TestRecordSetRefusals(t *testing.T) {
	existing := []pdns.RRset{{Name: "alias.example.com.", Type: "CNAME"}, {Name: "www.example.com.", Type: "A"}}
	many := rs("x", "A", 300)
	for i := 0; i < 101; i++ {
		many.Values = append(many.Values, RecordValue{Content: "192.0.2.1"})
	}
	withComment := func(c string) RecordSetInput { r := rs("x", "A", 300, "192.0.2.1"); r.Comment = c; return r }
	cases := []struct {
		name string
		zone string
		in   RecordSetInput
		want error
		msg  string
	}{
		{"bad zone", "a..b", rs("x", "A", 300, "192.0.2.1"), ErrName, ""},
		{"soa", zone, rs("@", "SOA", 300, "x"), ErrRecord, "read-only"},
		{"unknown type", zone, rs("x", "HINFO", 300, "x"), ErrRecord, "not editable"},
		{"outside zone", zone, rs("foo.other.test.", "A", 300, "192.0.2.1"), ErrName, "outside"},
		{"ttl low", zone, rs("x", "A", 59, "192.0.2.1"), ErrRecord, "ttl"},
		{"ttl high", zone, rs("x", "A", 604801, "192.0.2.1"), ErrRecord, "ttl"},
		{"no values", zone, rs("x", "A", 300), ErrRecord, "values"},
		{"too many values", zone, many, ErrRecord, "values"},
		{"bad value", zone, rs("x", "A", 300, "192.0.2.1", "999.1.1.1"), ErrRecord, "values[1]"},
		{"duplicate value", zone, rs("x", "AAAA", 300, "2001:db8::1", "2001:DB8:0::1"), ErrRecord, "duplicate"},
		{"apex cname", zone, rs("@", "CNAME", 300, "x.example.net."), ErrRecord, "apex"},
		{"multi cname", zone, rs("c", "CNAME", 300, "a.example.net.", "b.example.net."), ErrRecord, "one value"},
		{"cname next to a", zone, rs("www", "CNAME", 300, "x.example.net."), ErrRecord, "other data"},
		{"a next to cname", zone, rs("ALIAS", "A", 300, "192.0.2.1"), ErrRecord, "CNAME exists"},
		{"long comment", zone, withComment(strings.Repeat("c", MaxComment+1)), ErrRecord, "comment"},
		{"control comment", zone, withComment("a\nb"), ErrRecord, "comment"},
	}
	for _, c := range cases {
		_, err := RecordSet(c.zone, c.in, existing)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
			continue
		}
		if c.msg != "" && !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err = %q, want mention of %q", c.name, err, c.msg)
		}
	}
	var re *RecordError
	_, err := RecordSet(zone, rs("x", "A", 300, "192.0.2.1", "bad"), nil)
	if !errors.As(err, &re) || re.Field != "values[1].content" || re.Msg == "" {
		t.Fatalf("record error = %#v", err)
	}
}
