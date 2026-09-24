package validate

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ErrRecord wraps every record type/content/TTL/value refusal (RecordError).
var ErrRecord = errors.New("validate: invalid record")

// RecordError is a record refusal naming the offending field ("type",
// "content", "ttl", "values", "values[1].content", "comment") and a message
// written by this package (never a parser's echo of the input).
type RecordError struct {
	Field string
	Msg   string
}

func (e *RecordError) Error() string { return "validate: invalid record: " + e.Field + ": " + e.Msg }

// Unwrap makes errors.Is(err, ErrRecord) hold.
func (e *RecordError) Unwrap() error { return ErrRecord }

func recErr(field, format string, a ...any) *RecordError {
	return &RecordError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// MaxContent bounds one record value (presentation form).
const MaxContent = 4096

// EditableTypes are the record types users may write (FR-003); SOA is
// read-only (PowerDNS manages serials) and every other type is refused.
var EditableTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "CAA", "DS", "DNSKEY", "TLSA", "SSHFP", "SPF", "NAPTR"}

// Editable reports whether t (any case) is an editable record type.
func Editable(t string) bool {
	t = strings.ToUpper(t)
	for _, e := range EditableTypes {
		if e == t {
			return true
		}
	}
	return false
}

// editableType canonicalises a requested type (upper case) and refuses SOA
// and anything outside EditableTypes.
func editableType(s string) (string, *RecordError) {
	t := strings.ToUpper(strings.TrimSpace(s))
	if t == "SOA" {
		return "", recErr("type", "SOA is read-only (serials are managed by PowerDNS)")
	}
	if !Editable(t) {
		return "", recErr("type", "this record type is not editable")
	}
	return t, nil
}

// directives are zone-file control statements; none may appear in a value
// (nor in its canonical output).
var directives = []string{"$include", "$origin", "$ttl", "$generate"}

func hasDirective(s string) bool {
	l := strings.ToLower(s)
	for _, d := range directives {
		if strings.Contains(l, d) {
			return true
		}
	}
	return false
}

// hasControl reports raw control characters (incl. CR, LF, TAB, NUL, DEL).
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// quotedTypes carry character-strings; every other type's value is a plain
// token list (no quotes at all).
func quotedType(t string) bool { return t == "TXT" || t == "SPF" || t == "CAA" || t == "NAPTR" }

// scan refuses what could escape the single RR line the value is parsed in:
// control characters anywhere; outside quoted strings comments (;),
// multi-line groups ( ), escapes / generic RDATA (\), the origin shorthand
// (@), '$' and non-ASCII; quotes in unquoted types; unterminated strings.
func scan(v string, quoted bool) *RecordError {
	if hasControl(v) {
		return recErr("content", "control characters (including line breaks and tabs) are not allowed")
	}
	inQ, esc := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if inQ {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inQ = false
			}
			continue
		}
		switch {
		case c == '"' && quoted:
			inQ = true
		case c == '"' || c == ';' || c == '(' || c == ')' || c == '\\' || c == '@' || c == '$':
			return recErr("content", "character %q is not allowed here", string(c))
		case c >= 0x80:
			return recErr("content", "non-ASCII characters are only allowed inside quoted strings")
		}
	}
	if inQ {
		return recErr("content", "unterminated quoted string")
	}
	return nil
}

var txtQuoter = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// content validates one value of an editable type t in canonical zone z and
// returns the canonical re-serialisation produced by the parser.
func content(t, z, value string) (string, *RecordError) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", recErr("content", "content is empty")
	}
	if len(v) > MaxContent {
		return "", recErr("content", "content is too long (at most %d octets)", MaxContent)
	}
	if hasDirective(v) {
		return "", recErr("content", "zone-file directives are not allowed")
	}
	switch t {
	case "TXT", "SPF":
		if !strings.HasPrefix(v, `"`) {
			v = `"` + txtQuoter.Replace(v) + `"` // one character-string (split at 255 octets by the parser)
		}
	case "A", "AAAA", "CNAME", "NS", "PTR", "MX", "SRV":
		v = strings.ToLower(v)
	case "DS", "TLSA", "SSHFP":
		v = strings.ToUpper(v)
	}
	if re := scan(v, quotedType(t)); re != nil {
		return "", re
	}
	rr, err := dns.NewRR(z + " 3600 IN " + t + " " + v)
	if err != nil || rr == nil {
		return "", recErr("content", "not a valid %s value", t)
	}
	if re := semantic(rr); re != nil {
		return "", re
	}
	out := rr.String()[len(rr.Header().String()):]
	if hasDirective(out) {
		return "", recErr("content", "zone-file directives are not allowed")
	}
	return out, nil
}

// Content validates value as the rdata of a record of type rtype in zone and
// returns its canonical presentation form (research D5): the value is refused
// if it carries control characters, zone-file directives or syntax that could
// escape one RR line, it is parsed by building one RR line from OUR qualified
// zone name, TTL, class IN and the type, and per-type semantic rules apply.
// Only the parser's re-serialisation is ever sent to PowerDNS.
func Content(rtype, zone, value string) (string, error) {
	z, err := canonicalZone(zone)
	if err != nil {
		return "", err
	}
	t, re := editableType(rtype)
	if re != nil {
		return "", re
	}
	out, re := content(t, z, value)
	if re != nil {
		return "", re
	}
	return out, nil
}

// target checks a domain-name field of rdata: LDH/underscore labels, the root
// only where the type defines it (null MX, SRV "no service", NAPTR).
func target(name string, allowRoot bool) *RecordError {
	if name == "." {
		if allowRoot {
			return nil
		}
		return recErr("content", "the target cannot be the root")
	}
	for _, l := range dns.SplitDomainName(name) {
		if !labelOK(strings.ToLower(l), true) {
			return recErr("content", "label %q of the target is not valid", l)
		}
	}
	return nil
}

func hexOK(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && s != ""
}

var dsDigestLen = map[uint8]int{1: 40, 2: 64, 4: 96}
var sshfpLen = map[uint8]int{1: 40, 2: 64}
var tlsaLen = map[uint8]int{1: 64, 2: 128}

// semantic applies the per-type rules on top of the parser (research D5).
func semantic(rr dns.RR) *RecordError {
	switch r := rr.(type) {
	case *dns.AAAA:
		if r.AAAA.To4() != nil {
			return recErr("content", "IPv4-mapped IPv6 addresses are not allowed (use an A record)")
		}
	case *dns.CNAME:
		return target(r.Target, false)
	case *dns.NS:
		return target(r.Ns, false)
	case *dns.PTR:
		return target(r.Ptr, false)
	case *dns.MX:
		if r.Mx == "." && r.Preference != 0 {
			return recErr("content", "a null MX (target \".\") must have preference 0")
		}
		return target(r.Mx, true)
	case *dns.SRV:
		return target(r.Target, true)
	case *dns.CAA:
		return caa(r)
	case *dns.DS:
		return ds(r)
	case *dns.DNSKEY:
		return dnskey(r)
	case *dns.TLSA:
		return tlsa(r)
	case *dns.SSHFP:
		return sshfp(r)
	case *dns.NAPTR:
		return naptr(r)
	}
	return nil
}

func caa(r *dns.CAA) *RecordError {
	if r.Flag != 0 && r.Flag != 128 {
		return recErr("content", "CAA flags must be 0 or 128")
	}
	r.Tag = strings.ToLower(r.Tag)
	switch r.Tag {
	case "issue", "issuewild":
	case "iodef":
		v := strings.ToLower(r.Value)
		if !strings.HasPrefix(v, "mailto:") && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") {
			return recErr("content", "a CAA iodef value must be a mailto: or http(s): URL")
		}
	default:
		return recErr("content", "the CAA tag must be issue, issuewild or iodef")
	}
	return nil
}

func ds(r *dns.DS) *RecordError {
	n, ok := dsDigestLen[r.DigestType]
	if !ok {
		return recErr("content", "the DS digest type must be 1, 2 or 4")
	}
	if !hexOK(r.Digest) {
		return recErr("content", "the DS digest is not hex")
	}
	if len(r.Digest) != n {
		return recErr("content", "the DS digest must be %d hex digits for digest type %d", n, r.DigestType)
	}
	return nil
}

func dnskey(r *dns.DNSKEY) *RecordError {
	if r.Flags != 0 && r.Flags != 256 && r.Flags != 257 {
		return recErr("content", "DNSKEY flags must be 0, 256 or 257")
	}
	if r.Protocol != 3 {
		return recErr("content", "the DNSKEY protocol must be 3")
	}
	if b, err := base64.StdEncoding.DecodeString(r.PublicKey); err != nil || len(b) == 0 {
		return recErr("content", "the DNSKEY public key is not valid base64")
	}
	return nil
}

func tlsa(r *dns.TLSA) *RecordError {
	switch {
	case r.Usage > 3:
		return recErr("content", "the TLSA usage must be 0-3")
	case r.Selector > 1:
		return recErr("content", "the TLSA selector must be 0 or 1")
	case r.MatchingType > 2:
		return recErr("content", "the TLSA matching type must be 0, 1 or 2")
	case !hexOK(r.Certificate):
		return recErr("content", "the TLSA certificate data is not hex")
	}
	if n, ok := tlsaLen[r.MatchingType]; ok && len(r.Certificate) != n {
		return recErr("content", "the TLSA certificate data has the wrong length for matching type %d (%d hex digits)", r.MatchingType, n)
	}
	return nil
}

func sshfp(r *dns.SSHFP) *RecordError {
	switch r.Algorithm {
	case 1, 2, 3, 4, 6:
	default:
		return recErr("content", "the SSHFP algorithm must be 1, 2, 3, 4 or 6")
	}
	n, ok := sshfpLen[r.Type]
	if !ok {
		return recErr("content", "the SSHFP fingerprint type must be 1 or 2")
	}
	if !hexOK(r.FingerPrint) {
		return recErr("content", "the SSHFP fingerprint is not hex")
	}
	if len(r.FingerPrint) != n {
		return recErr("content", "the SSHFP fingerprint has the wrong length for fingerprint type %d (%d hex digits)", r.Type, n)
	}
	return nil
}

func naptr(r *dns.NAPTR) *RecordError {
	for i := 0; i < len(r.Flags); i++ {
		c := r.Flags[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return recErr("content", "NAPTR flags must be letters or digits")
		}
	}
	r.Replacement = strings.ToLower(r.Replacement)
	return target(r.Replacement, true)
}
