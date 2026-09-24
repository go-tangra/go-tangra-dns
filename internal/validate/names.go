// Package validate is the DNS module's boundary validation (research D4/D5):
// zone and record names are canonicalised and checked before anything reaches
// PowerDNS, public suffixes cannot be claimed as zones, and primaries /
// supermasters must be unicast IP literals (SSRF guard). Every accepted value is
// re-serialised in canonical form — nothing the caller typed reaches PowerDNS
// verbatim.
//
// Canonical names are lower-case ASCII (A-labels; IDNA U-labels are refused)
// with exactly one trailing dot; labels are 1–63 octets and a name is at most
// 253 octets (presentation form without the trailing dot).
package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Errors (every name refusal wraps ErrName; every masters/IP refusal wraps
// ErrMasters).
var (
	ErrName         = errors.New("validate: invalid name")
	ErrPublicSuffix = errors.New("validate: public suffix")
	ErrMasters      = errors.New("validate: invalid primary address")
)

// MaxMasters bounds the primaries of one slave/consumer zone.
const MaxMasters = 16

const (
	maxName  = 253
	maxLabel = 63
	v4Suffix = "in-addr.arpa."
	v6Suffix = "ip6.arpa."
)

func nameErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrName}, a...)...)
}

// labelOK checks one label: 1–63 octets of [a-z0-9_-] (already lower-cased),
// not starting or ending with a hyphen. underscore=false refuses '_'.
func labelOK(l string, underscore bool) bool {
	if l == "" || len(l) > maxLabel || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		case c == '_' && underscore:
		default:
			return false
		}
	}
	return true
}

// split lower-cases and trims s, refuses non-ASCII and empty labels, and
// returns the canonical absolute form with its labels (the root is refused).
func split(s string) (string, []string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return "", nil, nameErr("only printable ASCII is allowed (use A-labels for IDNs)")
		}
	}
	if s == "" || s == "." {
		return "", nil, nameErr("the root is not allowed")
	}
	fq := dns.Fqdn(s)
	if strings.HasPrefix(fq, ".") || strings.Contains(fq, "..") || strings.ContainsRune(fq, '\\') {
		return "", nil, nameErr("empty label")
	}
	if len(fq)-1 > maxName {
		return "", nil, nameErr("longer than %d octets", maxName)
	}
	return fq, dns.SplitDomainName(fq), nil
}

// canonicalZone is the syntax-only zone check: canonical form, valid labels,
// '_' allowed except in the left-most label.
func canonicalZone(s string) (string, error) {
	fq, labels, err := split(s)
	if err != nil {
		return "", err
	}
	for i, l := range labels {
		if !labelOK(l, i > 0) {
			return "", nameErr("label %q is not a valid zone label", l)
		}
	}
	return fq, nil
}

// IsReverse reports whether the canonical zone lies in a reverse tree.
func IsReverse(zone string) bool {
	return strings.HasSuffix(zone, "."+v4Suffix) || strings.HasSuffix(zone, "."+v6Suffix)
}

// reverseOK applies the reverse rules: under in-addr.arpa 1–4 decimal octets
// (0–255, no leading zeros); under ip6.arpa 1–32 single hex nibbles.
func reverseOK(zone string) bool {
	if strings.HasSuffix(zone, "."+v4Suffix) {
		labels := strings.Split(strings.TrimSuffix(zone, "."+v4Suffix), ".")
		if len(labels) > 4 {
			return false
		}
		for _, l := range labels {
			n, err := strconv.Atoi(l)
			if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != l {
				return false
			}
		}
		return true
	}
	labels := strings.Split(strings.TrimSuffix(zone, "."+v6Suffix), ".")
	if len(labels) > 32 {
		return false
	}
	for _, l := range labels {
		if len(l) != 1 || !strings.Contains("0123456789abcdef", l) {
			return false
		}
	}
	return true
}

// ZoneName canonicalises and validates a zone name: canonical form, label
// syntax, not the root, not a public suffix (ICANN or private section of the
// Public Suffix List — e.g. "com.", "co.uk.", "github.io."), reverse zones
// under in-addr.arpa./ip6.arpa. validated by the reverse rules instead.
// Overlap with another tenant's zone is the store's question (ZoneConflict).
func ZoneName(s string) (string, error) {
	z, err := canonicalZone(s)
	if err != nil {
		return "", err
	}
	if IsReverse(z) {
		if !reverseOK(z) {
			return "", nameErr("%q is not a valid reverse zone", z)
		}
		return z, nil
	}
	bare := strings.TrimSuffix(z, ".")
	if suffix, _ := publicsuffix.PublicSuffix(bare); suffix == bare {
		return "", fmt.Errorf("%w: %w: %q cannot be claimed as a zone", ErrName, ErrPublicSuffix, z)
	}
	return z, nil
}

// RecordName qualifies a record owner name against zone: "@" or "" is the
// apex, a relative name is appended to the zone, an absolute name (trailing
// dot) is taken as is. The result must equal the zone or lie inside it; '*'
// is allowed only as the whole left-most label; '_' is allowed in any label.
func RecordName(zone, name string) (string, error) {
	z, err := canonicalZone(zone)
	if err != nil {
		return "", err
	}
	n := strings.TrimSpace(name)
	if n == "" || n == "@" {
		return z, nil
	}
	if !strings.HasSuffix(n, ".") {
		if strings.HasPrefix(n, ".") {
			return "", nameErr("empty label")
		}
		n = n + "." + z
	}
	fq, labels, err := split(n)
	if err != nil {
		return "", err
	}
	for i, l := range labels {
		if l == "*" && i == 0 {
			continue
		}
		if !labelOK(l, true) {
			return "", nameErr("label %q is not valid", l)
		}
	}
	if fq != z && !strings.HasSuffix(fq, "."+z) {
		return "", nameErr("%q is outside the zone %q", fq, z)
	}
	return fq, nil
}

// Hostname canonicalises a host name used as a target (nameserver, supermaster
// nameserver): at least two LDH labels, no underscores or wildcards, and not an
// IP literal (the last label is not numeric).
func Hostname(s string) (string, error) {
	fq, labels, err := split(s)
	if err != nil {
		return "", err
	}
	if len(labels) < 2 {
		return "", nameErr("%q is not a fully qualified host name", fq)
	}
	for _, l := range labels {
		if !labelOK(l, false) {
			return "", nameErr("label %q is not a valid host label", l)
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return "", nameErr("%q looks like an IP address", fq)
	}
	return fq, nil
}

func mastersErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMasters}, a...)...)
}

var broadcast = netip.MustParseAddr("255.255.255.255")

// IPGuard parses an IP literal (no port, no zone) and refuses addresses that
// must never be a primary or supermaster: loopback, link-local, unspecified,
// multicast and the limited broadcast (SSRF guard). IPv4-mapped IPv6 is
// unmapped.
func IPGuard(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, mastersErr("%q is not an IP literal", s)
	}
	return guard(a)
}

func guard(a netip.Addr) (netip.Addr, error) {
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || a == broadcast {
		return netip.Addr{}, mastersErr("%s is not an allowed unicast address", a)
	}
	return a, nil
}

// Masters validates the primaries of a slave/consumer zone: each an IP literal
// with an optional port ("192.0.2.1", "192.0.2.1:5300", "2001:db8::1",
// "[2001:db8::1]:53"), guarded by IPGuard, port 1–65535, no duplicates, at
// most MaxMasters. The canonical forms are returned (never nil).
func Masters(in []string) ([]string, error) {
	if len(in) > MaxMasters {
		return nil, mastersErr("at most %d primaries", MaxMasters)
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		var canon string
		if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			g, err := guard(a)
			if err != nil {
				return nil, err
			}
			canon = g.String()
		} else {
			ap, err := netip.ParseAddrPort(s)
			if err != nil || ap.Addr().Zone() != "" {
				return nil, mastersErr("%q is not an IP literal with an optional port", s)
			}
			if ap.Port() == 0 {
				return nil, mastersErr("port must be within [1, 65535]")
			}
			g, err := guard(ap.Addr())
			if err != nil {
				return nil, err
			}
			canon = netip.AddrPortFrom(g, ap.Port()).String()
		}
		if seen[canon] {
			return nil, mastersErr("duplicate primary %s", canon)
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out, nil
}
