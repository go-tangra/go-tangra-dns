// Package ipamsync keeps DNS in sync with IPAM (US2, research D8/D9): address
// events from the platform event bus are untrusted triggers only — the
// address is re-read from IPAM over SPIFFE mTLS and IPAM's answer drives
// A/AAAA and PTR writes in the event's tenant, through the same validated
// zone/record services the HTTP API uses. Local sync state makes renames,
// cleared host names and deletions exact and idempotent. Zones are created
// on demand (origin ipam) and never deleted by the sync.
package ipamsync

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

// ErrSkip marks an address the sync does not manage (bare or invalid host
// name, a host that is a public suffix, an invalid address).
var ErrSkip = errors.New("ipamsync: skipped")

const (
	v4Reverse = "in-addr.arpa."
	v6Reverse = "ip6.arpa."
)

// CanonicalHost canonicalises an IPAM host name (lower-case, trailing dot,
// LDH labels via validate.Hostname). Bare hosts (one label), IP literals,
// underscores/wildcards and names inside the reverse trees are refused.
func CanonicalHost(h string) (string, bool) {
	fq, err := validate.Hostname(h)
	if err != nil || strings.HasSuffix(fq, "."+v4Reverse) || strings.HasSuffix(fq, "."+v6Reverse) {
		return "", false
	}
	return fq, true
}

// Forward is the planned address record of a host.
type Forward struct {
	Zone     string // zone the record lives in
	ZoneID   string // set when Existing
	Existing bool   // false: the zone must be created (origin ipam)
	Name     string // owner name (the host FQDN)
	Type     string // A | AAAA
}

// recordType is A for IPv4 (including v4-mapped IPv6) and AAAA otherwise.
func recordType(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "A"
	}
	return "AAAA"
}

// longest returns the tenant's longest zone that equals or contains name,
// limited to reverse or forward zones.
func longest(zones []store.Zone, name string, reverse bool) (store.Zone, bool) {
	var best store.Zone
	found := false
	for _, z := range zones {
		if validate.IsReverse(z.Name) != reverse {
			continue
		}
		if store.InZone(name, z.Name) && (!found || len(z.Name) > len(best.Name)) {
			best, found = z, true
		}
	}
	return best, found
}

// PlanForward chooses the zone of a host's A/AAAA record: the tenant's
// longest zone that equals or is a label-wise suffix of the host, else the
// host's registrable domain (public-suffix aware: web.newcorp.co.uk →
// newcorp.co.uk.), to be created. Bare hosts, public suffixes and invalid
// addresses are ErrSkip.
func PlanForward(tenantZones []store.Zone, host string, addr netip.Addr) (Forward, error) {
	if !addr.IsValid() {
		return Forward{}, ErrSkip
	}
	h, ok := CanonicalHost(host)
	if !ok {
		return Forward{}, ErrSkip
	}
	f := Forward{Name: h, Type: recordType(addr)}
	if z, ok := longest(tenantZones, h, false); ok {
		f.Zone, f.ZoneID, f.Existing = z.Name, z.ID, true
		return f, nil
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(h, "."))
	if err != nil {
		return Forward{}, ErrSkip
	}
	zone, err := validate.ZoneName(reg)
	if err != nil || !store.InZone(h, zone) {
		return Forward{}, ErrSkip
	}
	f.Zone = zone
	return f, nil
}

// nibbles returns the 32 hex nibbles of a 16-byte address, most significant first.
func nibbles(a netip.Addr) []string {
	b := a.As16()
	out := make([]string, 0, 32)
	for _, x := range b {
		out = append(out, strconv.FormatUint(uint64(x>>4), 16), strconv.FormatUint(uint64(x&0x0f), 16))
	}
	return out
}

// labels returns the reverse-tree labels of an address from the most
// significant part: 4 decimal octets for IPv4, 32 nibbles for IPv6.
func labels(a netip.Addr) ([]string, string) {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return []string{strconv.Itoa(int(b[0])), strconv.Itoa(int(b[1])), strconv.Itoa(int(b[2])), strconv.Itoa(int(b[3]))}, v4Reverse
	}
	return nibbles(a), v6Reverse
}

func reverseName(parts []string, suffix string) string {
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteString(parts[i])
		b.WriteByte('.')
	}
	b.WriteString(suffix)
	return b.String()
}

// PTROwner is the PTR owner name of an address ("" for an invalid address).
func PTROwner(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	parts, suffix := labels(a)
	return reverseName(parts, suffix)
}

// ReverseZone sizes the reverse zone of an address from its subnet prefix:
// IPv4 rounded down to an octet boundary and clamped to /8../24, IPv6 rounded
// down to a nibble boundary and clamped to /4../64. An out-of-range prefix
// (unknown subnet) falls back to /24 or /64.
func ReverseZone(a netip.Addr, prefix int) string {
	if !a.IsValid() {
		return ""
	}
	parts, suffix := labels(a)
	unit, lo, hi, full := 8, 8, 24, 32
	if suffix == v6Reverse {
		unit, lo, hi, full = 4, 4, 64, 128
	}
	if prefix < 0 || prefix > full {
		prefix = hi
	}
	bits := min(max(prefix/unit*unit, lo), hi)
	return reverseName(parts[:bits/unit], suffix)
}

// Reverse is the planned PTR record of an address.
type Reverse struct {
	Zone     string
	ZoneID   string // set when Existing
	Existing bool
	Owner    string // PTR owner name
}

// PlanReverse chooses the reverse zone of an address: an existing reverse
// zone of the tenant containing the PTR owner (the longest one — a more
// specific zone wins, and a containing one is reused rather than nesting a new
// zone inside it), else the subnet-sized zone to be created.
func PlanReverse(tenantZones []store.Zone, a netip.Addr, prefix int) (Reverse, error) {
	if !a.IsValid() {
		return Reverse{}, ErrSkip
	}
	r := Reverse{Owner: PTROwner(a)}
	if z, ok := longest(tenantZones, r.Owner, true); ok {
		r.Zone, r.ZoneID, r.Existing = z.Name, z.ID, true
		return r, nil
	}
	r.Zone = ReverseZone(a, prefix)
	return r, nil
}

// PrefixOf returns the prefix length of a CIDR (-1 when it is not one).
func PrefixOf(cidr string) int {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return -1
	}
	return p.Bits()
}
