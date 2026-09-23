package dnsconf

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Rendering errors.
var (
	ErrUnvalidated = errors.New("dnsconf: configuration not validated")
	ErrUnsafeValue = errors.New("dnsconf: value unsafe to render")
)

// Header marks the managed include files.
const Header = "# Managed by Freya DNS — do not edit by hand.\n"

// Scalars that may reach a file: IP/CIDR/IP:port literals and the DNSSEC
// enum. Anything else (whitespace, quotes, '#', ',', newlines…) is refused
// even though Validate already canonicalised every value.
var (
	addrRE = regexp.MustCompile(`^[0-9A-Fa-f.:/\[\]]{1,64}$`)
	modeRE = regexp.MustCompile(`^(off|process|validate)$`)
)

// writer accumulates lines and remembers the first unsafe value.
type writer struct {
	b   strings.Builder
	err error
}

func (w *writer) line(s string) { w.b.WriteString(s + "\n") }

// quoted returns v as a double-quoted YAML scalar after the allow-list check.
func (w *writer) quoted(v string, re *regexp.Regexp) string {
	if !re.MatchString(v) {
		if w.err == nil {
			w.err = fmt.Errorf("%w: %q", ErrUnsafeValue, v)
		}
		return `""`
	}
	return `"` + v + `"`
}

// bare returns v unquoted (key=value files) after the allow-list check.
func (w *writer) bare(vs []string) string {
	for _, v := range vs {
		if !addrRE.MatchString(v) && w.err == nil {
			w.err = fmt.Errorf("%w: %q", ErrUnsafeValue, v)
		}
	}
	return strings.Join(vs, ", ")
}

func (w *writer) result() (string, error) {
	if w.err != nil {
		return "", w.err
	}
	return w.b.String(), nil
}

// RenderRecursorYAML renders the recursor 5.x YAML include file (for the
// include-dir, e.g. /etc/powerdns/recursor.d). It fully defines the managed
// settings: incoming listen/port/allow_from, dnssec.validation and, when
// upstream resolvers are set, a forward-recurse of "." to them.
func RenderRecursorYAML(v Validated) (string, error) {
	if !v.ok {
		return "", ErrUnvalidated
	}
	r := v.m.Recursor
	w := &writer{}
	w.b.WriteString(Header)
	w.line("incoming:")
	w.line("  listen:")
	for _, a := range r.ListenAddresses {
		w.line("    - " + w.quoted(a, addrRE))
	}
	w.line("  port: " + strconv.Itoa(r.Port))
	if len(r.AllowedNetworks) > 0 {
		w.line("  allow_from:")
		for _, n := range r.AllowedNetworks {
			w.line("    - " + w.quoted(n, addrRE))
		}
	}
	w.line("dnssec:")
	w.line("  validation: " + w.quoted(r.DNSSECValidation, modeRE))
	if len(r.UpstreamResolvers) > 0 {
		w.line("recursor:")
		w.line("  forward_zones_recurse:")
		w.line(`    - zone: "."`)
		w.line("      forwarders:")
		for _, u := range r.UpstreamResolvers {
			w.line("        - " + w.quoted(u, addrRE))
		}
	}
	return w.result()
}

// RenderAuthConf renders the PowerDNS Authoritative key=value include file
// (for the include-dir, e.g. /etc/powerdns/pdns.d): local-address,
// local-port and, when transfer peers are set, allow-axfr-ips (otherwise the
// server default — loopback only — applies).
func RenderAuthConf(v Validated) (string, error) {
	if !v.ok {
		return "", ErrUnvalidated
	}
	a := v.m.Authoritative
	w := &writer{}
	w.b.WriteString(Header)
	w.line("local-address=" + w.bare(a.ListenAddresses))
	w.line("local-port=" + strconv.Itoa(a.Port))
	if len(a.TransferPeers) > 0 {
		w.line("allow-axfr-ips=" + w.bare(a.TransferPeers))
	}
	return w.result()
}
