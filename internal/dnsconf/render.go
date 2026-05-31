// Package dnsconf renders editable PowerDNS settings into the include-dir
// config files consumed by the recursor (YAML) and authoritative (conf)
// servers, and restarts the containers to apply them.
package dnsconf

import (
	"fmt"
	"strings"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
)

// RenderRecursorYAML produces a recursor 5.x YAML config snippet for the
// recursor's include-dir (/etc/powerdns/recursor.d). It fully defines the
// managed settings so this file is authoritative for them.
func RenderRecursorYAML(c *dnsV1.RecursorConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by go-tangra-dns — do not edit by hand.\n")

	b.WriteString("incoming:\n")
	if len(c.GetLocalAddress()) > 0 {
		b.WriteString("  listen:\n")
		for _, a := range c.GetLocalAddress() {
			fmt.Fprintf(&b, "    - %q\n", a)
		}
	}
	if c.GetLocalPort() != 0 {
		fmt.Fprintf(&b, "  port: %d\n", c.GetLocalPort())
	}
	if len(c.GetAllowFrom()) > 0 {
		b.WriteString("  allow_from:\n")
		for _, a := range c.GetAllowFrom() {
			fmt.Fprintf(&b, "    - %q\n", a)
		}
	}

	b.WriteString("dnssec:\n")
	if c.GetDnssecDisabled() {
		b.WriteString("  validation: \"off\"\n")
	} else {
		b.WriteString("  validation: \"process\"\n")
	}

	if len(c.GetUpstreamResolvers()) > 0 {
		b.WriteString("recursor:\n")
		b.WriteString("  forward_zones_recurse:\n")
		b.WriteString("    - zone: \".\"\n")
		b.WriteString("      forwarders:\n")
		for _, r := range c.GetUpstreamResolvers() {
			fmt.Fprintf(&b, "        - %q\n", r)
		}
	}

	return b.String()
}

// RenderAuthConf produces a PowerDNS Authoritative key=value config snippet
// for the auth include-dir (/etc/powerdns/pdns.d).
func RenderAuthConf(c *dnsV1.AuthConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by go-tangra-dns — do not edit by hand.\n")
	if len(c.GetLocalAddress()) > 0 {
		fmt.Fprintf(&b, "local-address=%s\n", strings.Join(c.GetLocalAddress(), ", "))
	}
	if c.GetLocalPort() != 0 {
		fmt.Fprintf(&b, "local-port=%d\n", c.GetLocalPort())
	}
	if len(c.GetAllowAxfr()) > 0 {
		fmt.Fprintf(&b, "allow-axfr-ips=%s\n", strings.Join(c.GetAllowAxfr(), ", "))
	}
	return b.String()
}
