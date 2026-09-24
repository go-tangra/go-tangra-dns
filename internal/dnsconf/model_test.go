package dnsconf

// T077: the typed server-configuration model — spec US5-1 defaults, and
// validation of every field (IP literals, ports, CIDRs, IP[:port] upstreams,
// list bounds, the DNSSEC enum, the open-resolver guard) with canonical output.

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	r, a := d.Recursor, d.Authoritative
	if strings.Join(r.ListenAddresses, ",") != "0.0.0.0,::" || r.Port != 53 || r.DNSSECValidation != DNSSECOff || r.AllowOpenResolver || len(r.UpstreamResolvers) != 0 {
		t.Fatalf("recursor defaults = %+v", r)
	}
	for _, n := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"} {
		found := false
		for _, x := range r.AllowedNetworks {
			found = found || x == n
		}
		if !found {
			t.Errorf("default allowed networks miss %s: %v", n, r.AllowedNetworks)
		}
	}
	if strings.Join(a.ListenAddresses, ",") != "0.0.0.0" || a.Port != 53 || len(a.TransferPeers) != 0 || a.TransferPeers == nil {
		t.Fatalf("auth defaults = %+v", a)
	}
	v, err := d.Validate()
	if err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
	if !v.OK() || v.Model().Recursor.Port != 53 {
		t.Fatal("validated defaults")
	}
	// Defaults are a fresh copy each time.
	d.Recursor.ListenAddresses[0] = "x"
	if Defaults().Recursor.ListenAddresses[0] != "0.0.0.0" {
		t.Fatal("defaults share state")
	}
}

func TestValidateCanonicalises(t *testing.T) {
	m := Defaults()
	m.Recursor.ListenAddresses = []string{" 192.0.2.1 ", "2001:DB8::1"}
	m.Recursor.AllowedNetworks = []string{"10.1.2.3/8", "192.0.2.7", "2001:db8::/32"}
	m.Recursor.UpstreamResolvers = []string{"9.9.9.9", "1.1.1.1:5353", "[2001:DB8::53]:53", "2001:db8::54"}
	m.Recursor.DNSSECValidation = " Validate "
	m.Authoritative.TransferPeers = []string{"198.51.100.4", "198.51.100.0/24"}
	v, err := m.Validate()
	if err != nil {
		t.Fatal(err)
	}
	got := v.Model()
	if strings.Join(got.Recursor.ListenAddresses, ",") != "192.0.2.1,2001:db8::1" ||
		strings.Join(got.Recursor.AllowedNetworks, ",") != "10.0.0.0/8,192.0.2.7/32,2001:db8::/32" ||
		strings.Join(got.Recursor.UpstreamResolvers, ",") != "9.9.9.9,1.1.1.1:5353,[2001:db8::53]:53,2001:db8::54" ||
		got.Recursor.DNSSECValidation != DNSSECValidate ||
		strings.Join(got.Authoritative.TransferPeers, ",") != "198.51.100.4/32,198.51.100.0/24" {
		t.Fatalf("canonical = %+v", got)
	}
	// nil lists become empty lists (never JSON null).
	m = Defaults()
	m.Recursor.AllowedNetworks, m.Recursor.UpstreamResolvers, m.Authoritative.TransferPeers = nil, nil, nil
	v, err = m.Validate()
	if err != nil || v.Model().Recursor.AllowedNetworks == nil || v.Model().Recursor.UpstreamResolvers == nil || v.Model().Authoritative.TransferPeers == nil {
		t.Fatalf("nil lists = %+v %v", v.Model(), err)
	}
}

func TestValidateRefuses(t *testing.T) {
	many := make([]string, MaxList+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.0.%d.1", i)
	}
	cases := []struct {
		field string
		mut   func(*Model)
	}{
		{"recursor.listen_addresses", func(m *Model) { m.Recursor.ListenAddresses = nil }},
		{"recursor.listen_addresses[0]", func(m *Model) { m.Recursor.ListenAddresses = []string{"localhost"} }},
		{"recursor.listen_addresses[0]", func(m *Model) { m.Recursor.ListenAddresses = []string{"fe80::1%eth0"} }},
		{"recursor.listen_addresses[1]", func(m *Model) { m.Recursor.ListenAddresses = []string{"0.0.0.0", "0.0.0.0"} }},
		{"recursor.listen_addresses", func(m *Model) { m.Recursor.ListenAddresses = many }},
		{"recursor.port", func(m *Model) { m.Recursor.Port = 0 }},
		{"recursor.port", func(m *Model) { m.Recursor.Port = 65536 }},
		{"recursor.allowed_networks[0]", func(m *Model) { m.Recursor.AllowedNetworks = []string{"10.0.0.0/33"} }},
		{"recursor.allowed_networks[0]", func(m *Model) { m.Recursor.AllowedNetworks = []string{"10.0.0.0/8\n#"} }},
		{"recursor.allowed_networks", func(m *Model) { m.Recursor.AllowedNetworks = many }},
		{"recursor.allowed_networks[0]", func(m *Model) { m.Recursor.AllowedNetworks = []string{"0.0.0.0/0"} }},
		{"recursor.allowed_networks[1]", func(m *Model) { m.Recursor.AllowedNetworks = []string{"10.0.0.0/8", "::/0"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"dns.google"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"1.1.1.1:0"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"0.0.0.0"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"224.0.0.1"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"127.0.0.1:5300"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"169.254.169.254"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"[::1]:53"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"255.255.255.255"} }},
		{"recursor.upstream_resolvers[0]", func(m *Model) { m.Recursor.UpstreamResolvers = []string{"1.1.1.1:53:53"} }},
		{"recursor.upstream_resolvers", func(m *Model) { m.Recursor.UpstreamResolvers = many }},
		{"recursor.dnssec_validation", func(m *Model) { m.Recursor.DNSSECValidation = "strict" }},
		{"recursor.dnssec_validation", func(m *Model) { m.Recursor.DNSSECValidation = "" }},
		{"authoritative.listen_addresses", func(m *Model) { m.Authoritative.ListenAddresses = []string{} }},
		{"authoritative.listen_addresses[0]", func(m *Model) { m.Authoritative.ListenAddresses = []string{"1.2.3.4:53"} }},
		{"authoritative.port", func(m *Model) { m.Authoritative.Port = -1 }},
		{"authoritative.transfer_peers[0]", func(m *Model) { m.Authoritative.TransferPeers = []string{"peer.example"} }},
		{"authoritative.transfer_peers", func(m *Model) { m.Authoritative.TransferPeers = many }},
	}
	for _, c := range cases {
		m := Defaults()
		c.mut(&m)
		v, err := m.Validate()
		var fe *FieldError
		if !errors.As(err, &fe) || !errors.Is(err, ErrInvalid) || fe.Field != c.field || v.OK() {
			t.Errorf("%s: err = %v (field %v)", c.field, err, fe)
			continue
		}
		if fe.Error() == "" || !strings.Contains(fe.Error(), c.field) {
			t.Errorf("%s: message %q", c.field, fe.Error())
		}
	}
}

func TestOpenResolverNeedsTheFlag(t *testing.T) {
	m := Defaults()
	m.Recursor.AllowedNetworks = []string{"0.0.0.0/0", "::/0"}
	if _, err := m.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("open resolver without the flag = %v", err)
	}
	m.Recursor.AllowOpenResolver = true
	v, err := m.Validate()
	if err != nil || !v.Model().Recursor.AllowOpenResolver || !v.OpenResolver() {
		t.Fatalf("open resolver with the flag = %v %v", v.Model(), err)
	}
	if d, _ := Defaults().Validate(); d.OpenResolver() {
		t.Fatal("defaults are not an open resolver")
	}
	// A zero Validated is refused.
	var zero Validated
	if zero.OK() {
		t.Fatal("zero validated")
	}
}
