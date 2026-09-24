// Package dnsconf is the DNS server configuration of US5 (research D11): a
// typed model with safe defaults and strict validation, renderers that turn a
// VALIDATED model into the PowerDNS Recursor (5.x YAML) and Authoritative
// (key=value) include files through a quoting writer, an atomic
// write-if-changed file writer, a restart-only Docker Engine client limited
// to the two configured container names, and the service that saves,
// renders, writes and restarts only what changed (platform-admin only).
package dnsconf

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ErrInvalid wraps every validation refusal (HTTP invalid_config).
var ErrInvalid = errors.New("dnsconf: invalid configuration")

// FieldError names the refused field.
type FieldError struct {
	Field string
	Msg   string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

// Unwrap makes errors.Is(err, ErrInvalid) true.
func (e *FieldError) Unwrap() error { return ErrInvalid }

func fieldErr(field, format string, a ...any) error {
	return &FieldError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// MaxList bounds every list of the model.
const MaxList = 32

// DNSSEC validation modes of the recursor.
const (
	DNSSECOff      = "off"
	DNSSECProcess  = "process"
	DNSSECValidate = "validate"
)

// Recursor is the resolver section.
type Recursor struct {
	ListenAddresses   []string `json:"listen_addresses"`
	Port              int      `json:"port"`
	AllowedNetworks   []string `json:"allowed_networks"`
	UpstreamResolvers []string `json:"upstream_resolvers"`
	DNSSECValidation  string   `json:"dnssec_validation"`
	// AllowOpenResolver must be set to accept 0.0.0.0/0 or ::/0 in
	// AllowedNetworks (opening the resolver to the internet).
	AllowOpenResolver bool `json:"allow_open_resolver"`
}

// Authoritative is the authoritative-server section.
type Authoritative struct {
	ListenAddresses []string `json:"listen_addresses"`
	Port            int      `json:"port"`
	TransferPeers   []string `json:"transfer_peers"`
}

// Model is the whole server configuration.
type Model struct {
	Recursor      Recursor      `json:"recursor"`
	Authoritative Authoritative `json:"authoritative"`
}

// Defaults are the spec US5-1 safe defaults: the resolver on all addresses
// port 53 serving private networks and loopback only, validation off; the
// authoritative server on all IPv4 addresses port 53 without transfer peers.
func Defaults() Model {
	return Model{
		Recursor: Recursor{
			ListenAddresses:   []string{"0.0.0.0", "::"},
			Port:              53,
			AllowedNetworks:   []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"},
			UpstreamResolvers: []string{},
			DNSSECValidation:  DNSSECOff,
		},
		Authoritative: Authoritative{ListenAddresses: []string{"0.0.0.0"}, Port: 53, TransferPeers: []string{}},
	}
}

// Validated is a model that passed Validate: every value canonical and
// checked. Only Validate produces one; the renderers refuse anything else.
type Validated struct {
	m  Model
	ok bool
}

// OK reports whether v came from a successful Validate.
func (v Validated) OK() bool { return v.ok }

// Model returns a copy of the validated model.
func (v Validated) Model() Model {
	m := v.m
	m.Recursor.ListenAddresses = append([]string{}, m.Recursor.ListenAddresses...)
	m.Recursor.AllowedNetworks = append([]string{}, m.Recursor.AllowedNetworks...)
	m.Recursor.UpstreamResolvers = append([]string{}, m.Recursor.UpstreamResolvers...)
	m.Authoritative.ListenAddresses = append([]string{}, m.Authoritative.ListenAddresses...)
	m.Authoritative.TransferPeers = append([]string{}, m.Authoritative.TransferPeers...)
	return m
}

// OpenResolver reports whether the resolver admits every client.
func (v Validated) OpenResolver() bool {
	for _, n := range v.m.Recursor.AllowedNetworks {
		if n == "0.0.0.0/0" || n == "::/0" {
			return true
		}
	}
	return false
}

// Validate checks every field and returns the canonical model.
func (m Model) Validate() (Validated, error) {
	var out Model
	var err error
	r, a := m.Recursor, m.Authoritative
	if out.Recursor.ListenAddresses, err = list("recursor.listen_addresses", r.ListenAddresses, true, listenAddr); err != nil {
		return Validated{}, err
	}
	if out.Recursor.Port, err = port("recursor.port", r.Port); err != nil {
		return Validated{}, err
	}
	if out.Recursor.AllowedNetworks, err = list("recursor.allowed_networks", r.AllowedNetworks, false, network); err != nil {
		return Validated{}, err
	}
	for i, n := range out.Recursor.AllowedNetworks {
		if (n == "0.0.0.0/0" || n == "::/0") && !r.AllowOpenResolver {
			return Validated{}, fieldErr(fmt.Sprintf("recursor.allowed_networks[%d]", i),
				"%s opens the resolver to every client; set allow_open_resolver to confirm", n)
		}
	}
	if out.Recursor.UpstreamResolvers, err = list("recursor.upstream_resolvers", r.UpstreamResolvers, false, upstream); err != nil {
		return Validated{}, err
	}
	switch mode := strings.ToLower(strings.TrimSpace(r.DNSSECValidation)); mode {
	case DNSSECOff, DNSSECProcess, DNSSECValidate:
		out.Recursor.DNSSECValidation = mode
	default:
		return Validated{}, fieldErr("recursor.dnssec_validation", "must be off, process or validate")
	}
	out.Recursor.AllowOpenResolver = r.AllowOpenResolver
	if out.Authoritative.ListenAddresses, err = list("authoritative.listen_addresses", a.ListenAddresses, true, listenAddr); err != nil {
		return Validated{}, err
	}
	if out.Authoritative.Port, err = port("authoritative.port", a.Port); err != nil {
		return Validated{}, err
	}
	if out.Authoritative.TransferPeers, err = list("authoritative.transfer_peers", a.TransferPeers, false, network); err != nil {
		return Validated{}, err
	}
	return Validated{m: out, ok: true}, nil
}

func port(field string, p int) (int, error) {
	if p < 1 || p > 65535 {
		return 0, fieldErr(field, "must be within [1, 65535]")
	}
	return p, nil
}

// list canonicalises every entry with f, refusing duplicates and more than
// MaxList entries (and an empty list when required).
func list(field string, in []string, required bool, f func(string) (string, error)) ([]string, error) {
	if len(in) > MaxList {
		return nil, fieldErr(field, "at most %d entries are allowed", MaxList)
	}
	if required && len(in) == 0 {
		return nil, fieldErr(field, "at least one entry is required")
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for i, raw := range in {
		name := fmt.Sprintf("%s[%d]", field, i)
		v, err := f(strings.TrimSpace(raw))
		if err != nil {
			return nil, fieldErr(name, "%s", err.Error())
		}
		if seen[v] {
			return nil, fieldErr(name, "duplicate entry %s", v)
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

// listenAddr is an IP literal without a zone.
func listenAddr(s string) (string, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", errors.New("must be an IP address literal")
	}
	return a.Unmap().String(), nil
}

// network is a CIDR or a single IP (canonical masked prefix).
func network(s string) (string, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return "", errors.New("must be an IP address or CIDR")
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", errors.New("must be an IP address or CIDR")
	}
	return p.Masked().String(), nil
}

// upstream is IP or IP:port ([v6]:port) of a unicast, specified address.
func upstream(s string) (string, error) {
	var addr netip.Addr
	var p uint16
	if ap, err := netip.ParseAddrPort(s); err == nil {
		addr, p = ap.Addr(), ap.Port()
		if p == 0 {
			return "", errors.New("port must be within [1, 65535]")
		}
	} else if a, err := netip.ParseAddr(s); err == nil {
		addr = a
	} else {
		return "", errors.New("must be IP or IP:port")
	}
	addr = addr.Unmap()
	// Same SSRF guard as masters/supermasters (validate.IPGuard): no loopback,
	// link-local, unspecified, multicast or broadcast upstream.
	if addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return "", errors.New("must be a unicast resolver address")
	}
	if p == 0 {
		return addr.String(), nil
	}
	if addr.Is6() {
		return "[" + addr.String() + "]:" + strconv.Itoa(int(p)), nil
	}
	return addr.String() + ":" + strconv.Itoa(int(p)), nil
}
