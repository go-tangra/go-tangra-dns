package dnsconf

// T078 (fuzz): arbitrary models that pass validation never render a line
// outside the managed keys, and no value ever carries a raw newline, '#',
// quote or whitespace that could break out of its scalar; models that fail
// validation are never rendered.

import (
	"regexp"
	"strings"
	"testing"
)

var (
	recursorLine = regexp.MustCompile(`^(# Managed by Freya DNS — do not edit by hand\.|incoming:|  listen:|  port: [0-9]{1,5}|  allow_from:|dnssec:|  validation: "(off|process|validate)"|recursor:|  forward_zones_recurse:|    - zone: "\."|      forwarders:|    - "[0-9A-Fa-f.:/]+"|        - "[0-9A-Fa-f.:\[\]]+")$`)
	authLine     = regexp.MustCompile(`^(# Managed by Freya DNS — do not edit by hand\.|local-address=[0-9A-Fa-f.:]+(, [0-9A-Fa-f.:]+)*|local-port=[0-9]{1,5}|allow-axfr-ips=[0-9A-Fa-f.:/]+(, [0-9A-Fa-f.:/]+)*)$`)
)

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "|")
}

func FuzzRender(f *testing.F) {
	f.Add("0.0.0.0|::", 53, "10.0.0.0/8|192.168.1.1", "9.9.9.9|[2001:db8::1]:53", "validate", false, "0.0.0.0", 53, "198.51.100.0/24")
	f.Add("1.2.3.4\nlaunch=pipe", 53, "0.0.0.0/0", "1.1.1.1:5353", "off", true, "::", 5353, "")
	f.Add("::1", 1, "\"#", "x:y", "process", false, "127.0.0.1", 65535, "1.2.3.4#")
	f.Fuzz(func(t *testing.T, listen string, rport int, nets, ups, mode string, open bool, alisten string, aport int, peers string) {
		m := Model{
			Recursor: Recursor{ListenAddresses: split(listen), Port: rport, AllowedNetworks: split(nets), UpstreamResolvers: split(ups),
				DNSSECValidation: mode, AllowOpenResolver: open},
			Authoritative: Authoritative{ListenAddresses: split(alisten), Port: aport, TransferPeers: split(peers)},
		}
		v, err := m.Validate()
		if err != nil {
			if v.OK() {
				t.Fatal("a refused model is marked validated")
			}
			if _, rerr := RenderRecursorYAML(v); rerr == nil {
				t.Fatal("an unvalidated model rendered")
			}
			return
		}
		rec, err := RenderRecursorYAML(v)
		if err != nil {
			t.Fatalf("validated model failed to render: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(rec, "\n"), "\n") {
			if !recursorLine.MatchString(line) {
				t.Fatalf("unexpected recursor line %q in\n%s", line, rec)
			}
		}
		auth, err := RenderAuthConf(v)
		if err != nil {
			t.Fatalf("validated model failed to render auth: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(auth, "\n"), "\n") {
			if !authLine.MatchString(line) {
				t.Fatalf("unexpected auth line %q in\n%s", line, auth)
			}
		}
	})
}
