package dnsconf

// T078: rendering — golden recursor YAML and authoritative conf for the
// defaults and a full configuration, deterministic output, and refusal of an
// unvalidated model. Update the golden files with -update.

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func full() Model {
	m := Defaults()
	m.Recursor.ListenAddresses = []string{"192.0.2.53", "2001:db8::53"}
	m.Recursor.Port = 5300
	m.Recursor.AllowedNetworks = []string{"10.0.0.0/8", "2001:db8::/32"}
	m.Recursor.UpstreamResolvers = []string{"9.9.9.9", "[2620:fe::fe]:53"}
	m.Recursor.DNSSECValidation = DNSSECValidate
	m.Authoritative.ListenAddresses = []string{"0.0.0.0", "::"}
	m.Authoritative.Port = 5353
	m.Authoritative.TransferPeers = []string{"198.51.100.0/24", "203.0.113.9"}
	return m
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "dnsconf", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- test fixture path
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("%s differs:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func mustRender(t *testing.T, m Model) (string, string) {
	t.Helper()
	v, err := m.Validate()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := RenderRecursorYAML(v)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := RenderAuthConf(v)
	if err != nil {
		t.Fatal(err)
	}
	return rec, auth
}

func TestRenderGolden(t *testing.T) {
	rec, auth := mustRender(t, Defaults())
	golden(t, "recursor_default.yaml", rec)
	golden(t, "auth_default.conf", auth)
	rec, auth = mustRender(t, full())
	golden(t, "recursor_full.yaml", rec)
	golden(t, "auth_full.conf", auth)
}

func TestRenderDeterministic(t *testing.T) {
	a1, b1 := mustRender(t, full())
	for i := 0; i < 20; i++ {
		a2, b2 := mustRender(t, full())
		if a1 != a2 || b1 != b2 {
			t.Fatal("rendering is not deterministic")
		}
	}
}

func TestRenderRefusesUnvalidated(t *testing.T) {
	if _, err := RenderRecursorYAML(Validated{}); !errors.Is(err, ErrUnvalidated) {
		t.Fatalf("recursor = %v", err)
	}
	if _, err := RenderAuthConf(Validated{}); !errors.Is(err, ErrUnvalidated) {
		t.Fatalf("auth = %v", err)
	}
	// A validated model tampered with afterwards is still refused by the
	// quoting writer (defence in depth).
	v, _ := Defaults().Validate()
	v.m.Recursor.AllowedNetworks = []string{"10.0.0.0/8\"\nincoming: {}"}
	if _, err := RenderRecursorYAML(v); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("tampered recursor = %v", err)
	}
	v, _ = Defaults().Validate()
	v.m.Authoritative.TransferPeers = []string{"1.2.3.4\nlaunch=pipe"}
	if _, err := RenderAuthConf(v); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("tampered auth = %v", err)
	}
	v, _ = Defaults().Validate()
	v.m.Recursor.DNSSECValidation = "off\"\nx: y"
	if _, err := RenderRecursorYAML(v); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("tampered dnssec = %v", err)
	}
	v, _ = Defaults().Validate()
	v.m.Recursor.UpstreamResolvers = []string{"1.1.1.1 #"}
	if _, err := RenderRecursorYAML(v); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("tampered upstream = %v", err)
	}
	v, _ = Defaults().Validate()
	v.m.Recursor.ListenAddresses = []string{"::\n"}
	if _, err := RenderRecursorYAML(v); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("tampered listen = %v", err)
	}
	v, _ = Defaults().Validate()
	v.m.Authoritative.ListenAddresses = []string{"0.0.0.0, 1.2.3.4"}
	if _, err := RenderAuthConf(v); !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("tampered auth listen = %v", err)
	}
}
