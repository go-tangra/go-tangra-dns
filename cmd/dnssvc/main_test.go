package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRefusesInsecureOrIncomplete(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dns.yaml")
	if _, err := loadConfig([]string{"-config", filepath.Join(dir, "missing.yaml")}); err == nil {
		t.Fatal("missing config accepted")
	}
	// No PowerDNS endpoint or key reference, no KEK, no store: the service must refuse to start.
	_ = os.WriteFile(p, []byte("service_name: dns\ntrust_domain: example.org\n"), 0o600)
	if _, err := loadConfig([]string{"-config", p}); err == nil {
		t.Fatal("incomplete config accepted")
	}
	if err := run([]string{"-config", p}); err == nil {
		t.Fatal("run with an invalid config must fail")
	}
	if err := bootstrap([]string{"-config", p}); err == nil {
		t.Fatal("bootstrap with an invalid config must fail")
	}
	if _, err := loadConfig([]string{"-bogus"}); err == nil || !strings.Contains(err.Error(), "flag") {
		t.Fatalf("bad flag: %v", err)
	}
}
