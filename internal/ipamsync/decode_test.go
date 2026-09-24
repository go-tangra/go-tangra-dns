package ipamsync

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/ipam/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDecodeFixtures(t *testing.T) {
	ev, err := Decode(fixture(t, "created.json"))
	if err != nil || ev.Type != TypeCreated || ev.Action != "created" || ev.ID != "0190f7c2-0000-7000-8000-00000000a001" ||
		ev.Address != "192.0.2.10" || ev.Hostname != "web.example.com" || ev.SubnetID != "0190f7c2-0000-7000-8000-00000000b001" {
		t.Fatalf("created = %+v %v", ev, err)
	}
	for name, typ := range map[string]string{"created_v6.json": TypeCreated, "updated.json": TypeUpdated, "deleted.json": TypeDeleted, "scanned.json": TypeScanned} {
		if ev, err := Decode(fixture(t, name)); err != nil || ev.Type != typ {
			t.Errorf("%s = %+v %v", name, ev, err)
		}
	}
	for _, name := range []string{"malformed.json", "malformed_json.json", "oversized.json"} {
		if _, err := Decode(fixture(t, name)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := Decode(fixture(t, "other_type.json")); !errors.Is(err, ErrIgnored) {
		t.Fatalf("other type = %v", err)
	}
}

func TestDecodeRules(t *testing.T) {
	ok := `{"id":"a-1","address":"2001:db8::1","hostname":"h.example.com","extra":{"nested":[1,2]}}`
	if ev, err := Decode(map[string]string{"type": TypeUpdated, "data": ok}); err != nil || ev.Address != "2001:db8::1" || ev.Action != "" {
		t.Fatalf("unknown fields must be ignored: %+v %v", ev, err)
	}
	for _, typ := range []string{"dns.record.changed", "dns.zone.created", "ipam.scan.completed", "", "IPAM.IP_ADDRESS.CREATED"} {
		if _, err := Decode(map[string]string{"type": typ, "data": ok}); !errors.Is(err, ErrIgnored) {
			t.Errorf("type %q = %v, want ErrIgnored", typ, err)
		}
	}
	for _, data := range []string{
		``, `null`, `[]`, `"x"`, `{}`,
		`{"id":"","address":"192.0.2.1"}`,
		`{"id":"` + strings.Repeat("a", 65) + `","address":"192.0.2.1"}`,
		`{"id":"a b","address":"192.0.2.1"}`,
		`{"id":"a-1","address":"192.0.2.1/24"}`,
		`{"id":"a-1","address":"fe80::1%eth0"}`,
		`{"id":"a-1","address":"192.0.2.1","hostname":7}`,
		`{"id":"a-1","address":"192.0.2.1"} trailing`,
		`{"id":"a-1","address":"192.0.2.1","hostname":"` + strings.Repeat("h", 300) + `"}`,
		`{"id":"a-1","address":"192.0.2.1","pad":"` + strings.Repeat("x", MaxPayload) + `"}`,
	} {
		if _, err := Decode(map[string]string{"type": TypeCreated, "data": data}); !errors.Is(err, ErrMalformed) {
			t.Errorf("data %.60q = %v, want ErrMalformed", data, err)
		}
	}
	if _, err := Decode(nil); !errors.Is(err, ErrIgnored) {
		t.Fatalf("nil fields = %v", err)
	}
}
