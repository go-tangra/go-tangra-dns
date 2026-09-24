package contract

// T081: server configuration over the full HTTP chain — GET/PUT shapes, 403
// for everyone who is not a platform administrator holding config:manage,
// invalid_config reasons with the refused field, and a response that lists
// the restarted containers but never file contents or keys.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dnsconf"
	"github.com/go-tangra/go-tangra-dns/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-dns/v4/internal/memstore"
)

func newConfigHarness(t *testing.T) (*harness, *dnsconf.Fake, string) {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := verifier{
		"admin-a":    {UserID: adminA, TenantID: tenantA, Roles: []string{"owner", "admin"}},
		"viewer-a":   {UserID: viewerA, TenantID: tenantA},
		"platform-a": {UserID: platformA, TenantID: tenantA, Roles: []string{authz.RolePlatformAdmin}},
	}
	// The tenant admin is (mis)granted config:manage: the module still refuses
	// because it is not a platform administrator.
	checker := authz.Static{adminA: {authz.ConfigManage}, platformA: {authz.ConfigManage}, viewerA: {authz.ZonesRead}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(checker))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.s = s
	dir := t.TempDir()
	for _, d := range []string{"recursor.d", "pdns.d"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	rs := dnsconf.NewFake(true)
	cs := dnsconf.New(dnsconf.ServiceDeps{Store: memstore.New(), Restarter: rs, Checker: checker,
		RecursorPath: filepath.Join(dir, "recursor.d", "freya.yml"), AuthPath: filepath.Join(dir, "pdns.d", "freya.conf")})
	s.Register(httpapi.Deps{Config: cs})
	return h, rs, dir
}

const cfgBody = `{"recursor":{"listen_addresses":["0.0.0.0"],"port":53,"allowed_networks":["10.0.0.0/8"],"upstream_resolvers":["9.9.9.9"],"dnssec_validation":"process"},
 "authoritative":{"listen_addresses":["0.0.0.0"],"port":53,"transfer_peers":[]}}`

func TestConfigShapes(t *testing.T) {
	h, rs, dir := newConfigHarness(t)
	w := h.do("GET", p+"/config", "platform-a", "")
	if w.Code != 200 {
		t.Fatalf("get = %d %s", w.Code, w.Body)
	}
	var view struct {
		Defaults  bool `json:"defaults"`
		Restarter struct {
			Enabled    bool              `json:"enabled"`
			Containers map[string]string `json:"containers"`
		} `json:"restarter"`
		Recursor struct {
			Port int `json:"port"`
		} `json:"recursor"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &view)
	if !view.Defaults || !view.Restarter.Enabled || view.Restarter.Containers["recursor"] != "freya-pdns-recursor" || view.Recursor.Port != 53 {
		t.Fatalf("view = %+v", view)
	}
	w = h.do("PUT", p+"/config", "platform-a", cfgBody)
	if w.Code != 200 {
		t.Fatalf("put = %d %s", w.Code, w.Body)
	}
	var res struct {
		Changed         []string `json:"changed"`
		Restarted       []string `json:"restarted"`
		RestartRequired []string `json:"restart_required"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if strings.Join(res.Changed, ",") != "recursor,authoritative" || strings.Join(res.Restarted, ",") != "freya-pdns-recursor,freya-pdns-auth" {
		t.Fatalf("result = %s", w.Body)
	}
	rendered, _ := os.ReadFile(filepath.Join(dir, "recursor.d", "freya.yml")) // #nosec G304 -- test temp dir
	for _, leak := range []string{"Managed by", "incoming:", "allow_from", "local-address"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("response carries file contents (%s): %s", leak, w.Body)
		}
	}
	if !strings.Contains(string(rendered), `validation: "process"`) {
		t.Fatalf("rendered = %s", rendered)
	}
	// A no-op save restarts nothing.
	w = h.do("PUT", p+"/config", "platform-a", cfgBody)
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || len(res.Restarted) != 0 || len(res.Changed) != 0 || len(rs.Restarts()) != 2 {
		t.Fatalf("no-op = %d %s", w.Code, w.Body)
	}
	if w = h.do("GET", p+"/config", "platform-a", ""); !strings.Contains(w.Body.String(), `"defaults":false`) {
		t.Fatalf("after save = %s", w.Body)
	}
}

func TestConfigRefusals(t *testing.T) {
	h, rs, _ := newConfigHarness(t)
	for _, tok := range []string{"admin-a", "viewer-a"} {
		if w := h.do("GET", p+"/config", tok, ""); w.Code != 403 {
			t.Errorf("%s get = %d", tok, w.Code)
		}
		if w := h.do("PUT", p+"/config", tok, cfgBody); w.Code != 403 {
			t.Errorf("%s put = %d", tok, w.Code)
		}
	}
	if w := h.do("GET", p+"/config", "", ""); w.Code != 401 {
		t.Fatalf("anonymous = %d", w.Code)
	}
	cases := map[string]string{
		"recursor.allowed_networks[0]":    strings.Replace(cfgBody, `"10.0.0.0/8"`, `"0.0.0.0/0"`, 1),
		"recursor.upstream_resolvers[0]":  strings.Replace(cfgBody, `"9.9.9.9"`, `"dns.google"`, 1),
		"recursor.listen_addresses[0]":    strings.Replace(cfgBody, `"listen_addresses":["0.0.0.0"],"port":53,"allowed`, `"listen_addresses":["any"],"port":53,"allowed`, 1),
		"authoritative.transfer_peers[0]": strings.Replace(cfgBody, `"transfer_peers":[]`, `"transfer_peers":["peer"]`, 1),
	}
	for field, body := range cases {
		w := h.do("PUT", p+"/config", "platform-a", body)
		var e struct {
			Reason string         `json:"reason"`
			Detail map[string]any `json:"detail"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		if w.Code != 422 || e.Reason != "invalid_config" || e.Detail["field"] != field {
			t.Errorf("%s: %d %s", field, w.Code, w.Body)
		}
	}
	// Schema refusals: unknown fields, bad enum, out-of-range port.
	for _, body := range []string{
		strings.Replace(cfgBody, `"port":53,"allowed`, `"port":0,"allowed`, 1),
		strings.Replace(cfgBody, `"process"`, `"strict"`, 1),
		strings.Replace(cfgBody, `"transfer_peers":[]`, `"transfer_peers":[],"launch":"pipe"`, 1),
	} {
		if w := h.do("PUT", p+"/config", "platform-a", body); w.Code != 422 && w.Code != 400 {
			t.Errorf("schema refusal = %d %s", w.Code, w.Body)
		}
	}
	if len(rs.Restarts()) != 0 {
		t.Fatalf("a refused request restarted %v", rs.Restarts())
	}
}
