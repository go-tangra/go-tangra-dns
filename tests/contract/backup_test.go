package contract

// T094: backup export/import and the SSE stream over the full HTTP chain.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/backup"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/httpapi"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/recursor"
	"github.com/go-freya/freya/services/dns/internal/stream"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

func newBackupHarness(t *testing.T) (*harness, *stream.Hub) {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := verifier{
		"admin-a":    {UserID: adminA, TenantID: tenantA},
		"viewer-a":   {UserID: viewerA, TenantID: tenantA},
		"admin-b":    {UserID: adminB, TenantID: tenantB},
		"platform-a": {UserID: platformA, TenantID: tenantA, Roles: []string{authz.RolePlatformAdmin}},
	}
	all := []string{authz.ZonesRead, authz.ZonesManage, authz.BackupManage}
	checker := authz.Static{adminA: all, adminB: all, platformA: all, viewerA: {authz.ZonesRead}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(checker))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.s = s
	h.st, h.pd, h.rec, h.pub = memstore.New(), pdns.NewFake(), recursor.NewFake(), &events.Recorder{}
	zs := zones.New(zones.Deps{Store: h.st, PDNS: h.pd, Recursor: h.rec, Events: h.pub})
	hub := stream.NewHub(stream.NewMemory(), stream.Config{StreamsPerUser: 1}, nil)
	t.Cleanup(hub.Close)
	s.Register(httpapi.Deps{Zones: zs, Backup: backup.New(backup.Deps{Store: h.st, PDNS: h.pd}), Hub: hub})
	return h, hub
}

func TestBackupRoutes(t *testing.T) {
	h, _ := newBackupHarness(t)
	h.createZone("admin-a", `{"name":"backup.example.","kind":"native"}`)
	w := h.do("POST", p+"/backup/export", "admin-a", "")
	if w.Code != 200 {
		t.Fatalf("export = %d %s", w.Code, w.Body)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "api_key") || strings.Contains(w.Body.String(), "pdns_id") {
		t.Fatalf("export carries server internals: %s", w.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || len(doc["zones"].([]any)) != 1 {
		t.Fatalf("export body = %s", w.Body)
	}
	raw := w.Body.String()
	if w := h.do("POST", p+"/backup/export", "admin-a", `{}`); w.Code != 200 {
		t.Fatalf("export {} = %d", w.Code)
	}
	w = h.do("POST", p+"/backup/import", "admin-a", `{"backup":`+raw+`}`)
	if w.Code != 200 {
		t.Fatalf("import = %d %s", w.Code, w.Body)
	}
	var res struct {
		TenantID string         `json:"tenant_id"`
		Mode     string         `json:"mode"`
		Skipped  map[string]int `json:"skipped"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.TenantID != tenantA || res.Mode != "skip" || res.Skipped["zones"] != 1 {
		t.Fatalf("import result = %s", w.Body)
	}
	// refusals
	for _, c := range []struct{ tok, path, body, want string }{
		{"viewer-a", "/backup/export", "", "forbidden"},
		{"admin-b", "/backup/export", `{"tenant_id":"` + tenantA + `"}`, "forbidden"},
		{"admin-b", "/backup/import", `{"backup":` + raw + `,"tenant_id":"` + tenantA + `"}`, "forbidden"},
		{"admin-a", "/backup/import", `{"backup":` + raw + `,"full":true}`, "forbidden"},
		{"admin-a", "/backup/import", `{"backup":{"schema_version":7}}`, "validation_failed"},
		{"admin-a", "/backup/import", `{"backup":{"schema_version":1,"zones":[{"id":"x","name":"com.","kind":"native"}]}}`, "validation_failed"},
	} {
		w := h.do("POST", p+c.path, c.tok, c.body)
		if got := reason(t, w); got != c.want {
			t.Errorf("%s %s: %d %s, want %s", c.tok, c.path, w.Code, got, c.want)
		}
	}
	// the platform admin may restore into another tenant: A's zone stays A's
	w = h.do("POST", p+"/backup/import", "platform-a", `{"backup":`+raw+`,"tenant_id":"`+tenantB+`","mode":"overwrite"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"zones":1`) {
		t.Fatalf("cross-tenant import = %d %s", w.Code, w.Body)
	}
}

func TestStreamRoute(t *testing.T) {
	h, hub := newBackupHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest("GET", p+"/stream", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer viewer-a")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.s.Handler().ServeHTTP(w, r); close(done) }()
	time.Sleep(100 * time.Millisecond)
	_ = hub.Publish(context.Background(), tenantA, nil, true, "dns.zone.created", map[string]string{"zone": "a.example."})
	<-done
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "dns.zone.created") {
		t.Fatalf("event not relayed: %q", w.Body.String())
	}
	if w := h.do("GET", p+"/stream", "", ""); w.Code != 401 {
		t.Fatalf("anonymous stream = %d", w.Code)
	}
}
