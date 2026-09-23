package contract

// T089: the dashboard over the full HTTP chain — response shape (validated
// against the document), dashboard:read required, only the window parameter
// (no query text) and "unavailable" without a metrics endpoint.

import (
	"encoding/json"
	"testing"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/dashboard"
	"github.com/go-freya/freya/services/dns/internal/httpapi"
)

func newDashboardHarness(t *testing.T, client dashboard.MetricsClient) *harness {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := verifier{
		"viewer-a": {UserID: viewerA, TenantID: tenantA},
		"admin-b":  {UserID: adminB, TenantID: tenantB},
	}
	checker := authz.Static{viewerA: {authz.ZonesRead, authz.DashboardRead}, adminB: {authz.ZonesRead}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(checker))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.s = s
	s.Register(httpapi.Deps{Dashboard: dashboard.New(dashboard.Deps{Client: client, Checker: checker})})
	return h
}

type dashJSON struct {
	Available   bool   `json:"available"`
	Window      string `json:"window"`
	StepSeconds int    `json:"step_seconds"`
	Panels      []struct {
		ID          string   `json:"id"`
		Kind        string   `json:"kind"`
		Value       *float64 `json:"value"`
		Unavailable bool     `json:"unavailable"`
		Series      []struct {
			Labels map[string]string `json:"labels"`
			Points [][2]float64      `json:"points"`
		} `json:"series"`
	} `json:"panels"`
}

func TestDashboardShape(t *testing.T) {
	f := dashboard.NewFake()
	for _, p := range dashboard.Catalogue() {
		for _, q := range p.Queries {
			f.Instant[q.Expr] = []dashboard.Sample{{Value: 7}}
			f.Range[q.Expr] = []dashboard.Series{{Labels: map[string]string{}, Points: [][2]float64{{1, 1}}}}
		}
	}
	h := newDashboardHarness(t, f)
	for window, step := range map[string]int{"1h": 60, "6h": 300, "24h": 900} {
		w := h.do("GET", p+"/dashboard?window="+window, "viewer-a", "")
		if w.Code != 200 {
			t.Fatalf("%s = %d %s", window, w.Code, w.Body)
		}
		var d dashJSON
		_ = json.Unmarshal(w.Body.Bytes(), &d)
		if !d.Available || d.Window != window || d.StepSeconds != step || len(d.Panels) != len(dashboard.Catalogue()) {
			t.Fatalf("%s = %s", window, w.Body)
		}
	}
	if w := h.do("GET", p+"/dashboard", "viewer-a", ""); w.Code != 200 {
		t.Fatalf("default window = %d", w.Code)
	}
}

func TestDashboardRefusals(t *testing.T) {
	f := dashboard.NewFake()
	h := newDashboardHarness(t, f)
	if w := h.do("GET", p+"/dashboard?window=1h", "admin-b", ""); w.Code != 403 {
		t.Fatalf("without dashboard:read = %d", w.Code)
	}
	if w := h.do("GET", p+"/dashboard?window=1h", "", ""); w.Code != 401 {
		t.Fatalf("anonymous = %d", w.Code)
	}
	for _, q := range []string{"?window=7d", "?window=1h&query=up", "?query=up", "?window=1h&window=6h", "?expr=pdns_recursor_questions"} {
		w := h.do("GET", p+"/dashboard"+q, "viewer-a", "")
		if w.Code != 400 && w.Code != 422 {
			t.Errorf("%s = %d %s", q, w.Code, w.Body)
		}
	}
	for _, e := range f.Exprs() {
		if e == "up" {
			t.Fatal("caller text reached the metrics client")
		}
	}
	// The document declares no parameter but the window.
	doc, _ := httpapi.LoadDocument()
	op := doc.Paths.Find("/api/dns/v1/dashboard").Get
	if len(op.Parameters) != 1 || op.Parameters[0].Value.Name != "window" {
		t.Fatalf("dashboard parameters = %+v", op.Parameters)
	}
}

func TestDashboardUnavailable(t *testing.T) {
	h := newDashboardHarness(t, nil)
	w := h.do("GET", p+"/dashboard?window=24h", "viewer-a", "")
	var d dashJSON
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if w.Code != 200 || d.Available || len(d.Panels) != 0 {
		t.Fatalf("unavailable = %d %s", w.Code, w.Body)
	}
}
