package dashboard

// T087: the curated dashboard — window → range/step mapping, unknown windows
// refused, ONLY catalogue expressions reach the metrics client, "unavailable"
// without a metrics URL, one failing panel never fails the rest, bounded
// concurrency and an overall timeout.

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
)

const tenant = "11111111-1111-7111-8111-111111111111"

var viewer = authz.User(tenant, "viewer", nil)

func TestWindows(t *testing.T) {
	for in, want := range map[string][2]time.Duration{"1h": {time.Hour, 60 * time.Second}, "6h": {6 * time.Hour, 300 * time.Second}, "24h": {24 * time.Hour, 900 * time.Second}, "": {time.Hour, 60 * time.Second}} {
		w, err := ParseWindow(in)
		if err != nil || w.Range != want[0] || w.Step != want[1] {
			t.Errorf("%q = %+v %v", in, w, err)
		}
	}
	for _, bad := range []string{"2h", "1d", "7d", "1h;drop", "60"} {
		if _, err := ParseWindow(bad); !errors.Is(err, ErrWindow) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCatalogueIsFixed(t *testing.T) {
	c := Catalogue()
	if len(c) < 10 {
		t.Fatalf("catalogue = %d panels", len(c))
	}
	ids := map[string]bool{}
	for _, p := range c {
		if ids[p.ID] || p.ID == "" || (p.Kind != KindStat && p.Kind != KindSeries) || len(p.Queries) == 0 {
			t.Fatalf("bad panel %+v", p)
		}
		ids[p.ID] = true
		for _, q := range p.Queries {
			if !strings.Contains(q.Expr, "pdns_") {
				t.Fatalf("panel %s queries %q", p.ID, q.Expr)
			}
		}
	}
	for _, want := range []string{"recursor_qps", "recursor_cache_hit", "recursor_answers", "recursor_latency", "auth_qps", "auth_errors"} {
		if !ids[want] {
			t.Errorf("catalogue lacks %s", want)
		}
	}
	c[0].Queries[0].Expr = "up"
	if Catalogue()[0].Queries[0].Expr == "up" {
		t.Fatal("catalogue is mutable")
	}
}

func fakeWithData() *Fake {
	f := NewFake()
	for _, p := range Catalogue() {
		for _, q := range p.Queries {
			if p.Kind == KindStat {
				f.Instant[q.Expr] = []Sample{{Labels: map[string]string{}, Value: 42}}
			} else {
				f.Range[q.Expr] = []Series{{Labels: map[string]string{"instance": "rec"}, Points: [][2]float64{{1, 2}, {61, 3}}}}
			}
		}
	}
	return f
}

func TestDashboardRunsOnlyTheCatalogue(t *testing.T) {
	f := fakeWithData()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	s := New(Deps{Client: f, Now: func() time.Time { return now }})
	res, err := s.Get(context.Background(), viewer, "6h")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Available || res.Window != "6h" || res.StepSeconds != 300 || len(res.Panels) != len(Catalogue()) {
		t.Fatalf("result = %+v", res)
	}
	var want []string
	for _, p := range Catalogue() {
		for _, q := range p.Queries {
			want = append(want, q.Expr)
		}
	}
	got := f.Exprs()
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("queried:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range f.Ranges() {
		if r.Step != 300*time.Second || !r.End.Equal(now) || !r.Start.Equal(now.Add(-6*time.Hour)) {
			t.Fatalf("range call = %+v", r)
		}
	}
	for _, p := range res.Panels {
		switch p.Kind {
		case KindStat:
			if p.Value == nil || *p.Value != 42 {
				t.Fatalf("stat %s = %+v", p.ID, p)
			}
		case KindSeries:
			if len(p.Series) == 0 || p.Series[0].Labels["series"] == "" || len(p.Series[0].Points) != 2 {
				t.Fatalf("series %s = %+v", p.ID, p)
			}
		}
	}
	if _, err := s.Get(context.Background(), viewer, "30d"); !errors.Is(err, ErrWindow) {
		t.Fatalf("bad window = %v", err)
	}
}

func TestUnavailableWithoutClient(t *testing.T) {
	res, err := New(Deps{}).Get(context.Background(), viewer, "1h")
	if err != nil || res.Available || res.Window != "1h" || len(res.Panels) != 0 {
		t.Fatalf("no client = %+v %v", res, err)
	}
}

func TestOnePanelFailureIsIsolated(t *testing.T) {
	f := fakeWithData()
	c := Catalogue()
	f.Err[c[2].Queries[0].Expr] = errors.New("prometheus: 500") // used by one panel only
	// NaN / Inf values are dropped (not JSON-encodable).
	f.Instant[c[1].Queries[0].Expr] = []Sample{{Value: math.NaN()}}
	res, err := New(Deps{Client: f}).Get(context.Background(), viewer, "1h")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Panels[2].Unavailable || res.Panels[2].Value != nil {
		t.Fatalf("failing panel = %+v", res.Panels[2])
	}
	if res.Panels[1].Value != nil || res.Panels[1].Unavailable {
		t.Fatalf("NaN panel = %+v", res.Panels[1])
	}
	ok := 0
	for i, p := range res.Panels {
		if i != 2 && !p.Unavailable {
			ok++
		}
	}
	if ok != len(res.Panels)-1 {
		t.Fatalf("other panels failed: %+v", res.Panels)
	}
}

func TestSeriesCapAndNonFinitePoints(t *testing.T) {
	f := fakeWithData()
	var sp Panel
	for _, p := range Catalogue() {
		if p.Kind == KindSeries {
			sp = p
			break
		}
	}
	many := make([]Series, 50)
	for i := range many {
		many[i] = Series{Labels: map[string]string{"i": string(rune('a' + i%26))}, Points: [][2]float64{{1, math.Inf(1)}, {2, 1}}}
	}
	f.Range[sp.Queries[0].Expr] = many
	res, _ := New(Deps{Client: f, MaxSeries: 5}).Get(context.Background(), viewer, "1h")
	for _, p := range res.Panels {
		if p.ID == sp.ID {
			if len(p.Series) != 5 || len(p.Series[0].Points) != 1 {
				t.Fatalf("capped = %d series, %d points", len(p.Series), len(p.Series[0].Points))
			}
		}
	}
}

func TestBoundedConcurrencyAndTimeout(t *testing.T) {
	f := fakeWithData()
	var cur, peak atomic.Int32
	f.Hook = func(ctx context.Context) error {
		n := cur.Add(1)
		defer cur.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-time.After(5 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if _, err := New(Deps{Client: f, Concurrency: 2}).Get(context.Background(), viewer, "1h"); err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency = %d", peak.Load())
	}
	// A hung metrics backend is cut off by the overall timeout.
	f.Hook = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	start := time.Now()
	res, err := New(Deps{Client: f, Timeout: 50 * time.Millisecond}).Get(context.Background(), viewer, "1h")
	if err != nil || time.Since(start) > 2*time.Second {
		t.Fatalf("timeout = %v after %v", err, time.Since(start))
	}
	for _, p := range res.Panels {
		if !p.Unavailable {
			t.Fatalf("panel %s not marked unavailable", p.ID)
		}
	}
}

func TestPermission(t *testing.T) {
	checker := authz.Static{"viewer": {authz.DashboardRead}}
	s := New(Deps{Client: fakeWithData(), Checker: checker})
	if _, err := s.Get(context.Background(), viewer, "1h"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), authz.User(tenant, "nobody", nil), "1h"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no permission = %v", err)
	}
}

func TestUnreachablePrometheusIsUnavailable(t *testing.T) {
	f := NewFake()
	f.Hook = func(context.Context) error { return errors.New("dial tcp: connection refused") }
	res, err := New(Deps{Client: f}).Get(context.Background(), viewer, "1h")
	if err != nil || res.Available || len(res.Panels) != 0 {
		t.Fatalf("unreachable prometheus = %+v %v", res, err)
	}
}
