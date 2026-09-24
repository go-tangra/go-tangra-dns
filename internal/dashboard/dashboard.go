package dashboard

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
)

// ErrWindow refuses a window outside {1h, 6h, 24h}.
var ErrWindow = errors.New("dashboard: window must be 1h, 6h or 24h")

// Window is a bounded range and step.
type Window struct {
	Name  string
	Range time.Duration
	Step  time.Duration
}

var windows = map[string]Window{
	"1h":  {"1h", time.Hour, 60 * time.Second},
	"6h":  {"6h", 6 * time.Hour, 300 * time.Second},
	"24h": {"24h", 24 * time.Hour, 900 * time.Second},
}

// ParseWindow maps a window name to its range and step ("" = 1h).
func ParseWindow(s string) (Window, error) {
	if s == "" {
		s = "1h"
	}
	w, ok := windows[s]
	if !ok {
		return Window{}, ErrWindow
	}
	return w, nil
}

// SeriesData is one series of a panel.
type SeriesData struct {
	Labels map[string]string `json:"labels"`
	Points [][2]float64      `json:"points"`
}

// PanelData is one panel of the response.
type PanelData struct {
	ID          string       `json:"id"`
	Kind        Kind         `json:"kind"`
	Unit        string       `json:"unit,omitempty"`
	Value       *float64     `json:"value,omitempty"`
	Series      []SeriesData `json:"series,omitempty"`
	Unavailable bool         `json:"unavailable,omitempty"`
}

// Result is the GET /dashboard response.
type Result struct {
	Available   bool        `json:"available"`
	Window      string      `json:"window"`
	StepSeconds int         `json:"step_seconds"`
	Panels      []PanelData `json:"panels"`
}

// Deps wire the service; a nil Client means metrics are not configured.
type Deps struct {
	Client      MetricsClient
	Checker     authz.Checker
	Concurrency int           // parallel queries (default 4)
	Timeout     time.Duration // whole refresh (default 10 s)
	MaxSeries   int           // per panel (default 20)
	Now         func() time.Time
	Log         *slog.Logger
}

// Service runs the catalogue.
type Service struct{ d Deps }

// New builds the service.
func New(d Deps) *Service {
	if d.Concurrency <= 0 {
		d.Concurrency = 4
	}
	if d.Timeout <= 0 {
		d.Timeout = 10 * time.Second
	}
	if d.MaxSeries <= 0 {
		d.MaxSeries = 20
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	return &Service{d: d}
}

// Get runs every catalogue panel over the window. One failing panel is
// marked unavailable without failing the others; when every panel fails the
// result is {available: false}.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, window string) (Result, error) {
	if s.d.Checker != nil {
		if err := authz.Require(ctx, s.d.Checker, subj, authz.DashboardRead); err != nil {
			return Result{}, err
		}
	}
	w, err := ParseWindow(window)
	if err != nil {
		return Result{}, err
	}
	res := Result{Window: w.Name, StepSeconds: int(w.Step / time.Second), Panels: []PanelData{}}
	if s.d.Client == nil {
		return res, nil
	}
	res.Available = true
	ctx, cancel := context.WithTimeout(ctx, s.d.Timeout)
	defer cancel()
	end := s.d.Now()
	cat := Catalogue()
	res.Panels = make([]PanelData, len(cat))
	sem := make(chan struct{}, s.d.Concurrency)
	done := make(chan struct{}, len(cat))
	for i, p := range cat {
		go func(i int, p Panel) {
			defer func() { done <- struct{}{} }()
			res.Panels[i] = s.panel(ctx, sem, p, end, w)
		}(i, p)
	}
	for range cat {
		<-done
	}
	// A configured but unreachable Prometheus (every panel failed) is the same
	// as no metrics: the UI shows its "metrics unavailable" notice.
	for _, p := range res.Panels {
		if !p.Unavailable {
			return res, nil
		}
	}
	res.Available, res.Panels = false, []PanelData{}
	return res, nil
}

// acquire takes a concurrency slot (false when ctx ended first).
func acquire(ctx context.Context, sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Service) panel(ctx context.Context, sem chan struct{}, p Panel, end time.Time, w Window) PanelData {
	out := PanelData{ID: p.ID, Kind: p.Kind, Unit: p.Unit}
	for _, q := range p.Queries {
		if !acquire(ctx, sem) {
			out.Unavailable, out.Value, out.Series = true, nil, nil
			return out
		}
		err := s.run(ctx, &out, p, q, end, w)
		<-sem
		if err != nil {
			s.d.Log.WarnContext(ctx, "dashboard panel query failed", "panel", p.ID, "err", err)
			out.Unavailable, out.Value, out.Series = true, nil, nil
			return out
		}
	}
	return out
}

func (s *Service) run(ctx context.Context, out *PanelData, p Panel, q Query, end time.Time, w Window) error {
	if p.Kind == KindStat {
		samples, err := s.d.Client.Query(ctx, q.Expr, end)
		if err != nil {
			return err
		}
		for _, smp := range samples {
			if !math.IsNaN(smp.Value) && !math.IsInf(smp.Value, 0) {
				v := smp.Value
				out.Value = &v
				break
			}
		}
		return nil
	}
	series, err := s.d.Client.QueryRange(ctx, q.Expr, end.Add(-w.Range), end, w.Step)
	if err != nil {
		return err
	}
	for _, sr := range series {
		if len(out.Series) >= s.d.MaxSeries {
			break
		}
		labels := map[string]string{}
		keys := make([]string, 0, len(sr.Labels))
		for k := range sr.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			labels[k] = sr.Labels[k]
		}
		labels["series"] = q.Label
		pts := make([][2]float64, 0, len(sr.Points))
		for _, pt := range sr.Points {
			if !math.IsNaN(pt[1]) && !math.IsInf(pt[1], 0) {
				pts = append(pts, pt)
			}
		}
		out.Series = append(out.Series, SeriesData{Labels: labels, Points: pts})
	}
	return nil
}
