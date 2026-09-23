package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics-client errors (the server's error text is never surfaced).
var (
	ErrQuery       = errors.New("dashboard: metrics query failed")
	ErrTooLarge    = errors.New("dashboard: metrics response too large")
	ErrUnreachable = errors.New("dashboard: metrics endpoint unreachable")
)

// Sample is one instant value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Series is one range series of [unix seconds, value] points.
type Series struct {
	Labels map[string]string
	Points [][2]float64
}

// MetricsClient runs catalogue expressions against a Prometheus-compatible
// API. It is only ever called with catalogue expressions.
type MetricsClient interface {
	Query(ctx context.Context, expr string, at time.Time) ([]Sample, error)
	QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) ([]Series, error)
}

// PromConfig configures the Prometheus HTTP API client.
type PromConfig struct {
	BaseURL  string        // http(s)://host[:port][/prefix]
	Timeout  time.Duration // per request (default 10 s)
	MaxBytes int64         // response cap (default 4 MiB)
}

// Prom is a stdlib client of the Prometheus HTTP API (/api/v1/query and
// /api/v1/query_range, GET only).
type Prom struct {
	base string
	max  int64
	http *http.Client
}

var _ MetricsClient = (*Prom)(nil)

// NewProm validates the base URL and builds the client.
func NewProm(c PromConfig) (*Prom, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("dashboard: metrics URL must be an http(s) base URL without credentials, query or fragment")
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = 4 << 20
	}
	return &Prom{base: strings.TrimSuffix(c.BaseURL, "/"), max: c.MaxBytes, http: &http.Client{Timeout: c.Timeout}}, nil
}

type apiResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

func (p *Prom) get(ctx context.Context, path string, q url.Values) (apiResponse, error) {
	var out apiResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return out, fmt.Errorf("%w: request", ErrQuery)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return out, ErrUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.max+1))
	if err != nil {
		return out, ErrUnreachable
	}
	if int64(len(body)) > p.max {
		return out, ErrTooLarge
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%w: status %d", ErrQuery, resp.StatusCode)
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Status != "success" {
		return out, fmt.Errorf("%w: bad response", ErrQuery)
	}
	return out, nil
}

// point decodes a [ts, "value"] pair.
func point(raw []json.RawMessage) (float64, float64, error) {
	if len(raw) != 2 {
		return 0, 0, fmt.Errorf("%w: bad sample", ErrQuery)
	}
	var ts float64
	var sv string
	if json.Unmarshal(raw[0], &ts) != nil || json.Unmarshal(raw[1], &sv) != nil {
		return 0, 0, fmt.Errorf("%w: bad sample", ErrQuery)
	}
	v, err := strconv.ParseFloat(sv, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: bad value", ErrQuery)
	}
	return ts, v, nil
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Query runs an instant query at the given time.
func (p *Prom) Query(ctx context.Context, expr string, at time.Time) ([]Sample, error) {
	r, err := p.get(ctx, "/api/v1/query", url.Values{"query": {expr}, "time": {strconv.FormatInt(at.Unix(), 10)}})
	if err != nil {
		return nil, err
	}
	switch r.Data.ResultType {
	case "vector":
		var vec []struct {
			Metric map[string]string `json:"metric"`
			Value  []json.RawMessage `json:"value"`
		}
		if json.Unmarshal(r.Data.Result, &vec) != nil {
			return nil, fmt.Errorf("%w: bad vector", ErrQuery)
		}
		out := make([]Sample, 0, len(vec))
		for _, s := range vec {
			_, v, err := point(s.Value)
			if err != nil {
				return nil, err
			}
			if finite(v) {
				out = append(out, Sample{Labels: s.Metric, Value: v})
			}
		}
		return out, nil
	case "scalar":
		var raw []json.RawMessage
		if json.Unmarshal(r.Data.Result, &raw) != nil {
			return nil, fmt.Errorf("%w: bad scalar", ErrQuery)
		}
		_, v, err := point(raw)
		if err != nil {
			return nil, err
		}
		if !finite(v) {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{}, Value: v}}, nil
	}
	return nil, fmt.Errorf("%w: unexpected result type", ErrQuery)
}

// QueryRange runs a range query.
func (p *Prom) QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) ([]Series, error) {
	r, err := p.get(ctx, "/api/v1/query_range", url.Values{"query": {expr},
		"start": {strconv.FormatInt(start.Unix(), 10)}, "end": {strconv.FormatInt(end.Unix(), 10)},
		"step": {strconv.FormatInt(int64(step/time.Second), 10)}})
	if err != nil {
		return nil, err
	}
	var mat []struct {
		Metric map[string]string   `json:"metric"`
		Values [][]json.RawMessage `json:"values"`
	}
	if r.Data.ResultType != "matrix" || json.Unmarshal(r.Data.Result, &mat) != nil {
		return nil, fmt.Errorf("%w: unexpected result type", ErrQuery)
	}
	out := make([]Series, 0, len(mat))
	for _, m := range mat {
		s := Series{Labels: m.Metric, Points: make([][2]float64, 0, len(m.Values))}
		for _, raw := range m.Values {
			ts, v, err := point(raw)
			if err != nil {
				return nil, err
			}
			if finite(v) {
				s.Points = append(s.Points, [2]float64{ts, v})
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// RangeCall records one QueryRange of the Fake.
type RangeCall struct {
	Expr       string
	Start, End time.Time
	Step       time.Duration
}

// Fake is an in-memory MetricsClient that records every expression.
type Fake struct {
	mu      sync.Mutex
	Instant map[string][]Sample
	Range   map[string][]Series
	Err     map[string]error
	// Hook runs on every call (latency / cancellation tests).
	Hook   func(ctx context.Context) error
	exprs  []string
	ranges []RangeCall
}

var _ MetricsClient = (*Fake)(nil)

// NewFake builds an empty fake.
func NewFake() *Fake {
	return &Fake{Instant: map[string][]Sample{}, Range: map[string][]Series{}, Err: map[string]error{}}
}

func (f *Fake) begin(ctx context.Context, expr string) error {
	f.mu.Lock()
	f.exprs = append(f.exprs, expr)
	hook, err := f.Hook, f.Err[expr]
	f.mu.Unlock()
	if hook != nil {
		if herr := hook(ctx); herr != nil {
			return herr
		}
	}
	return err
}

// Query implements MetricsClient.
func (f *Fake) Query(ctx context.Context, expr string, _ time.Time) ([]Sample, error) {
	if err := f.begin(ctx, expr); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Sample(nil), f.Instant[expr]...), nil
}

// QueryRange implements MetricsClient.
func (f *Fake) QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration) ([]Series, error) {
	f.mu.Lock()
	f.ranges = append(f.ranges, RangeCall{Expr: expr, Start: start, End: end, Step: step})
	f.mu.Unlock()
	if err := f.begin(ctx, expr); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Series(nil), f.Range[expr]...), nil
}

// Exprs lists every expression queried so far.
func (f *Fake) Exprs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.exprs...)
}

// Ranges lists every range call so far.
func (f *Fake) Ranges() []RangeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RangeCall(nil), f.ranges...)
}
