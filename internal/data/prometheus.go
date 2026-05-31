package data

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// PrometheusClient is a tiny client over the Prometheus HTTP API. We avoid
// pulling in github.com/prometheus/client_golang/api/v1 — its transitive
// graph is heavy and we only need two endpoints.
//
// The configured URL is the base, e.g. "http://prometheus:9090"; Query and
// QueryRange append /api/v1/query and /api/v1/query_range respectively.
type PrometheusClient struct {
	base string
	http *http.Client
}

// NewPrometheusClient returns nil when no URL is configured; callers
// must treat that as "feature disabled". The URL comes from the
// PROMETHEUS_URL env var at wire time so this module degrades
// gracefully in deployments without a Prometheus.
func NewPrometheusClient() *PrometheusClient {
	url := os.Getenv("PROMETHEUS_URL")
	if url == "" {
		return nil
	}
	return &PrometheusClient{
		base: url,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// Sample is a single (timestamp, value) point. NaN/Inf are normalised to
// HasValue=false so JSON encoding stays well-formed downstream.
type Sample struct {
	Time     time.Time
	Value    float64
	HasValue bool
}

// InstantSeries pairs a label set with a single sample.
type InstantSeries struct {
	Labels map[string]string
	Sample Sample
}

// RangeSeries pairs a label set with a stream of samples.
type RangeSeries struct {
	Labels  map[string]string
	Samples []Sample
}

// Query evaluates a PromQL expression at a single instant. ts==zero means
// "server now".
func (p *PrometheusClient) Query(ctx context.Context, query string, ts time.Time) ([]InstantSeries, error) {
	if p == nil {
		return nil, fmt.Errorf("prometheus client not configured")
	}
	v := url.Values{"query": {query}}
	if !ts.IsZero() {
		v.Set("time", strconv.FormatFloat(float64(ts.UnixNano())/1e9, 'f', 3, 64))
	}
	body, err := p.do(ctx, "/api/v1/query", v)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Status    string `json:"status"`
		ErrorType string `json:"errorType"`
		Error     string `json:"error"`
		Data      struct {
			ResultType string            `json:"resultType"`
			Result     []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("prometheus error: %s — %s", resp.ErrorType, resp.Error)
	}

	switch resp.Data.ResultType {
	case "vector":
		out := make([]InstantSeries, 0, len(resp.Data.Result))
		for _, raw := range resp.Data.Result {
			var item struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				return nil, fmt.Errorf("decode vector item: %w", err)
			}
			s, err := decodeSample(item.Value)
			if err != nil {
				return nil, err
			}
			out = append(out, InstantSeries{Labels: item.Metric, Sample: s})
		}
		return out, nil
	case "scalar":
		var pair [2]any
		if err := json.Unmarshal(resp.Data.Result[0], &pair); err != nil {
			return nil, fmt.Errorf("decode scalar: %w", err)
		}
		s, err := decodeSample(pair)
		if err != nil {
			return nil, err
		}
		return []InstantSeries{{Labels: map[string]string{}, Sample: s}}, nil
	default:
		return nil, fmt.Errorf("unsupported instant result type %q", resp.Data.ResultType)
	}
}

// QueryRange evaluates a PromQL expression over a time window with a fixed
// step. start, end, step are required; step must be positive.
func (p *PrometheusClient) QueryRange(ctx context.Context, query string, start, end time.Time, step time.Duration) ([]RangeSeries, error) {
	if p == nil {
		return nil, fmt.Errorf("prometheus client not configured")
	}
	if step <= 0 {
		return nil, fmt.Errorf("step must be positive")
	}
	v := url.Values{
		"query": {query},
		"start": {strconv.FormatFloat(float64(start.UnixNano())/1e9, 'f', 3, 64)},
		"end":   {strconv.FormatFloat(float64(end.UnixNano())/1e9, 'f', 3, 64)},
		"step":  {strconv.FormatFloat(step.Seconds(), 'f', 3, 64)},
	}
	body, err := p.do(ctx, "/api/v1/query_range", v)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Status    string `json:"status"`
		ErrorType string `json:"errorType"`
		Error     string `json:"error"`
		Data      struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("prometheus error: %s — %s", resp.ErrorType, resp.Error)
	}
	if resp.Data.ResultType != "matrix" {
		return nil, fmt.Errorf("unsupported range result type %q", resp.Data.ResultType)
	}

	out := make([]RangeSeries, 0, len(resp.Data.Result))
	for _, item := range resp.Data.Result {
		series := RangeSeries{Labels: item.Metric, Samples: make([]Sample, 0, len(item.Values))}
		for _, pair := range item.Values {
			s, err := decodeSample(pair)
			if err != nil {
				return nil, err
			}
			series.Samples = append(series.Samples, s)
		}
		out = append(out, series)
	}
	return out, nil
}

func (p *PrometheusClient) do(ctx context.Context, path string, params url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call prometheus: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("prometheus http %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// decodeSample converts a Prometheus [timestamp, "value"] pair into our
// Sample struct. The timestamp is a float64 unix-seconds; the value is a
// string so that NaN/Inf round-trip — we treat those as missing samples.
func decodeSample(pair [2]any) (Sample, error) {
	tsRaw, ok := pair[0].(float64)
	if !ok {
		return Sample{}, fmt.Errorf("timestamp not a number: %T", pair[0])
	}
	valRaw, ok := pair[1].(string)
	if !ok {
		return Sample{}, fmt.Errorf("value not a string: %T", pair[1])
	}
	sec := int64(tsRaw)
	nsec := int64((tsRaw - float64(sec)) * 1e9)
	s := Sample{Time: time.Unix(sec, nsec).UTC()}
	v, err := strconv.ParseFloat(valRaw, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return s, nil
	}
	s.Value = v
	s.HasValue = true
	return s, nil
}
