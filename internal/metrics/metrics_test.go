package metrics

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/go-tangra/go-tangra/v4/observe"
)

func TestInstrumentsRenderOnAdminHandler(t *testing.T) {
	fm, err := observe.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(fm.Meter(Scope))
	if err != nil {
		t.Fatal(err)
	}
	m.PDNSCall("GetZone", ResultOK, 20*time.Millisecond)
	m.PDNSCall("GetZone", ResultOK, 30*time.Millisecond)
	m.PDNSCall("CreateZone", ResultUnavailable, time.Second)
	m.RecursorSync(ResultOK)
	m.IPAMSync("upsert", ResultOK)
	m.IPAMSync("skip", ResultSkipped)
	m.Restart(TargetRecursor, ResultOK)
	m.Challenge("present", ResultRefused)
	m.SetUnownedZones(3)
	m.SetUnownedZones(2)
	rec := httptest.NewRecorder()
	fm.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`dns_pdns_calls_total{op="GetZone",result="ok"} 2`,
		`dns_pdns_calls_total{op="CreateZone",result="unavailable"} 1`,
		`dns_pdns_call_seconds_count{op="GetZone"} 2`,
		`dns_recursor_sync_total{result="ok"} 1`,
		`dns_ipam_sync_total{action="upsert",result="ok"} 1`,
		`dns_ipam_sync_total{action="skip",result="skipped"} 1`,
		`dns_config_restarts_total{result="ok",target="recursor"} 1`,
		`dns_challenges_total{op="present",result="refused"} 1`,
		`dns_pdns_unowned_zones 2`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in:\n%s", want, body)
		}
	}
}

func TestNilSafe(t *testing.T) {
	var m *Metrics
	m.PDNSCall("x", ResultError, time.Second)
	m.RecursorSync(ResultError)
	m.IPAMSync("delete", ResultError)
	m.Restart(TargetAuth, ResultError)
	m.Challenge("sweep", ResultOK)
	m.SetUnownedZones(1)
	if _, err := New(noop.NewMeterProvider().Meter("x")); err != nil {
		t.Fatal(err)
	}
}

type failingMeter struct {
	noop.Meter
	failAt int
	n      *int
}

func (f failingMeter) step(name string) error {
	*f.n++
	if *f.n == f.failAt {
		return errors.New("boom " + name)
	}
	return nil
}

func (f failingMeter) Int64Counter(name string, _ ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return noop.Int64Counter{}, f.step(name)
}

func (f failingMeter) Float64Histogram(name string, _ ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	return noop.Float64Histogram{}, f.step(name)
}

func (f failingMeter) Int64UpDownCounter(name string, _ ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	return noop.Int64UpDownCounter{}, f.step(name)
}

func TestNewPropagatesErrors(t *testing.T) {
	for i := 1; i <= 7; i++ {
		n := 0
		if _, err := New(failingMeter{failAt: i, n: &n}); err == nil {
			t.Errorf("instrument %d error swallowed", i)
		}
	}
}
