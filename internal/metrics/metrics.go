// Package metrics holds the DNS module's Prometheus instruments (plan
// Constitution V). They are created on the framework's meter (freya
// App.Metrics().Meter), so the admin listener's /metrics renders them next to
// the framework instruments:
//
//	dns_pdns_calls_total{op,result}          PowerDNS API calls by outcome
//	dns_pdns_call_seconds{op}                PowerDNS API call latency (histogram)
//	dns_recursor_sync_total{result}          recursor forward syncs/removals
//	dns_ipam_sync_total{action,result}       IPAM-driven record changes
//	dns_config_restarts_total{target,result} container restarts (auth|recursor)
//	dns_challenges_total{op,result}          ACME DNS-01 present/cleanup/sweep
//	dns_pdns_unowned_zones                   PowerDNS zones with no local owner
//
// Labels carry closed vocabularies only (never tenants, zone names, addresses
// or ids). Every method is nil-safe so services can run without metrics in tests.
package metrics

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Scope is the instrumentation scope name.
const Scope = "github.com/go-tangra/go-tangra-dns/v4"

// Results (closed set).
const (
	ResultOK          = "ok"
	ResultNotFound    = "not_found"
	ResultConflict    = "conflict"
	ResultUnavailable = "unavailable"
	ResultRefused     = "refused"
	ResultSkipped     = "skipped"
	ResultError       = "error"
)

// Restart targets.
const (
	TargetAuth     = "auth"
	TargetRecursor = "recursor"
)

// Metrics are the module instruments.
type Metrics struct {
	pdnsCalls  metric.Int64Counter
	pdnsTime   metric.Float64Histogram
	recursor   metric.Int64Counter
	ipamSync   metric.Int64Counter
	restarts   metric.Int64Counter
	challenges metric.Int64Counter
	unowned    metric.Int64UpDownCounter

	mu          sync.Mutex
	lastUnowned int64
}

// New creates the instruments on meter.
func New(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error
	counters := []struct {
		dst  *metric.Int64Counter
		name string
		desc string
	}{
		{&m.pdnsCalls, "dns.pdns.calls", "PowerDNS API calls by operation and result"},
		{&m.recursor, "dns.recursor.sync", "Recursor forward-zone syncs by result"},
		{&m.ipamSync, "dns.ipam.sync", "IPAM-driven record changes by action and result"},
		{&m.restarts, "dns.config.restarts", "DNS container restarts by target and result"},
		{&m.challenges, "dns.challenges", "ACME DNS-01 challenge operations by result"},
	}
	for _, c := range counters {
		if *c.dst, err = meter.Int64Counter(c.name, metric.WithDescription(c.desc)); err != nil {
			return nil, err
		}
	}
	if m.pdnsTime, err = meter.Float64Histogram("dns.pdns.call", metric.WithUnit("s"), metric.WithDescription("PowerDNS API call latency"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)); err != nil {
		return nil, err
	}
	if m.unowned, err = meter.Int64UpDownCounter("dns.pdns.unowned.zones", metric.WithDescription("PowerDNS zones with no local owner (never adopted)")); err != nil {
		return nil, err
	}
	return m, nil
}

func add(c metric.Int64Counter, attrs ...attribute.KeyValue) {
	c.Add(context.Background(), 1, metric.WithAttributes(attrs...))
}

// PDNSCall records one PowerDNS API call.
func (m *Metrics) PDNSCall(op, result string, d time.Duration) {
	if m == nil {
		return
	}
	add(m.pdnsCalls, attribute.String("op", op), attribute.String("result", result))
	m.pdnsTime.Record(context.Background(), d.Seconds(), metric.WithAttributes(attribute.String("op", op)))
}

// RecursorSync records one forward sync/removal.
func (m *Metrics) RecursorSync(result string) {
	if m != nil {
		add(m.recursor, attribute.String("result", result))
	}
}

// IPAMSync records one IPAM-driven change (action upsert|delete|skip).
func (m *Metrics) IPAMSync(action, result string) {
	if m != nil {
		add(m.ipamSync, attribute.String("action", action), attribute.String("result", result))
	}
}

// Restart records one container restart (target auth|recursor).
func (m *Metrics) Restart(target, result string) {
	if m != nil {
		add(m.restarts, attribute.String("target", target), attribute.String("result", result))
	}
}

// Challenge records one ACME challenge operation (op present|cleanup|sweep).
func (m *Metrics) Challenge(op, result string) {
	if m != nil {
		add(m.challenges, attribute.String("op", op), attribute.String("result", result))
	}
}

// SetUnownedZones sets the gauge of PowerDNS zones with no local owner.
func (m *Metrics) SetUnownedZones(n int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unowned.Add(context.Background(), n-m.lastUnowned)
	m.lastUnowned = n
}
