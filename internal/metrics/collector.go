package metrics

import (
	"context"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	commonMetrics "github.com/go-tangra/go-tangra-common/metrics"
)

const (
	namespace = "tangra"
	subsystem = "dns"
)

// Collector holds all Prometheus metrics for the dns module.
type Collector struct {
	log    *log.Helper
	server *commonMetrics.MetricsServer

	// Domain gauges
	ZonesTotal      prometheus.Gauge
	SupermastersTotal prometheus.Gauge

	// gRPC request metrics
	RequestDuration *prometheus.HistogramVec
	RequestsTotal   *prometheus.CounterVec
}

// NewCollector creates and registers all dns Prometheus metrics.
func NewCollector(ctx *bootstrap.Context) *Collector {
	c := &Collector{
		log: ctx.NewLoggerHelper("dns/metrics"),

		ZonesTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "zones_total",
			Help:      "Total number of managed DNS zones.",
		}),

		SupermastersTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "supermasters_total",
			Help:      "Total number of configured supermasters.",
		}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "grpc_request_duration_seconds",
			Help:      "Histogram of gRPC request durations in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method"}),

		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "grpc_requests_total",
			Help:      "Total number of gRPC requests by method and status.",
		}, []string{"method", "status"}),
	}

	prometheus.MustRegister(
		c.ZonesTotal,
		c.SupermastersTotal,
		c.RequestDuration,
		c.RequestsTotal,
	)

	addr := os.Getenv("METRICS_ADDR")
	if addr == "" {
		addr = ":9810"
	}
	c.server = commonMetrics.NewMetricsServer(addr, nil, ctx.GetLogger())

	go func() {
		if err := c.server.Start(); err != nil {
			c.log.Errorf("Metrics server failed: %v", err)
		}
	}()

	return c
}

// Stop shuts down the metrics HTTP server.
func (c *Collector) Stop(ctx context.Context) {
	if c.server != nil {
		c.server.Stop(ctx)
	}
}

// Middleware returns a Kratos middleware that records gRPC request metrics.
func (c *Collector) Middleware() middleware.Middleware {
	return commonMetrics.NewServerMiddleware(c.RequestDuration, c.RequestsTotal)
}
