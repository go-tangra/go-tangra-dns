package service

import (
	"context"
	"time"

	kratoserr "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/protobuf/types/known/timestamppb"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/data"
)

// DashboardService is a thin Prometheus proxy for DNS metrics (pdns_auth_*,
// pdns_recursor_*). The frontend issues PromQL through these RPCs; this keeps
// the Prometheus API out of the browser and routes dashboard data through the
// same admin gateway as the rest of the module.
type DashboardService struct {
	dnsV1.UnimplementedDnsDashboardServiceServer

	log    *log.Helper
	client *data.PrometheusClient
}

func NewDashboardService(ctx *bootstrap.Context, client *data.PrometheusClient) *DashboardService {
	return &DashboardService{
		log:    ctx.NewLoggerHelper("dns/service/dashboard"),
		client: client,
	}
}

func (s *DashboardService) InstantQuery(ctx context.Context, req *dnsV1.InstantQueryRequest) (*dnsV1.InstantQueryResponse, error) {
	if s.client == nil {
		return nil, kratoserr.New(503, "PROMETHEUS_DISABLED", "prometheus url is not configured")
	}
	if req.GetQuery() == "" {
		return nil, kratoserr.BadRequest("INVALID_ARGUMENT", "query is required")
	}

	var ts time.Time
	if req.GetTime() != nil {
		ts = req.GetTime().AsTime()
	}
	series, err := s.client.Query(ctx, req.GetQuery(), ts)
	if err != nil {
		s.log.WithContext(ctx).Errorf("instant query %q: %v", req.GetQuery(), err)
		return nil, kratoserr.InternalServer("PROMETHEUS_QUERY_FAILED", err.Error())
	}

	out := &dnsV1.InstantQueryResponse{Series: make([]*dnsV1.InstantSample, 0, len(series))}
	for _, sr := range series {
		out.Series = append(out.Series, &dnsV1.InstantSample{
			Labels:    sr.Labels,
			Timestamp: timestamppb.New(sr.Sample.Time),
			Value:     sr.Sample.Value,
			HasValue:  sr.Sample.HasValue,
		})
	}
	return out, nil
}

func (s *DashboardService) RangeQuery(ctx context.Context, req *dnsV1.RangeQueryRequest) (*dnsV1.RangeQueryResponse, error) {
	if s.client == nil {
		return nil, kratoserr.New(503, "PROMETHEUS_DISABLED", "prometheus url is not configured")
	}
	if req.GetQuery() == "" {
		return nil, kratoserr.BadRequest("INVALID_ARGUMENT", "query is required")
	}
	if req.GetStart() == nil || req.GetEnd() == nil {
		return nil, kratoserr.BadRequest("INVALID_ARGUMENT", "start and end are required")
	}
	if req.GetStepSeconds() <= 0 {
		return nil, kratoserr.BadRequest("INVALID_ARGUMENT", "step_seconds must be positive")
	}

	step := time.Duration(req.GetStepSeconds()) * time.Second
	series, err := s.client.QueryRange(ctx, req.GetQuery(), req.GetStart().AsTime(), req.GetEnd().AsTime(), step)
	if err != nil {
		s.log.WithContext(ctx).Errorf("range query %q: %v", req.GetQuery(), err)
		return nil, kratoserr.InternalServer("PROMETHEUS_QUERY_FAILED", err.Error())
	}

	out := &dnsV1.RangeQueryResponse{Series: make([]*dnsV1.RangeSeries, 0, len(series))}
	for _, sr := range series {
		ts := make([]*timestamppb.Timestamp, 0, len(sr.Samples))
		vals := make([]float64, 0, len(sr.Samples))
		for _, sample := range sr.Samples {
			ts = append(ts, timestamppb.New(sample.Time))
			vals = append(vals, sample.Value)
		}
		out.Series = append(out.Series, &dnsV1.RangeSeries{
			Labels:     sr.Labels,
			Timestamps: ts,
			Values:     vals,
		})
	}
	return out, nil
}
