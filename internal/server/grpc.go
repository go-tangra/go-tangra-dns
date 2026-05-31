package server

import (
	"context"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/metadata"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-common/middleware/audit"
	"github.com/go-tangra/go-tangra-common/middleware/mtls"
	"github.com/go-tangra/go-tangra-common/viewer"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/cert"
	"github.com/go-tangra/go-tangra-dns/internal/metrics"
	"github.com/go-tangra/go-tangra-dns/internal/service"
)

// systemViewerMiddleware injects system viewer context so the dns module can
// bypass tenant privacy checks at the ent level (tenant scoping is enforced
// explicitly in the repositories via the tenant_id metadata).
func systemViewerMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			ctx = viewer.NewSystemViewerContext(ctx)
			return handler(ctx, req)
		}
	}
}

// NewGRPCServer creates a gRPC server with mTLS and audit logging.
func NewGRPCServer(
	ctx *bootstrap.Context,
	certManager *cert.CertManager,
	collector *metrics.Collector,
	zoneSvc *service.ZoneService,
	recordSvc *service.RecordService,
	templateSvc *service.ZoneTemplateService,
	supermasterSvc *service.SupermasterService,
	configSvc *service.ConfigService,
	dashboardSvc *service.DashboardService,
) *grpc.Server {
	cfg := ctx.GetConfig()
	l := ctx.NewLoggerHelper("dns/grpc")

	var opts []grpc.ServerOption

	if cfg.Server != nil && cfg.Server.Grpc != nil {
		if cfg.Server.Grpc.Network != "" {
			opts = append(opts, grpc.Network(cfg.Server.Grpc.Network))
		}
		if cfg.Server.Grpc.Addr != "" {
			opts = append(opts, grpc.Address(cfg.Server.Grpc.Addr))
		}
		if cfg.Server.Grpc.Timeout != nil {
			opts = append(opts, grpc.Timeout(cfg.Server.Grpc.Timeout.AsDuration()))
		}
	}

	// Configure TLS if certificates are available.
	tlsEnabled := false
	if certManager != nil && certManager.IsTLSEnabled() {
		tlsConfig, err := certManager.GetServerTLSConfig()
		if err != nil {
			l.Warnf("Failed to get TLS config, running without TLS: %v", err)
		} else {
			opts = append(opts, grpc.TLSConfig(tlsConfig))
			l.Info("gRPC server configured with mTLS")
			tlsEnabled = true
		}
	} else {
		l.Warn("TLS not enabled, running without mTLS")
	}

	// Middleware stack.
	var ms []middleware.Middleware
	ms = append(ms, recovery.Recovery())
	ms = append(ms, collector.Middleware())
	ms = append(ms, systemViewerMiddleware())
	ms = append(ms, metadata.Server())
	ms = append(ms, logging.Server(ctx.GetLogger()))

	if tlsEnabled {
		ms = append(ms, mtls.MTLSMiddleware(
			ctx.GetLogger(),
			mtls.WithPublicEndpoints(
				"/grpc.health.v1.Health/Check",
				"/grpc.health.v1.Health/Watch",
			),
		))
	} else {
		l.Warn("mTLS middleware disabled (TLS not configured)")
	}

	ms = append(ms, audit.Server(
		ctx.GetLogger(),
		audit.WithServiceName("dns-service"),
		audit.WithSkipOperations(
			"/grpc.health.v1.Health/Check",
			"/grpc.health.v1.Health/Watch",
		),
	))

	ms = append(ms, protoValidator())

	opts = append(opts, grpc.Middleware(ms...))

	srv := grpc.NewServer(opts...)

	// Register services with redacted wrappers so sensitive data never leaks into logs.
	dnsV1.RegisterRedactedDnsZoneServiceServer(srv, zoneSvc, nil)
	dnsV1.RegisterRedactedDnsRecordServiceServer(srv, recordSvc, nil)
	dnsV1.RegisterRedactedDnsZoneTemplateServiceServer(srv, templateSvc, nil)
	dnsV1.RegisterRedactedDnsSupermasterServiceServer(srv, supermasterSvc, nil)
	dnsV1.RegisterRedactedDnsConfigServiceServer(srv, configSvc, nil)
	dnsV1.RegisterRedactedDnsDashboardServiceServer(srv, dashboardSvc, nil)

	return srv
}
