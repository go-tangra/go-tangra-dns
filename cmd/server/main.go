package main

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	kratosHttp "github.com/go-kratos/kratos/v2/transport/http"

	conf "github.com/tx7do/kratos-bootstrap/api/gen/go/conf/v1"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-common/registration"
	pkgService "github.com/go-tangra/go-tangra-common/service"
	"github.com/go-tangra/go-tangra-dns/cmd/server/assets"
	"github.com/go-tangra/go-tangra-dns/internal/event"
	"github.com/go-tangra/go-tangra-dns/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/internal/service"
)

var (
	// Module info
	moduleID    = "dns"
	moduleName  = "DNS"
	version     = "1.0.0"
	description = "DNS zone, record, template and supermaster management backed by PowerDNS"
)

var globalRegHelper *registration.RegistrationHelper
var globalEventSubscriber *event.Subscriber
var globalRecursorReconciler *recursor.Reconciler
var globalConfigService *service.ConfigService

func newApp(
	ctx *bootstrap.Context,
	gs *grpc.Server,
	hs *kratosHttp.Server,
	eventSubscriber *event.Subscriber,
	recursorReconciler *recursor.Reconciler,
	configService *service.ConfigService,
) *kratos.App {
	// Re-apply persisted PowerDNS config on boot (covers config-file drift).
	globalConfigService = configService
	if configService != nil {
		if err := configService.Start(); err != nil {
			ctx.GetLogger().Log(0, "msg", "failed to start config service", "err", err)
		}
	}

	// Start the IPAM event subscriber (auto-creates zones/records on
	// ip_address.created). Best-effort: a Redis outage must not stop boot.
	globalEventSubscriber = eventSubscriber
	if eventSubscriber != nil {
		if err := eventSubscriber.Start(); err != nil {
			ctx.GetLogger().Log(0, "msg", "failed to start event subscriber", "err", err)
		}
	}

	// Start the recursor reconciler (keeps pdns-recursor forward zones in
	// sync with the managed zones). Best-effort.
	globalRecursorReconciler = recursorReconciler
	if recursorReconciler != nil {
		if err := recursorReconciler.Start(); err != nil {
			ctx.GetLogger().Log(0, "msg", "failed to start recursor reconciler", "err", err)
		}
	}

	globalRegHelper = registration.StartRegistration(ctx, ctx.GetLogger(), &registration.Config{
		ModuleID:          moduleID,
		ModuleName:        moduleName,
		Version:           version,
		Description:       description,
		GRPCEndpoint:      registration.GetGRPCAdvertiseAddr(ctx, "0.0.0.0:9800"),
		AdminEndpoint:     registration.GetEnvOrDefault("ADMIN_GRPC_ENDPOINT", ""),
		FrontendEntryUrl:  registration.GetEnvOrDefault("FRONTEND_ENTRY_URL", ""),
		HttpEndpoint:      registration.GetEnvOrDefault("HTTP_ADVERTISE_ADDR", ""),
		OpenapiSpec:       assets.OpenApiData,
		ProtoDescriptor:   assets.DescriptorData,
		MenusYaml:         assets.MenusData,
		HeartbeatInterval: 30 * time.Second,
		RetryInterval:     5 * time.Second,
		MaxRetries:        60,
	})

	return bootstrap.NewApp(ctx, gs, hs)
}

func runApp() error {
	ctx := bootstrap.NewContext(
		context.Background(),
		&conf.AppInfo{
			Project: pkgService.Project,
			AppId:   "dns.service",
			Version: version,
		},
	)

	defer func() {
		if globalConfigService != nil {
			_ = globalConfigService.Stop()
		}
		if globalRecursorReconciler != nil {
			_ = globalRecursorReconciler.Stop()
		}
		if globalEventSubscriber != nil {
			_ = globalEventSubscriber.Stop()
		}
		if globalRegHelper != nil {
			globalRegHelper.Stop()
		}
	}()

	return bootstrap.RunApp(ctx, initApp)
}

func main() {
	if err := runApp(); err != nil {
		panic(err)
	}
}
