//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// Package providers defines the dependency injection ProviderSet for the service layer.
package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-dns/internal/event"
	"github.com/go-tangra/go-tangra-dns/internal/metrics"
	"github.com/go-tangra/go-tangra-dns/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/internal/service"
)

// ProviderSet is the Wire provider set for the service layer.
var ProviderSet = wire.NewSet(
	service.NewSqlBackupService,
	metrics.NewCollector,
	recursor.NewClient,
	recursor.NewReconciler,
	service.NewZoneService,
	service.NewRecordService,
	service.NewZoneTemplateService,
	service.NewSupermasterService,
	service.NewConfigService,
	service.NewDashboardService,
	event.NewHandler,
	event.NewSubscriber,
)
