//go:build wireinject
// +build wireinject

//go:generate go run github.com/google/wire/cmd/wire

// Package providers defines the dependency injection ProviderSet for the data layer.
package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-dns/internal/data"
)

// ProviderSet is the Wire provider set for the data layer.
var ProviderSet = wire.NewSet(
	data.NewRedisClient,
	data.NewEntClient,
	data.NewPdnsClient,
	data.NewZoneRepo,
	data.NewZoneTemplateRepo,
	data.NewSupermasterRepo,
	data.NewDnsConfigRepo,
	data.NewPrometheusClient,
)
