//go:build wireinject
// +build wireinject

package main

import (
	"github.com/go-kratos/kratos/v2"
	"github.com/google/wire"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	dataProviders "github.com/go-tangra/go-tangra-dns/internal/data/providers"
	serverProviders "github.com/go-tangra/go-tangra-dns/internal/server/providers"
	serviceProviders "github.com/go-tangra/go-tangra-dns/internal/service/providers"
)

func initApp(*bootstrap.Context) (*kratos.App, func(), error) {
	panic(wire.Build(
		dataProviders.ProviderSet,
		serverProviders.ProviderSet,
		serviceProviders.ProviderSet,
		newApp,
	))
}
