package data

import (
	"os"

	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-common/grpcx"
	"github.com/go-tangra/go-tangra-common/registration"
)

func NewRegistrationClient(ctx *bootstrap.Context) (*registration.Client, error) {
	adminEndpoint := os.Getenv("ADMIN_GRPC_ENDPOINT")
	if adminEndpoint == "" {
		return nil, nil
	}

	cfg := &registration.Config{
		AdminEndpoint: adminEndpoint,
		MaxRetries:    60,
	}

	return registration.NewClient(ctx.GetLogger(), cfg)
}

func NewModuleDialer(ctx *bootstrap.Context, regClient *registration.Client) *grpcx.ModuleDialer {
	if regClient == nil {
		return nil
	}
	return grpcx.NewModuleDialer(ctx.GetLogger(), "dns", regClient.AdminConn(), "")
}
