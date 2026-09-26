package app

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/pkg/dnsmanifest"
)

// AuthPerms answers API-permission questions through the auth service's
// Authorization/Check. A failed call is a "no" (fail closed).
type AuthPerms struct {
	Client authv1.AuthorizationClient
}

// Has implements authz.Checker.
func (p AuthPerms) Has(ctx context.Context, tenantID, userID, permission string) bool {
	resource, action, ok := authz.Split(permission)
	if !ok || p.Client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := p.Client.Check(ctx, &authv1.CheckRequest{TenantId: tenantID, UserId: userID, Resource: resource, Action: action})
	return err == nil && res.GetAllowed()
}

var _ authz.Checker = AuthPerms{}

// Registration cadence: retry until auth accepts the registration, then
// re-register every five minutes so tenants created later receive the grants.
const (
	registerRetry = 5 * time.Second
	registerEvery = 5 * time.Minute
)

// RegisterPermissions registers the module's permissions, module roles and
// built-in role grants with the auth service (idempotent).
func (a *App) RegisterPermissions(ctx context.Context) error {
	conn, err := a.Freya.Client(ctx, "auth")
	if err != nil {
		return err
	}
	return registerPermissions(ctx, conn, a.Log)
}

func registerPermissions(ctx context.Context, cc grpc.ClientConnInterface, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := dnsmanifest.Registration().Register(ctx, cc, log)
	return err
}

func (a *App) seedLoop(ctx context.Context) {
	registrationLoop(ctx, a.Log, a.RegisterPermissions, registerRetry, registerEvery)
}

// registrationLoop calls register until it succeeds (every retry), then every
// period until ctx ends.
func registrationLoop(ctx context.Context, log *slog.Logger, register func(context.Context) error, retry, period time.Duration) {
	for ctx.Err() == nil {
		err := register(ctx)
		if err == nil {
			break
		}
		log.Warn("auth registration failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := register(ctx); err != nil {
				log.Warn("auth registration", "err", err)
			}
		}
	}
}
