package app

import (
	"context"
	"time"

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

// SeedPermissions registers the module's permissions + built-in role grants with
// the auth service (idempotent).
func (a *App) SeedPermissions(ctx context.Context) error {
	conn, err := a.Freya.Client(ctx, "auth")
	if err != nil {
		return err
	}
	return dnsmanifest.SeedPermissions(ctx, conn)
}

// seedLoop seeds at start (retrying until it succeeds) and then every five
// minutes so tenants created later receive the grants.
func (a *App) seedLoop(ctx context.Context) {
	for ctx.Err() == nil {
		err := a.SeedPermissions(ctx)
		if err == nil {
			break
		}
		a.Log.Warn("permission seeding failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.SeedPermissions(ctx); err != nil {
				a.Log.Warn("permission seeding", "err", err)
			}
		}
	}
}
