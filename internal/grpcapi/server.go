// Package grpcapi serves dns.v1 for other platform services on the Freya SPIFFE
// mTLS channel (contracts §B): the caller is an authenticated service (the
// framework's policy allow-list admits it before any handler runs) acting for
// the tenant named in the request. Zones is a read-only view for any module;
// Challenges is additionally re-checked in the handler against the exact lcm
// identity (authz.CallerIs). Nothing here is proxied by the gateway; responses
// never carry API keys or record values beyond the challenge token.
package grpcapi

import (
	"context"
	"errors"
	"regexp"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/authn"
	dnsv1 "github.com/go-freya/freya/services/dns/api/proto/dns/v1"
	"github.com/go-freya/freya/services/dns/internal/acmechallenge"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// callerFunc resolves the verified SPIFFE identity of a call (overridable in tests).
var callerFunc = func(ctx context.Context) (string, bool) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return "", false
	}
	return p.ID.String(), true
}

// Caller returns the module subject for the tenant named in the request; the
// tenant must be a uuid and the peer must present a SPIFFE identity (the
// transport-verified peer, never a request field).
func Caller(ctx context.Context, tenantID string) (authz.Subjects, error) {
	id, ok := callerFunc(ctx)
	if !ok || id == "" {
		return authz.Subjects{}, status.Error(codes.Unauthenticated, "service identity required")
	}
	if !uuidRE.MatchString(tenantID) {
		return authz.Subjects{}, status.Error(codes.InvalidArgument, "tenant_id must be a uuid")
	}
	return authz.Module(tenantID, id), nil
}

// GRPCError maps a service/domain error to a gRPC status carrying only a
// stable reason (never PowerDNS messages or detail).
func GRPCError(err error) error {
	if _, ok := status.FromError(err); ok && err != nil {
		return err
	}
	switch {
	case errors.Is(err, authz.ErrForbidden):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, repo.ErrNotFound), errors.Is(err, pdns.ErrNotFound):
		return status.Error(codes.NotFound, "not_found")
	case errors.Is(err, validate.ErrName), errors.Is(err, validate.ErrMasters):
		return status.Error(codes.InvalidArgument, "invalid_name")
	case errors.Is(err, repo.ErrConflict), errors.Is(err, pdns.ErrConflict):
		return status.Error(codes.FailedPrecondition, "conflict")
	case errors.Is(err, pdns.ErrUnavailable):
		return status.Error(codes.Unavailable, "pdns_unavailable")
	}
	return status.Error(codes.Unavailable, "temporarily_unavailable")
}

// Deps carries the services the dns.v1 servers use; the user stories add
// them (US1 zones read view, US4 ACME challenges). AllowedChallengeCaller is
// the exact SPIFFE ID permitted to call Challenges (config acme.allowed_caller).
type Deps struct {
	AllowedChallengeCaller string
	Zones                  *zones.Service         // US1: read-only module view of a tenant's zones
	Challenges             *acmechallenge.Service // US4: lcm-only ACME DNS-01 challenges
}

// ZonesServer implements dns.v1.Zones (zones.go); without a wired zones
// service every method answers Unimplemented.
type ZonesServer struct {
	dnsv1.UnimplementedZonesServer
	d Deps
}

// ChallengesServer implements dns.v1.Challenges (lcm only, challenges.go);
// without a wired challenge service every method answers Unimplemented.
type ChallengesServer struct {
	dnsv1.UnimplementedChallengesServer
	d Deps
}

// Register registers the dns.v1 mesh servers on the gRPC server.
func Register(gs grpc.ServiceRegistrar, d Deps) {
	dnsv1.RegisterZonesServer(gs, &ZonesServer{d: d})
	dnsv1.RegisterChallengesServer(gs, &ChallengesServer{d: d})
}
