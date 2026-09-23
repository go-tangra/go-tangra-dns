package grpcapi

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsv1 "github.com/go-freya/freya/services/dns/api/proto/dns/v1"
	"github.com/go-freya/freya/services/dns/internal/acmechallenge"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/pdns"
)

// challengeError maps challenge-service errors to a gRPC status carrying only
// a stable reason.
func challengeError(err error) error {
	switch {
	case errors.Is(err, acmechallenge.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid_challenge")
	case errors.Is(err, acmechallenge.ErrNotFound):
		return status.Error(codes.NotFound, "zone_not_found")
	case errors.Is(err, acmechallenge.ErrPrecondition):
		return status.Error(codes.FailedPrecondition, "precondition_failed")
	case errors.Is(err, pdns.ErrUnavailable):
		return status.Error(codes.Unavailable, "pdns_unavailable")
	}
	return GRPCError(err)
}

// admit checks the verified peer against the configured lcm identity BEFORE
// anything else (a refused peer learns nothing about tenants or zones), then
// resolves the module subject for the request's tenant.
func (s *ChallengesServer) admit(ctx context.Context, tenantID string) (authz.Subjects, error) {
	peer, ok := callerFunc(ctx)
	if !ok || peer == "" || s.d.AllowedChallengeCaller == "" || peer != s.d.AllowedChallengeCaller {
		s.d.Challenges.Refused(ctx, peer, tenantID)
		return authz.Subjects{}, status.Error(codes.PermissionDenied, "forbidden")
	}
	return Caller(ctx, tenantID)
}

func request(req *dnsv1.ChallengeRequest) acmechallenge.Request {
	return acmechallenge.Request{Domain: req.GetDomain(), FQDN: req.GetFqdn(), Value: req.GetValue()}
}

// Present adds the challenge value to the TXT rrset at fqdn (idempotent).
func (s *ChallengesServer) Present(ctx context.Context, req *dnsv1.ChallengeRequest) (*dnsv1.ChallengeResponse, error) {
	if s.d.Challenges == nil {
		return nil, status.Error(codes.Unimplemented, "challenges not wired")
	}
	subj, err := s.admit(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	zone, err := s.d.Challenges.Present(ctx, subj, request(req))
	if err != nil {
		return nil, challengeError(err)
	}
	return &dnsv1.ChallengeResponse{Zone: zone}, nil
}

// CleanUp removes the challenge value from the TXT rrset at fqdn (absent = OK).
func (s *ChallengesServer) CleanUp(ctx context.Context, req *dnsv1.ChallengeRequest) (*dnsv1.ChallengeResponse, error) {
	if s.d.Challenges == nil {
		return nil, status.Error(codes.Unimplemented, "challenges not wired")
	}
	subj, err := s.admit(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	zone, err := s.d.Challenges.CleanUp(ctx, subj, request(req))
	if err != nil {
		return nil, challengeError(err)
	}
	return &dnsv1.ChallengeResponse{Zone: zone}, nil
}
