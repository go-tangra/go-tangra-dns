package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsv1 "github.com/go-freya/freya/services/dns/api/proto/dns/v1"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

const tn = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func withCaller(t *testing.T, id string, ok bool) {
	t.Helper()
	prev := callerFunc
	callerFunc = func(context.Context) (string, bool) { return id, ok }
	t.Cleanup(func() { callerFunc = prev })
}

func TestCaller(t *testing.T) {
	if _, err := Caller(context.Background(), tn); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer: %v", err)
	}
	withCaller(t, "spiffe://example.org/svc/lcm", true)
	s, err := Caller(context.Background(), tn)
	if err != nil || s.ActorKind != authz.ActorModule || s.TenantID != tn || s.PeerSPIFFE != "spiffe://example.org/svc/lcm" {
		t.Fatalf("caller = %+v %v", s, err)
	}
	if authz.CallerIs(s, "spiffe://example.org/svc/lcm") != nil || authz.CallerIs(s, "spiffe://example.org/svc/deployer") == nil {
		t.Fatal("caller identity check")
	}
	if _, err := Caller(context.Background(), "not-a-uuid"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad tenant: %v", err)
	}
	withCaller(t, "", true)
	if _, err := Caller(context.Background(), tn); status.Code(err) != codes.Unauthenticated {
		t.Fatal("empty identity")
	}
}

func TestGRPCError(t *testing.T) {
	cases := map[error]codes.Code{
		repo.ErrNotFound:                         codes.NotFound,
		pdns.ErrNotFound:                         codes.NotFound,
		authz.ErrForbidden:                       codes.PermissionDenied,
		repo.ErrConflict:                         codes.FailedPrecondition,
		pdns.ErrConflict:                         codes.FailedPrecondition,
		fmt.Errorf("%w: x", validate.ErrName):    codes.InvalidArgument,
		fmt.Errorf("%w: x", validate.ErrMasters): codes.InvalidArgument,
		fmt.Errorf("%w: x", pdns.ErrUnavailable): codes.Unavailable,
		errors.New("x"):                          codes.Unavailable,
		status.Error(codes.Aborted, "keep"):      codes.Aborted,
	}
	for err, want := range cases {
		if got := status.Code(GRPCError(err)); got != want {
			t.Errorf("%v => %s, want %s", err, got, want)
		}
	}
	// PowerDNS messages never travel to the caller
	if st := status.Convert(GRPCError(&pdns.APIError{Status: 503, Message: "internal detail"})); st.Message() == "internal detail" {
		t.Fatal("detail leaked")
	}
}

type registrar struct{ names []string }

func (r *registrar) RegisterService(d *grpc.ServiceDesc, _ any) {
	r.names = append(r.names, d.ServiceName)
}

func TestRegisterAndUnimplemented(t *testing.T) {
	r := &registrar{}
	Register(r, Deps{AllowedChallengeCaller: "spiffe://example.org/svc/lcm"})
	if len(r.names) != 2 || r.names[0] != "dns.v1.Zones" || r.names[1] != "dns.v1.Challenges" {
		t.Fatalf("registered = %v", r.names)
	}
	z := &ZonesServer{}
	if _, err := z.List(context.Background(), &dnsv1.ListZonesRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("list = %v", err)
	}
	c := &ChallengesServer{}
	if _, err := c.Present(context.Background(), &dnsv1.ChallengeRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("present = %v", err)
	}
}
