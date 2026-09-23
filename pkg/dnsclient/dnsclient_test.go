package dnsclient

// T069: the typed module client over an in-process gRPC server — requests
// carry the tenant and fields verbatim, responses map to plain Go values, and
// gRPC statuses become typed errors (never the server's message text).

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	dnsv1 "github.com/go-freya/freya/services/dns/api/proto/dns/v1"
)

const tenant = "11111111-1111-7111-8111-111111111111"

type challenges struct {
	dnsv1.UnimplementedChallengesServer
	last *dnsv1.ChallengeRequest
	err  error
}

func (c *challenges) Present(_ context.Context, r *dnsv1.ChallengeRequest) (*dnsv1.ChallengeResponse, error) {
	c.last = r
	if c.err != nil {
		return nil, c.err
	}
	return &dnsv1.ChallengeResponse{Zone: "example.test."}, nil
}

func (c *challenges) CleanUp(_ context.Context, r *dnsv1.ChallengeRequest) (*dnsv1.ChallengeResponse, error) {
	c.last = r
	if c.err != nil {
		return nil, c.err
	}
	return &dnsv1.ChallengeResponse{Zone: "example.test."}, nil
}

type zonesSrv struct {
	dnsv1.UnimplementedZonesServer
	err error
}

var zone = &dnsv1.Zone{Id: "z1", Name: "example.test.", Kind: "native", Dnssec: true, Origin: "manual", Description: "d",
	Masters: []string{"192.0.2.1"}, CreatedAt: &dnsv1.Timestamp{Unix: 100}, UpdatedAt: &dnsv1.Timestamp{Unix: 200}}

func (z *zonesSrv) List(_ context.Context, r *dnsv1.ListZonesRequest) (*dnsv1.ListZonesResponse, error) {
	if z.err != nil {
		return nil, z.err
	}
	if r.GetTenantId() != tenant || r.GetQuery() != "ex" || r.GetPage() != 2 || r.GetPageSize() != 10 {
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}
	return &dnsv1.ListZonesResponse{Items: []*dnsv1.Zone{zone}, Total: 11}, nil
}

func (z *zonesSrv) Get(_ context.Context, r *dnsv1.GetZoneRequest) (*dnsv1.Zone, error) {
	if z.err != nil {
		return nil, z.err
	}
	if r.GetId() == "z1" || r.GetName() == "example.test" {
		return zone, nil
	}
	return nil, status.Error(codes.NotFound, "zone_not_found")
}

func (z *zonesSrv) FindForName(_ context.Context, r *dnsv1.FindForNameRequest) (*dnsv1.Zone, error) {
	if z.err != nil {
		return nil, z.err
	}
	if r.GetName() == "www.example.test" {
		return zone, nil
	}
	return nil, status.Error(codes.NotFound, "zone_not_found")
}

func dial(t *testing.T, c *challenges, z *zonesSrv) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	dnsv1.RegisterChallengesServer(gs, c)
	dnsv1.RegisterZonesServer(gs, z)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return New(conn)
}

func TestChallenges(t *testing.T) {
	c := &challenges{}
	cl := dial(t, c, &zonesSrv{})
	ctx := context.Background()
	if err := cl.Present(ctx, tenant, "*.example.test", "_acme-challenge.example.test", "v"); err != nil {
		t.Fatal(err)
	}
	if c.last.GetTenantId() != tenant || c.last.GetDomain() != "*.example.test" || c.last.GetFqdn() != "_acme-challenge.example.test" || c.last.GetValue() != "v" {
		t.Fatalf("request = %+v", c.last)
	}
	if err := cl.CleanUp(ctx, tenant, "example.test", "_acme-challenge.example.test", "w"); err != nil || c.last.GetValue() != "w" {
		t.Fatalf("cleanup = %v %+v", err, c.last)
	}
	for code, want := range map[codes.Code]error{
		codes.NotFound: ErrNotFound, codes.PermissionDenied: ErrPermissionDenied, codes.Unauthenticated: ErrPermissionDenied,
		codes.InvalidArgument: ErrInvalid, codes.FailedPrecondition: ErrPrecondition, codes.Unavailable: ErrUnavailable,
		codes.DeadlineExceeded: ErrUnavailable, codes.Internal: ErrFailed, codes.Unimplemented: ErrFailed,
	} {
		c.err = status.Error(code, "secret server detail")
		err := cl.Present(ctx, tenant, "example.test", "_acme-challenge.example.test", "v")
		if !errors.Is(err, want) {
			t.Errorf("%v: present = %v, want %v", code, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "secret server detail") {
			t.Errorf("%v: server text surfaced: %v", code, err)
		}
		if err := cl.CleanUp(ctx, tenant, "example.test", "_acme-challenge.example.test", "v"); !errors.Is(err, want) {
			t.Errorf("%v: cleanup = %v, want %v", code, err, want)
		}
	}
	if !errors.Is(mapErr(errors.New("plain")), ErrFailed) || mapErr(nil) != nil {
		t.Fatal("mapErr")
	}
}

func TestZones(t *testing.T) {
	z := &zonesSrv{}
	cl := dial(t, &challenges{}, z)
	ctx := context.Background()
	items, total, err := cl.ListZones(ctx, tenant, "ex", 2, 10)
	if err != nil || total != 11 || len(items) != 1 {
		t.Fatalf("list = %v %d %v", items, total, err)
	}
	got := items[0]
	if got.ID != "z1" || got.Name != "example.test." || got.Kind != "native" || !got.DNSSEC || got.Origin != "manual" || got.Description != "d" ||
		len(got.Masters) != 1 || got.CreatedAt.Unix() != 100 || got.UpdatedAt.Unix() != 200 {
		t.Fatalf("zone = %+v", got)
	}
	if g, err := cl.GetZone(ctx, tenant, "z1"); err != nil || g.ID != "z1" {
		t.Fatalf("get = %+v %v", g, err)
	}
	if g, err := cl.GetZoneByName(ctx, tenant, "example.test"); err != nil || g.Name != "example.test." {
		t.Fatalf("get by name = %+v %v", g, err)
	}
	if _, err := cl.GetZone(ctx, tenant, "zz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if g, err := cl.FindForName(ctx, tenant, "www.example.test"); err != nil || g.ID != "z1" {
		t.Fatalf("find = %+v %v", g, err)
	}
	if _, err := cl.FindForName(ctx, tenant, "nowhere"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("find missing = %v", err)
	}
	z.err = status.Error(codes.Unavailable, "down")
	if _, _, err := cl.ListZones(ctx, tenant, "", 0, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("list down = %v", err)
	}
	if _, err := cl.GetZoneByName(ctx, tenant, "example.test"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("get down = %v", err)
	}
	if _, err := cl.FindForName(ctx, tenant, "www.example.test"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("find down = %v", err)
	}
	// A zone without timestamps maps to zero times.
	if zz := toZone(&dnsv1.Zone{Id: "x"}); !zz.CreatedAt.IsZero() || !zz.UpdatedAt.IsZero() {
		t.Fatalf("zero times = %+v", zz)
	}
}
