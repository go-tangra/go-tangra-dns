package grpcapi

// Wire compatibility: lcm's own dns.v1.Challenges client (lcm/pkg/dnschallenge,
// dynamic messages so lcm needs no Go module dependency on dns) against the
// real dns.v1 server registered on a gRPC server.

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/dnschallenge"
)

func TestLCMClientWireCompatibility(t *testing.T) {
	s, _, _, _, _ := challengesServer(t)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	Register(gs, s.d)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := dnschallenge.New(conn)
	ctx := context.Background()

	withCaller(t, lcmID, true)
	zone, err := c.Present(ctx, tn, "*.example.test", "_acme-challenge.example.test", goodValue)
	if err != nil || zone != "example.test." {
		t.Fatalf("present = %q %v", zone, err)
	}
	if zone, err = c.CleanUp(ctx, tn, "*.example.test", "_acme-challenge.example.test", goodValue); err != nil || zone != "example.test." {
		t.Fatalf("cleanup = %q %v", zone, err)
	}
	if _, err := c.Present(ctx, tn, "nowhere.invalid", "_acme-challenge.nowhere.invalid", goodValue); !errors.Is(err, dnschallenge.ErrNotFound) {
		t.Fatalf("no zone = %v", err)
	}
	withCaller(t, "spiffe://example.org/svc/deployer", true)
	if _, err := c.Present(ctx, tn, "example.test", "_acme-challenge.example.test", goodValue); !errors.Is(err, dnschallenge.ErrPermissionDenied) {
		t.Fatalf("other peer = %v", err)
	}
}
