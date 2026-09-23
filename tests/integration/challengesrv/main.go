//go:build integration

// Command challengesrv is an integration-test helper (T103): the REAL dns
// module code path behind dns.v1.Challenges — zones + records + acmechallenge
// over the PowerDNS Authoritative and Recursor HTTP clients, a memstore — served
// on a plain gRPC listener. It lets services/lcm's integration suite (which may
// not import services/dns: dns depends on lcm, not the reverse) drive the
// "freya-dns" ACME provider against live PowerDNS containers and a real Pebble.
//
// The SPIFFE mTLS transport is replaced by a unary interceptor that places the
// configured peer identity (-peer) in the context exactly where the Freya authn
// middleware would; the handler's own check against acme.allowed_caller still
// runs. It creates -zone for -tenant (syncing the recursor forward to
// -forward-host) and prints "READY <addr>" once serving.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/go-freya/freya/authn"
	"github.com/go-freya/freya/identity"
	"github.com/go-freya/freya/services/dns/internal/acmechallenge"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/grpcapi"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/recursor"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

func main() {
	pdnsURL := flag.String("pdns-url", "", "PowerDNS Authoritative API base URL")
	pdnsKey := flag.String("pdns-key", "", "PowerDNS Authoritative API key")
	recURL := flag.String("recursor-url", "", "PowerDNS Recursor API base URL")
	recKey := flag.String("recursor-key", "", "PowerDNS Recursor API key")
	fwd := flag.String("forward-host", "", "authoritative server address the recursor forwards managed zones to")
	tenant := flag.String("tenant", "", "tenant id owning -zone")
	zone := flag.String("zone", "", "zone to create for -tenant")
	listen := flag.String("listen", "127.0.0.1:0", "gRPC listen address")
	peer := flag.String("peer", "spiffe://example.org/svc/lcm", "verified peer identity the interceptor asserts")
	allowed := flag.String("allowed-caller", "spiffe://example.org/svc/lcm", "acme.allowed_caller")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	pd, err := pdns.New(pdns.Config{BaseURL: *pdnsURL, Key: func(context.Context) (string, error) { return *pdnsKey, nil }})
	if err != nil {
		log.Fatal(err)
	}
	rc, err := recursor.New(recursor.Config{BaseURL: *recURL, Key: func(context.Context) (string, error) { return *recKey, nil }, ForwardHost: *fwd})
	if err != nil {
		log.Fatal(err)
	}
	st := memstore.New()
	zs := zones.New(zones.Deps{Store: st, PDNS: pd, Recursor: rc, Log: logger})
	rs := records.New(records.Deps{Zones: zs, PDNS: pd, Log: logger})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if _, err := zs.Create(ctx, authz.Internal(*tenant), zones.CreateInput{Name: *zone, Kind: "native", Nameservers: []string{"ns1." + *zone}}); err != nil {
		log.Fatalf("create zone: %v", err)
	}
	cancel()
	cs := acmechallenge.New(acmechallenge.Deps{Zones: zs, Records: rs, Store: st, AllowedCaller: *allowed, Log: logger})

	id, err := identity.ParseSPIFFEID(*peer)
	if err != nil {
		log.Fatal(err)
	}
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		return h(authn.WithPeer(ctx, authn.PeerIdentity{ID: id, VerifiedAt: time.Now()}), req)
	}))
	grpcapi.Register(gs, grpcapi.Deps{AllowedChallengeCaller: *allowed, Zones: zs, Challenges: cs})
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("READY %s\n", lis.Addr())
	if err := gs.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
