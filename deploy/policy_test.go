package deploy

// T068: the development service-to-service policy of the DNS module. The
// ACME challenge methods are reachable from the lcm identity ONLY (the handler
// re-checks it too); any platform module may read zones; the gateway forwards
// browser traffic. Evaluated with the framework's own policy engine.

import (
	"context"
	"os"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/identity"
)

func load(t *testing.T) *authz.Policy {
	t.Helper()
	f, err := os.Open("policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p, err := authz.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func allowed(t *testing.T, p *authz.Policy, peer, op string) bool {
	t.Helper()
	id, err := identity.ParseSPIFFEID(peer)
	if err != nil {
		t.Fatal(err)
	}
	return p.Authorize(context.Background(), id, "dns", op).Allowed
}

func TestOnlyLCMMayCallChallenges(t *testing.T) {
	p := load(t)
	const lcm = "spiffe://example.org/svc/lcm"
	for _, op := range []string{"/dns.v1.Challenges/Present", "/dns.v1.Challenges/CleanUp"} {
		if !allowed(t, p, lcm, op) {
			t.Errorf("lcm refused %s", op)
		}
		for _, peer := range []string{"spiffe://example.org/svc/deployer", "spiffe://example.org/svc/ipam", "spiffe://example.org/svc/gateway", "spiffe://example.org/svc/dns"} {
			if allowed(t, p, peer, op) {
				t.Errorf("%s may call %s", peer, op)
			}
		}
	}
	if allowed(t, p, lcm, "/dns.v1.Challenges/Other") {
		t.Error("lcm may call an undeclared challenge method")
	}
}

func TestModulesReadZones(t *testing.T) {
	p := load(t)
	for _, op := range []string{"/dns.v1.Zones/List", "/dns.v1.Zones/Get", "/dns.v1.Zones/FindForName", "/grpc.health.v1.Health/Check"} {
		for _, peer := range []string{"spiffe://example.org/svc/lcm", "spiffe://example.org/svc/deployer"} {
			if !allowed(t, p, peer, op) {
				t.Errorf("%s refused %s", peer, op)
			}
		}
	}
	if allowed(t, p, "spiffe://other.org/svc/lcm", "/dns.v1.Zones/List") {
		t.Error("a foreign trust domain is admitted")
	}
}

func TestGatewayForwardsHTTPOnly(t *testing.T) {
	p := load(t)
	const gw = "spiffe://example.org/svc/gateway"
	for _, op := range []string{"GET /api/dns/v1/zones", "PUT /api/dns/v1/config", "DELETE /api/dns/v1/zones/x", "GET /ui/remoteEntry.js"} {
		if !allowed(t, p, gw, op) {
			t.Errorf("gateway refused %s", op)
		}
	}
	if allowed(t, p, "spiffe://example.org/svc/deployer", "GET /api/dns/v1/zones") {
		t.Error("a module may call the browser API")
	}
}
