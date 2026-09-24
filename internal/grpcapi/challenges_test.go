package grpcapi

// T068: dns.v1.Challenges — only the configured lcm SPIFFE ID is served (any
// other peer, or none, is PermissionDenied and audited challenge.refused);
// service errors map to NotFound / FailedPrecondition / InvalidArgument /
// Unavailable without detail.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsv1 "github.com/go-tangra/go-tangra-dns/v4/api/proto/dns/v1"
	"github.com/go-tangra/go-tangra-dns/v4/internal/acmechallenge"
	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/records"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

const lcmID = "spiffe://example.org/svc/lcm"

type auditRec struct {
	mu sync.Mutex
	ev []audit.Event
}

func (a *auditRec) Record(_ context.Context, e audit.Event) error {
	if err := audit.Validate(e); err != nil {
		return err
	}
	a.mu.Lock()
	a.ev = append(a.ev, e)
	a.mu.Unlock()
	return nil
}

func (a *auditRec) count(t audit.EventType) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.ev {
		if e.EventType == t {
			n++
		}
	}
	return n
}

func challengesServer(t *testing.T) (*ChallengesServer, *pdns.Fake, *auditRec, *records.Service, *zones.Service) {
	t.Helper()
	st, pd, aud := memstore.New(), pdns.NewFake(), &auditRec{}
	zs := zones.New(zones.Deps{Store: st, PDNS: pd})
	rs := records.New(records.Deps{Zones: zs, PDNS: pd})
	ctx := context.Background()
	if _, err := zs.Create(ctx, authz.Internal(tn), zones.CreateInput{Name: "example.test", Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	cs := acmechallenge.New(acmechallenge.Deps{Zones: zs, Records: rs, Store: st, Audit: aud, AllowedCaller: lcmID})
	return &ChallengesServer{d: Deps{AllowedChallengeCaller: lcmID, Challenges: cs}}, pd, aud, rs, zs
}

var goodValue = strings.Repeat("a", 43)

func creq(domain, fqdn, value string) *dnsv1.ChallengeRequest {
	return &dnsv1.ChallengeRequest{TenantId: tn, Domain: domain, Fqdn: fqdn, Value: value}
}

func TestChallengesLCMOnly(t *testing.T) {
	s, pd, aud, _, _ := challengesServer(t)
	ctx := context.Background()
	for _, peer := range []struct {
		id string
		ok bool
	}{{"spiffe://example.org/svc/deployer", true}, {"spiffe://example.org/svc/gateway", true}, {"", false}, {"spiffe://example.org/svc/lcm-evil", true}} {
		withCaller(t, peer.id, peer.ok)
		if _, err := s.Present(ctx, creq("example.test", "_acme-challenge.example.test", goodValue)); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%q present = %v", peer.id, err)
		}
		if _, err := s.CleanUp(ctx, creq("example.test", "_acme-challenge.example.test", goodValue)); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%q cleanup = %v", peer.id, err)
		}
	}
	if aud.count(audit.ChallengeRefused) != 8 {
		t.Fatalf("refusals audited = %d", aud.count(audit.ChallengeRefused))
	}
	for _, c := range pd.CallLog() {
		if strings.HasPrefix(c, "PatchRRsets") {
			t.Fatal("a refused caller reached PowerDNS")
		}
	}
	withCaller(t, lcmID, true)
	resp, err := s.Present(ctx, creq("*.example.test", "_acme-challenge.example.test", goodValue))
	if err != nil || resp.GetZone() != "example.test." {
		t.Fatalf("lcm present = %v %v", resp, err)
	}
	if resp, err = s.CleanUp(ctx, creq("*.example.test", "_acme-challenge.example.test.", goodValue)); err != nil || resp.GetZone() != "example.test." {
		t.Fatalf("lcm cleanup = %v %v", resp, err)
	}
}

func TestChallengesErrorMapping(t *testing.T) {
	s, pd, _, rs, zs := challengesServer(t)
	ctx := context.Background()
	withCaller(t, lcmID, true)
	z, err := zs.ByName(ctx, authz.Internal(tn), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	cname := validate.RecordSetInput{Name: "_acme-challenge.www", Type: "CNAME", TTL: 300, Values: []validate.RecordValue{{Content: "x.example."}}}
	if _, err := rs.Apply(ctx, authz.Internal(tn), z, cname, "api"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		r    *dnsv1.ChallengeRequest
		want codes.Code
	}{
		{"bad tenant", &dnsv1.ChallengeRequest{TenantId: "x", Domain: "example.test", Fqdn: "_acme-challenge.example.test", Value: goodValue}, codes.InvalidArgument},
		{"bad value", creq("example.test", "_acme-challenge.example.test", "short"), codes.InvalidArgument},
		{"fqdn mismatch", creq("example.test", "_acme-challenge.www.example.test", goodValue), codes.InvalidArgument},
		{"no zone", creq("nowhere.invalid", "_acme-challenge.nowhere.invalid", goodValue), codes.NotFound},
		{"cname", creq("www.example.test", "_acme-challenge.www.example.test", goodValue), codes.FailedPrecondition},
	}
	for _, c := range cases {
		_, err := s.Present(ctx, c.r)
		if status.Code(err) != c.want {
			t.Errorf("%s: present = %v, want %v", c.name, err, c.want)
		}
		if st, _ := status.FromError(err); strings.Contains(st.Message(), "nowhere") || strings.Contains(st.Message(), goodValue) {
			t.Errorf("%s: message leaks detail: %q", c.name, st.Message())
		}
	}
	pd.SetDown(true)
	if _, err := s.Present(ctx, creq("example.test", "_acme-challenge.example.test", goodValue)); status.Code(err) != codes.Unavailable {
		t.Fatalf("down = %v", err)
	}
	if _, err := s.CleanUp(ctx, creq("example.test", "_acme-challenge.example.test", goodValue)); status.Code(err) != codes.Unavailable {
		t.Fatalf("down cleanup = %v", err)
	}
}

func TestChallengeErrorFallback(t *testing.T) {
	if status.Code(challengeError(authz.ErrForbidden)) != codes.PermissionDenied {
		t.Fatal("forbidden")
	}
	if status.Code(challengeError(context.Canceled)) != codes.Unavailable {
		t.Fatal("fallback")
	}
}
