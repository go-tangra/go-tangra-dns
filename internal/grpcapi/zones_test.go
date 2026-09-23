package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsv1 "github.com/go-freya/freya/services/dns/api/proto/dns/v1"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

const other = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"

func zonesServer(t *testing.T) (*ZonesServer, *memstore.Mem, string) {
	t.Helper()
	st := memstore.New()
	zs := zones.New(zones.Deps{Store: st, PDNS: pdns.NewFake()})
	z, err := zs.Create(context.Background(), authz.Internal(tn), zones.CreateInput{Name: "example.test", Kind: "master", Description: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zs.Create(context.Background(), authz.Internal(tn), zones.CreateInput{Name: "lab.example.test", Kind: "slave", Masters: []string{"192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := zs.Create(context.Background(), authz.Internal(other), zones.CreateInput{Name: "other.test", Kind: "native"}); err != nil {
		t.Fatal(err)
	}
	return &ZonesServer{d: Deps{Zones: zs}}, st, z.ID
}

func TestZonesList(t *testing.T) {
	s, _, _ := zonesServer(t)
	ctx := context.Background()
	withCaller(t, "spiffe://example.org/svc/ipam", true)
	res, err := s.List(ctx, &dnsv1.ListZonesRequest{TenantId: tn})
	if err != nil || res.Total != 2 || len(res.Items) != 2 || res.Items[0].Name != "example.test." || res.Items[0].CreatedAt.GetUnix() == 0 ||
		res.Items[1].Kind != "slave" || len(res.Items[1].Masters) != 1 {
		t.Fatalf("list = %+v %v", res, err)
	}
	res, err = s.List(ctx, &dnsv1.ListZonesRequest{TenantId: tn, Query: "lab", PageSize: 1})
	if err != nil || res.Total != 1 || res.Items[0].Name != "lab.example.test." {
		t.Fatalf("query = %+v %v", res, err)
	}
	if _, err := s.List(ctx, &dnsv1.ListZonesRequest{TenantId: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad tenant = %v", err)
	}
	withCaller(t, "", false)
	if _, err := s.List(ctx, &dnsv1.ListZonesRequest{TenantId: tn}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer = %v", err)
	}
}

func TestZonesGetAndFind(t *testing.T) {
	s, st, id := zonesServer(t)
	ctx := context.Background()
	withCaller(t, "spiffe://example.org/svc/lcm", true)
	z, err := s.Get(ctx, &dnsv1.GetZoneRequest{TenantId: tn, Id: id})
	if err != nil || z.Name != "example.test." || z.Kind != "master" || z.Description != "d" {
		t.Fatalf("get = %+v %v", z, err)
	}
	if z, err := s.Get(ctx, &dnsv1.GetZoneRequest{TenantId: tn, Name: "Example.Test"}); err != nil || z.Id != id {
		t.Fatalf("by name = %+v %v", z, err)
	}
	if _, err := s.Get(ctx, &dnsv1.GetZoneRequest{TenantId: other, Id: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-tenant = %v", err)
	}
	if _, err := s.Get(ctx, &dnsv1.GetZoneRequest{TenantId: tn}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no key = %v", err)
	}
	if _, err := s.Get(ctx, &dnsv1.GetZoneRequest{TenantId: "bad", Id: id}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad tenant = %v", err)
	}
	f, err := s.FindForName(ctx, &dnsv1.FindForNameRequest{TenantId: tn, Name: "_acme-challenge.host.lab.example.test"})
	if err != nil || f.Name != "lab.example.test." {
		t.Fatalf("find = %+v %v", f, err)
	}
	if _, err := s.FindForName(ctx, &dnsv1.FindForNameRequest{TenantId: tn, Name: "host.other.test"}); status.Code(err) != codes.NotFound {
		t.Fatalf("find other tenant = %v", err)
	}
	if _, err := s.FindForName(ctx, &dnsv1.FindForNameRequest{TenantId: tn, Name: " "}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("find empty = %v", err)
	}
	if _, err := s.FindForName(ctx, &dnsv1.FindForNameRequest{TenantId: "bad", Name: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("find bad tenant = %v", err)
	}
	st.FailNext("ZonesForTenant")
	if _, err := s.FindForName(ctx, &dnsv1.FindForNameRequest{TenantId: tn, Name: "x.example.test"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("store failure = %v", err)
	}
	st.FailNext("ListZones")
	if _, err := s.List(ctx, &dnsv1.ListZonesRequest{TenantId: tn}); status.Code(err) != codes.Unavailable {
		t.Fatalf("list store failure = %v", err)
	}
	// a peer without a SPIFFE ID is refused by the actor allow-list
	withCaller(t, "", true)
	if _, err := s.Get(ctx, &dnsv1.GetZoneRequest{TenantId: tn, Id: id}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous = %v", err)
	}
	// unwired
	u := &ZonesServer{}
	if _, err := u.Get(ctx, &dnsv1.GetZoneRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal("get unwired")
	}
	if _, err := u.FindForName(ctx, &dnsv1.FindForNameRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal("find unwired")
	}
	if p := toProto(store.Zone{}); p.CreatedAt != nil || p.Masters == nil {
		t.Fatalf("zero timestamps = %+v", p)
	}
}
