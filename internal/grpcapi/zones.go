package grpcapi

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsv1 "github.com/go-tangra/go-tangra-dns/v4/api/proto/dns/v1"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

// zoneError maps zone-service errors (zone_not_found → NotFound) before the
// generic mapping.
func zoneError(err error) error {
	if errors.Is(err, zones.ErrNotFound) {
		return status.Error(codes.NotFound, "zone_not_found")
	}
	return GRPCError(err)
}

func toProto(z store.Zone) *dnsv1.Zone {
	out := &dnsv1.Zone{Id: z.ID, Name: z.Name, Kind: z.Kind, Dnssec: z.DNSSEC, Origin: z.Origin, Description: z.Description,
		Masters: append([]string{}, z.Masters...)}
	if !z.CreatedAt.IsZero() {
		out.CreatedAt = &dnsv1.Timestamp{Unix: z.CreatedAt.Unix()}
	}
	if !z.UpdatedAt.IsZero() {
		out.UpdatedAt = &dnsv1.Timestamp{Unix: z.UpdatedAt.Unix()}
	}
	return out
}

// List pages the zones of the tenant named in the request (read-only module
// view; the peer is the transport-verified SPIFFE identity, admitted by the
// policy allow-list).
func (s *ZonesServer) List(ctx context.Context, req *dnsv1.ListZonesRequest) (*dnsv1.ListZonesResponse, error) {
	if s.d.Zones == nil {
		return nil, status.Error(codes.Unimplemented, "zones not wired")
	}
	subj, err := Caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	items, total, err := s.d.Zones.List(ctx, subj, store.ZoneFilter{Query: req.GetQuery(), Page: int(req.GetPage()), PageSize: int(req.GetPageSize())})
	if err != nil {
		return nil, zoneError(err)
	}
	out := &dnsv1.ListZonesResponse{Total: total}
	for _, z := range items {
		out.Items = append(out.Items, toProto(z))
	}
	return out, nil
}

// Get returns one zone of the tenant by id or by name.
func (s *ZonesServer) Get(ctx context.Context, req *dnsv1.GetZoneRequest) (*dnsv1.Zone, error) {
	if s.d.Zones == nil {
		return nil, status.Error(codes.Unimplemented, "zones not wired")
	}
	subj, err := Caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	var z store.Zone
	switch {
	case req.GetId() != "":
		z, err = s.d.Zones.Owned(ctx, subj, req.GetId())
	case strings.TrimSpace(req.GetName()) != "":
		z, err = s.d.Zones.ByName(ctx, subj, req.GetName())
	default:
		return nil, status.Error(codes.InvalidArgument, "id or name required")
	}
	if err != nil {
		return nil, zoneError(err)
	}
	return toProto(z), nil
}

// FindForName returns the tenant's longest managed zone containing the name.
func (s *ZonesServer) FindForName(ctx context.Context, req *dnsv1.FindForNameRequest) (*dnsv1.Zone, error) {
	if s.d.Zones == nil {
		return nil, status.Error(codes.Unimplemented, "zones not wired")
	}
	subj, err := Caller(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	z, err := s.d.Zones.FindForName(ctx, subj, req.GetName())
	if err != nil {
		return nil, zoneError(err)
	}
	return toProto(z), nil
}
